/*
    Get target process by name/pid and retrieve informations like:
        - tokens
        - modules
        - handles
        - protection
        - command line
        - threads
        - arch
*/  

#include <general.h>

auto get_modules(
    _In_ HANDLE process_handle
) -> void {
    HMODULE modules[1024];
    ULONG   bytes_needed = 0;

    if ( ! EnumProcessModulesEx( process_handle, modules, sizeof(modules), &bytes_needed, LIST_MODULES_ALL ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"EnumProcessModulesEx failed with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    INT32 module_count = bytes_needed / sizeof(HMODULE);

    for ( INT32 i = 0; i < module_count; i++) {
        WCHAR      module_name[MAX_PATH * sizeof(WCHAR)] = { 0 };
        MODULEINFO module_info = { 0 };

        if ( GetModuleFileNameExW( process_handle, modules[i], module_name, MAX_PATH * sizeof(WCHAR) ) ) {
            GetModuleInformation( process_handle, modules[i], &module_info, sizeof(module_info) );
            
            BeaconPkgBytes( (PBYTE)module_name, wcslen( module_name ) * sizeof(WCHAR) );
            BeaconPkgInt64( (INT64)module_info.EntryPoint  );
            BeaconPkgInt64( (INT64)module_info.lpBaseOfDll );
            BeaconPkgInt32( module_info.SizeOfImage );

            printf("    [%03lu] 0x%p | Size: 0x%08lX | %s\n",
                i,
                module_info.lpBaseOfDll,
                module_info.SizeOfImage,
                module_name
            );
        }
    }
}

// NtQueryInformationProcess( handle, ProcessMitigationPolicy ... ); # PROCESS_MITIGATION_POLICY_INFORMATION
auto get_policy(
    _In_ HANDLE process_handle
) -> void {
    PROCESS_MITIGATION_POLICY_INFORMATION policy = {};

    NTSTATUS status = STATUS_SUCCESS;

    status = NtQueryInformationProcess( process_handle, ProcessMitigationPolicy, &policy, sizeof( policy ), nullptr );
    if ( ! nt_success( status ) ) {
        return;
    }

    policy.Policy;

    return;
}

auto get_threads(
    _In_ DWORD process_id
) -> void {
    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( snapshot == INVALID_HANDLE_VALUE ) {
        BeaconPrintfW( CALLBACK_ERROR, L"CreateToolhelp32Snapshot failed: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    THREADENTRY32 thread_entry = { 0 };
    thread_entry.dwSize = sizeof(THREADENTRY32);

    printf("[*] Threads:\n");

    if ( Thread32First(snapshot, &thread_entry) ) {
        do {
            if ( thread_entry.th32OwnerProcessID == process_id ) {

                DbgPrint("    TID: %6lu | Priority: %2ld\n",
                    thread_entry.th32ThreadID,
                    thread_entry.tpBasePri
                );

                BeaconPkgInt32( thread_entry.th32ThreadID );
                BeaconPkgInt32( thread_entry.dwFlags );
                BeaconPkgInt32( thread_entry.dwSize );
                BeaconPkgInt32( thread_entry.tpBasePri );
                BeaconPkgInt32( thread_entry.tpBasePri );
            }
        } while ( Thread32Next( snapshot, &thread_entry ) );
    }

    CloseHandle( snapshot );
}


// NtQueryInformationProcess( handle, ProcessInstrumentationCallback, ... ); # PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
auto get_instcallbacks(
    _In_ HANDLE process_handle
) -> void {
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION instrumentation_callback = { 0 };

    NTSTATUS status = STATUS_SUCCESS;

    status = NtQueryInformationProcess( process_handle, ProcessInstrumentationCallback, &instrumentation_callback, sizeof( instrumentation_callback ), nullptr );
    if ( ! nt_success( status ) ) {
        return;
    }

    instrumentation_callback.Callback;

    return;
}

auto get_protection(
    _In_ HANDLE process_handle
) -> void {
    PS_PROTECTION protection = { 0 };
    NTSTATUS      status     = STATUS_SUCCESS;

    status = NtQueryInformationProcess( process_handle, ProcessProtectionInformation, &protection, sizeof( protection ), nullptr );
    if ( ! nt_success( status ) ) {
        return;
    }

    protection.Audit;  
    protection.Signer; 
    protection.Type;   

    return;
}

// NtQueryInformationProcess( handle, ProcessBasicInformation, ... ); # PROCESS_EXTENDED_BASIC_INFORMATION
// - arch
// - parent id / pid
auto get_basicex(
    _In_ HANDLE        process_handle,
    _In_ BASICEX_FLAGS basicex_flags
) -> void {
    PROCESS_EXTENDED_BASIC_INFORMATION basicex_info = { 0 };

    NTSTATUS status = STATUS_SUCCESS;

    status = NtQueryInformationProcess( ((HANDLE)-1), ProcessBasicInformation, &basicex_info, sizeof( basicex_info ), nullptr );
    if ( ! nt_success( status ) ) {
        return;
    }

    basicex_info.PebBaseAddress;
    // basicex_info.IsWow64Process;                            // arch
    basicex_info.UniqueProcessId;                           // pid
    basicex_info.BasicInfo.InheritedFromUniqueProcessId;    // ppid

    return;
}

auto get_handles(
    _In_ HANDLE process_handle
) -> void {
    NTSTATUS status      = STATUS_SUCCESS;
    ULONG    buffer_size = 0x10000;  
    PVOID    buffer      = nullptr;

    do {
        buffer = malloc( buffer_size );
        if ( ! buffer ) return;

        status = NtQueryInformationProcess(
            process_handle, ProcessHandleInformation, buffer, buffer_size, nullptr
        );

        if ( status == STATUS_INFO_LENGTH_MISMATCH ) {
            free( buffer );
            buffer_size *= 2;
        }
    } while ( status == STATUS_INFO_LENGTH_MISMATCH );

    if ( ! nt_success( status ) ) {
        if ( buffer ) free( buffer );
        BeaconPrintfW( CALLBACK_ERROR, L"NtQueryInformationProcess (handles) failed: (status: %X)\n", status );
        return;
    }

    auto handle_info = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;
    printf("[*] Handles (%llu):\n", handle_info->NumberOfHandles);

    // for ( INT32 i = 0; i < min( handle_info->NumberOfHandles, 50 ); i++ ) {  
    //     printf("    Handle: 0x%04X | Type: 0x%02lX | Access: 0x%08lX\n",
    //         (USHORT)(ULONG_PTR)handle_info->Handles[i].HandleValue,
    //         handle_info->Handles[i].ObjectTypeIndex,
    //         handle_info->Handles[i].GrantedAccess
    //     );
    // }

    free( buffer );
}

auto get_tokens(
    _In_ HANDLE process_handle
) -> void {
    HANDLE          token_handle    = nullptr;
    TOKEN_ELEVATION elevation       = { 0 };
    ULONG           elevation_size  = sizeof( elevation );
    ULONG           token_user_size = 0;
    ULONG           integrity_size  = 0;

    if ( ! OpenProcessToken( process_handle, TOKEN_QUERY, &token_handle ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to open process token with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    GetTokenInformation( token_handle, TokenUser, nullptr, 0, &token_user_size );
    
    auto token_user = (PTOKEN_USER)malloc( token_user_size );
    if ( token_user && GetTokenInformation( token_handle, TokenUser, token_user, token_user_size, &token_user_size ) ) {
        WCHAR username[MAX_PATH] = { 0 };
        WCHAR domain[MAX_PATH]   = { 0 };
        DWORD username_len = sizeof( username );
        DWORD domain_len   = sizeof( domain );

        SID_NAME_USE sid_type;

        if ( LookupAccountSidW( nullptr, token_user->User.Sid, username, &username_len, domain, &domain_len, &sid_type ) ) {
            DbgPrint("Token User: %s\\%s\n", domain, username);

            BeaconPkgBytes( (PBYTE)username, wcslen( username ) * sizeof(WCHAR) );
            BeaconPkgBytes( (PBYTE)domain, wcslen( domain ) * sizeof(WCHAR) );
        }
    }

    if ( GetTokenInformation( token_handle, TokenElevation, &elevation, sizeof(elevation), &elevation_size ) ) {
        DbgPrint( "Elevated: %s\n", elevation.TokenIsElevated ? "Yes" : "No" );

        BeaconPkgInt32( elevation.TokenIsElevated );
    }

    GetTokenInformation( token_handle, TokenIntegrityLevel, nullptr, 0, &integrity_size );
    
    auto integrity = (PTOKEN_MANDATORY_LABEL)malloc( integrity_size );

    if ( integrity && GetTokenInformation( token_handle, TokenIntegrityLevel, integrity, integrity_size, &integrity_size ) ) {
        ULONG integrity_level = *GetSidSubAuthority(
            integrity->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(integrity->Label.Sid) - 1)
        );

        const char* level_str = "Unknown";
        if      ( integrity_level >= SECURITY_MANDATORY_SYSTEM_RID  ) level_str = "System";
        else if ( integrity_level >= SECURITY_MANDATORY_HIGH_RID    ) level_str = "High";
        else if ( integrity_level >= SECURITY_MANDATORY_MEDIUM_RID  ) level_str = "Medium";
        else if ( integrity_level >= SECURITY_MANDATORY_LOW_RID     ) level_str = "Low";
        else                                                          level_str = "Untrusted";

        BeaconPkgBytes( (PBYTE)level_str, strlen( level_str ) );

        DbgPrint("[*] Integrity Level: %s (0x%lX)\n", level_str, integrity_level);
        free( integrity );
    }

    if ( token_user ) free( token_user );
    CloseHandle( token_handle );
}

auto get_cmdline(
    _In_ HANDLE process_handle
) -> void {
    NTSTATUS status     = STATUS_SUCCESS;
    ULONG    return_len = 0;

    status = NtQueryInformationProcess(
        process_handle, ProcessCommandLineInformation, nullptr, 0, &return_len
    );
    if ( return_len == 0 ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to get command line size: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    auto cmdline = (PUNICODE_STRING)malloc( return_len );
    if ( ! cmdline ) {
        return;
    }

    status = NtQueryInformationProcess(
        process_handle, ProcessCommandLineInformation, cmdline, return_len, nullptr
    );
    if ( nt_success( status ) && cmdline->Buffer ) {
        BeaconPkgBytes( (PBYTE)cmdline->Buffer, wcslen( cmdline->Buffer ) * sizeof(WCHAR) );
        DbgPrint("[*] Command Line: %s\n", cmdline->Buffer);
    }

    free( cmdline );
}

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    HANDLE process_handle = nullptr;
    ULONG  target_process = BeaconDataInt( &data_parser );

    BOOL modules    = BeaconDataInt( &data_parser );
    BOOL protection = BeaconDataInt( &data_parser );
    BOOL tokens     = BeaconDataInt( &data_parser );
    BOOL policy     = BeaconDataInt( &data_parser );
    BOOL threads    = BeaconDataInt( &data_parser );
    BOOL callbacks  = BeaconDataInt( &data_parser );
    BOOL cmdline    = BeaconDataInt( &data_parser );
    BOOL handles    = BeaconDataInt( &data_parser );
    BOOL arch       = BeaconDataInt( &data_parser );
    BOOL parentid   = BeaconDataInt( &data_parser );
    BOOL processid  = BeaconDataInt( &data_parser );

    process_handle = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, target_process );
    if ( ! process_handle || process_handle == INVALID_HANDLE_VALUE ) {
        return;
    }

    BASICEX_FLAGS basicex = { 0 };

    basicex.Flags = (arch & 0xFF) | ((parentid & 0xFF) << 8) | ((processid & 0xFF) << 16) | ((protection & 0xFF) << 24);

    if ( processid || parentid || protection ) get_basicex( process_handle, basicex );

    if ( modules   ) get_modules( process_handle );
    if ( tokens    ) get_tokens( process_handle );
    if ( handles   ) get_handles( process_handle );
    if ( threads   ) get_threads( processid );
    if ( cmdline   ) get_cmdline( process_handle );
    if ( callbacks ) get_instcallbacks( process_handle );

    return;
}
