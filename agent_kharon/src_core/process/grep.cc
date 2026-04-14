#include <general.h>

enum section_id : INT32 {
    SECTION_END           = 0x00,
    SECTION_PID           = 0x01,
    SECTION_PPID          = 0x02,
    SECTION_ARCH          = 0x03,
    SECTION_IMAGE_NAME    = 0x04,
    SECTION_IMAGE_PATH    = 0x05,
    SECTION_CMDLINE       = 0x06,
    SECTION_PROTECTION    = 0x07,
    SECTION_MITIGATIONS   = 0x08,
    SECTION_MODULES       = 0x09,
    SECTION_THREADS       = 0x0A,
    SECTION_HANDLES       = 0x0B,
    SECTION_MEMORY        = 0x0C,
    SECTION_NETWORK       = 0x0D,
    SECTION_ENV           = 0x0E,
    SECTION_TOKEN         = 0x0F,
    SECTION_STARTED       = 0x10,
    SECTION_INST_CALLBACK = 0x11,
};

enum section_flag : UINT32 {
    FLAG_PID           = 1 << 0,
    FLAG_PPID          = 1 << 1,
    FLAG_ARCH          = 1 << 2,
    FLAG_IMAGE_NAME    = 1 << 3,
    FLAG_IMAGE_PATH    = 1 << 4,
    FLAG_CMDLINE       = 1 << 5,
    FLAG_PROTECTION    = 1 << 6,
    FLAG_MITIGATIONS   = 1 << 7,
    FLAG_MODULES       = 1 << 8,
    FLAG_THREADS       = 1 << 9,
    FLAG_HANDLES       = 1 << 10,
    FLAG_MEMORY        = 1 << 11,
    FLAG_NETWORK       = 1 << 12,
    FLAG_ENV           = 1 << 13,
    FLAG_TOKEN         = 1 << 14,
    FLAG_STARTED       = 1 << 15,
    FLAG_INST_CALLBACK = 1 << 16,
    FLAG_ALL           = 0xFFFFFFFF,
};

auto get_mitigations(
    _In_ HANDLE process_handle
) -> void {
    const char* entries[ 128 ] = {};
    int         count          = 0;
 
    auto query = [&]( PROCESS_MITIGATION_POLICY pol ) -> PROCESS_MITIGATION_POLICY_INFORMATION
    {
        PROCESS_MITIGATION_POLICY_INFORMATION info = {};
        info.Policy = pol;
        NTSTATUS status = STATUS_SUCCESS;
        if ( ! nt_success (status = NtQueryInformationProcess( process_handle, ProcessMitigationPolicy, &info, sizeof( info ), nullptr ))){
            //BeaconPrintf(CALLBACK_OUTPUT, "NTQuery failed with error: %x during: %d", status, pol); todo
        }
        return info;
    };
 
    auto add = [&]( const char* name, bool enabled )
    {
        if ( enabled && count < 128 )
            entries[ count++ ] = name;
    };
 
    {
        ULONG dep_flags = 0;
        NTSTATUS status = NtQueryInformationProcess( process_handle, ProcessExecuteFlags, &dep_flags, sizeof( dep_flags ), nullptr );

        if ( nt_success( status ) )
        {
            add( "DEP.Enable",                   dep_flags & 0x01 );
            add( "DEP.DisableAtlThunkEmulation", dep_flags & 0x02 );
            add( "DEP.Permanent",                dep_flags & 0x08 );
        } else{
            BeaconPrintf(CALLBACK_OUTPUT, "NTQuery failed with error: %x during: DEP", status);
        }

    }
 
    {
        auto p = query( ProcessASLRPolicy );
        add( "ASLR.EnableBottomUpRandomization",  p.ASLRPolicy.EnableBottomUpRandomization );
        add( "ASLR.EnableForceRelocateImages",    p.ASLRPolicy.EnableForceRelocateImages );
        add( "ASLR.EnableHighEntropy",            p.ASLRPolicy.EnableHighEntropy );
        add( "ASLR.DisallowStrippedImages",       p.ASLRPolicy.DisallowStrippedImages );
    }
 
    {
        auto p = query( ProcessDynamicCodePolicy );
        add( "DynamicCode.ProhibitDynamicCode",      p.DynamicCodePolicy.ProhibitDynamicCode );
        add( "DynamicCode.AllowThreadOptOut",        p.DynamicCodePolicy.AllowThreadOptOut );
        add( "DynamicCode.AllowRemoteDowngrade",     p.DynamicCodePolicy.AllowRemoteDowngrade );
        add( "DynamicCode.AuditProhibitDynamicCode", p.DynamicCodePolicy.AuditProhibitDynamicCode );
    }
 
    {
        auto p = query( ProcessStrictHandleCheckPolicy );
        add( "StrictHandleCheck.RaiseExceptionOnInvalidHandleReference", p.StrictHandleCheckPolicy.RaiseExceptionOnInvalidHandleReference );
        add( "StrictHandleCheck.HandleExceptionsPermanentlyEnabled",     p.StrictHandleCheckPolicy.HandleExceptionsPermanentlyEnabled );
    }
 
    {
        auto p = query( ProcessSystemCallDisablePolicy );
        add( "SystemCallDisable.DisallowWin32kSystemCalls",      p.SystemCallDisablePolicy.DisallowWin32kSystemCalls );
        add( "SystemCallDisable.AuditDisallowWin32kSystemCalls", p.SystemCallDisablePolicy.AuditDisallowWin32kSystemCalls );
        add( "SystemCallDisable.DisallowFsctlSystemCalls",       p.SystemCallDisablePolicy.DisallowFsctlSystemCalls );
        add( "SystemCallDisable.AuditDisallowFsctlSystemCalls",  p.SystemCallDisablePolicy.AuditDisallowFsctlSystemCalls );
    }
 
    {
        auto p = query( ProcessExtensionPointDisablePolicy );
        add( "ExtensionPointDisable.DisableExtensionPoints", p.ExtensionPointDisablePolicy.DisableExtensionPoints );
    }
 
    {
        auto p = query( ProcessControlFlowGuardPolicy );
        add( "CFG.EnableControlFlowGuard",   p.ControlFlowGuardPolicy.EnableControlFlowGuard );
        add( "CFG.EnableExportSuppression",  p.ControlFlowGuardPolicy.EnableExportSuppression );
        add( "CFG.StrictMode",               p.ControlFlowGuardPolicy.StrictMode );
        add( "CFG.EnableXfg",                p.ControlFlowGuardPolicy.EnableXfg );
        add( "CFG.EnableXfgAuditMode",       p.ControlFlowGuardPolicy.EnableXfgAuditMode );
    }
 
    {
        auto p = query( ProcessSignaturePolicy );
        add( "Signature.MicrosoftSignedOnly",      p.SignaturePolicy.MicrosoftSignedOnly );
        add( "Signature.StoreSignedOnly",          p.SignaturePolicy.StoreSignedOnly );
        add( "Signature.MitigationOptIn",          p.SignaturePolicy.MitigationOptIn );
        add( "Signature.AuditMicrosoftSignedOnly", p.SignaturePolicy.AuditMicrosoftSignedOnly );
        add( "Signature.AuditStoreSignedOnly",     p.SignaturePolicy.AuditStoreSignedOnly );
    }
 
    {
        auto p = query( ProcessFontDisablePolicy );
        add( "FontDisable.DisableNonSystemFonts",     p.FontDisablePolicy.DisableNonSystemFonts );
        add( "FontDisable.AuditNonSystemFontLoading", p.FontDisablePolicy.AuditNonSystemFontLoading );
    }
 
    {
        auto p = query( ProcessImageLoadPolicy );
        add( "ImageLoad.NoRemoteImages",                  p.ImageLoadPolicy.NoRemoteImages );
        add( "ImageLoad.NoLowMandatoryLabelImages",       p.ImageLoadPolicy.NoLowMandatoryLabelImages );
        add( "ImageLoad.PreferSystem32Images",            p.ImageLoadPolicy.PreferSystem32Images );
        add( "ImageLoad.AuditNoRemoteImages",             p.ImageLoadPolicy.AuditNoRemoteImages );
        add( "ImageLoad.AuditNoLowMandatoryLabelImages",  p.ImageLoadPolicy.AuditNoLowMandatoryLabelImages );
    }
 
    {
        auto p = query( ProcessChildProcessPolicy );
        add( "ChildProcess.NoChildProcessCreation",      p.ChildProcessPolicy.NoChildProcessCreation );
        add( "ChildProcess.AuditNoChildProcessCreation", p.ChildProcessPolicy.AuditNoChildProcessCreation );
        add( "ChildProcess.AllowSecureProcessCreation",  p.ChildProcessPolicy.AllowSecureProcessCreation );
    }
 
    {
        auto p = query( ProcessSystemCallFilterPolicy );
        add( "SystemCallFilter.FilterId", p.SystemCallFilterPolicy.FilterId );
    }
 
    {
        auto p = query( ProcessPayloadRestrictionPolicy );
        add( "PayloadRestriction.EnableExportAddressFilter",       p.PayloadRestrictionPolicy.EnableExportAddressFilter );
        add( "PayloadRestriction.AuditExportAddressFilter",        p.PayloadRestrictionPolicy.AuditExportAddressFilter );
        add( "PayloadRestriction.EnableExportAddressFilterPlus",   p.PayloadRestrictionPolicy.EnableExportAddressFilterPlus );
        add( "PayloadRestriction.AuditExportAddressFilterPlus",    p.PayloadRestrictionPolicy.AuditExportAddressFilterPlus );
        add( "PayloadRestriction.EnableImportAddressFilter",       p.PayloadRestrictionPolicy.EnableImportAddressFilter );
        add( "PayloadRestriction.AuditImportAddressFilter",        p.PayloadRestrictionPolicy.AuditImportAddressFilter );
        add( "PayloadRestriction.EnableRopStackPivot",             p.PayloadRestrictionPolicy.EnableRopStackPivot );
        add( "PayloadRestriction.AuditRopStackPivot",              p.PayloadRestrictionPolicy.AuditRopStackPivot );
        add( "PayloadRestriction.EnableRopCallerCheck",            p.PayloadRestrictionPolicy.EnableRopCallerCheck );
        add( "PayloadRestriction.AuditRopCallerCheck",             p.PayloadRestrictionPolicy.AuditRopCallerCheck );
        add( "PayloadRestriction.EnableRopSimExec",                p.PayloadRestrictionPolicy.EnableRopSimExec );
        add( "PayloadRestriction.AuditRopSimExec",                 p.PayloadRestrictionPolicy.AuditRopSimExec );
    }
 
    {
        auto p = query( ProcessSideChannelIsolationPolicy );
        add( "SideChannel.SmtBranchTargetIsolation",       p.SideChannelIsolationPolicy.SmtBranchTargetIsolation );
        add( "SideChannel.IsolateSecurityDomain",          p.SideChannelIsolationPolicy.IsolateSecurityDomain );
        add( "SideChannel.DisablePageCombine",             p.SideChannelIsolationPolicy.DisablePageCombine );
        add( "SideChannel.SpeculativeStoreBypassDisable",  p.SideChannelIsolationPolicy.SpeculativeStoreBypassDisable );
        add( "SideChannel.RestrictCoreSharing",            p.SideChannelIsolationPolicy.RestrictCoreSharing );
    }
 
    {
        auto p = query( ProcessUserShadowStackPolicy );
        add( "CET.EnableUserShadowStack",                    p.UserShadowStackPolicy.EnableUserShadowStack );
        add( "CET.AuditUserShadowStack",                     p.UserShadowStackPolicy.AuditUserShadowStack );
        add( "CET.SetContextIpValidation",                   p.UserShadowStackPolicy.SetContextIpValidation );
        add( "CET.AuditSetContextIpValidation",              p.UserShadowStackPolicy.AuditSetContextIpValidation );
        add( "CET.EnableUserShadowStackStrictMode",          p.UserShadowStackPolicy.EnableUserShadowStackStrictMode );
        add( "CET.BlockNonCetBinaries",                      p.UserShadowStackPolicy.BlockNonCetBinaries );
        add( "CET.BlockNonCetBinariesNonEhcont",             p.UserShadowStackPolicy.BlockNonCetBinariesNonEhcont );
        add( "CET.AuditBlockNonCetBinaries",                 p.UserShadowStackPolicy.AuditBlockNonCetBinaries );
        add( "CET.CetDynamicApisOutOfProcOnly",              p.UserShadowStackPolicy.CetDynamicApisOutOfProcOnly );
        add( "CET.SetContextIpValidationRelaxedMode",        p.UserShadowStackPolicy.SetContextIpValidationRelaxedMode );
    }
 
    {
        auto p = query( ProcessRedirectionTrustPolicy );
        add( "RedirectionTrust.EnforceRedirectionTrust", p.RedirectionTrustPolicy.EnforceRedirectionTrust );
        add( "RedirectionTrust.AuditRedirectionTrust",   p.RedirectionTrustPolicy.AuditRedirectionTrust );
    }
 
    {
        auto p = query( ProcessUserPointerAuthPolicy );
        add( "UserPointerAuth.EnablePointerAuthUserIp", p.UserPointerAuthPolicy.EnablePointerAuthUserIp );
    }
 
    {
        auto p = query( ProcessSEHOPPolicy );
        add( "SEHOP.EnableSehop", p.SEHOPPolicy.EnableSehop );
    }

    BeaconPkgInt32( SECTION_MITIGATIONS );
    BeaconPkgInt32( count );
    for ( int i = 0; i < count; i++ )
        BeaconPkgBytes( ( PBYTE ) entries[ i ], ( ULONG ) strlen( entries[ i ] ) );
}

auto get_protection(
    _In_ HANDLE process_handle
) -> void {
    PS_PROTECTION protection = {};

    NTSTATUS status = NtQueryInformationProcess( process_handle, ProcessProtectionInformation, &protection, sizeof( protection ), nullptr);

    if ( ! nt_success( status ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[DEBUG] protection query failed: 0x%X", status );
        return;
    }

    BeaconPkgInt32( SECTION_PROTECTION );
    BeaconPkgInt32( protection.Type );
    BeaconPkgInt32( protection.Audit );
    BeaconPkgInt32( protection.Signer );
}

auto get_cmdline(
    _In_ HANDLE process_handle
) -> void {
    NTSTATUS status     = STATUS_SUCCESS;
    ULONG    return_len = 0;

    status = NtQueryInformationProcess( process_handle, ProcessCommandLineInformation, nullptr, 0, &return_len );

    if ( return_len == 0 ) {
        return;
    }

    auto cmdline = ( PUNICODE_STRING ) malloc( return_len );
    if ( ! cmdline ) {
        return;
    }

    status = NtQueryInformationProcess( process_handle, ProcessCommandLineInformation, cmdline, return_len, nullptr );

    if ( nt_success( status ) && cmdline->Buffer ) {
        BeaconPkgInt32( SECTION_CMDLINE );
        BeaconPkgBytes( ( PBYTE ) cmdline->Buffer, cmdline->Length );
    }

    free( cmdline );
}

auto get_modules(
    _In_ HANDLE process_handle
) -> void {
    ULONG bytes_needed = 0;

    K32EnumProcessModulesEx( process_handle, nullptr, 0, &bytes_needed, LIST_MODULES_ALL );

    if ( bytes_needed == 0 ) {
        return;
    }

    auto hmodules = ( HMODULE* ) malloc( bytes_needed );
    if ( ! hmodules ) return;

    if ( ! K32EnumProcessModulesEx( process_handle, hmodules, bytes_needed, &bytes_needed, LIST_MODULES_ALL ) ) {
        free( hmodules );
        return;
    }

    INT32 total = bytes_needed / sizeof( HMODULE );

    struct mod_entry {
        WCHAR      name[ MAX_PATH ];
        MODULEINFO info;
    };

    auto entries = ( mod_entry* ) malloc( sizeof( mod_entry ) * total );
    if ( ! entries ) {
        free( hmodules );
        return;
    }

    INT32 count = 0;

    for ( INT32 i = 0; i < total; i++ ) {
        memset( &entries[ count ], 0, sizeof( mod_entry ) );

        if ( K32GetModuleFileNameExW( process_handle, hmodules[ i ], entries[ count ].name, MAX_PATH ) ) {
            K32GetModuleInformation( process_handle, hmodules[ i ], &entries[ count ].info, sizeof( MODULEINFO ) );
            count++;
        }
    }

    BeaconPrintf( CALLBACK_OUTPUT, "[DEBUG] modules: collected=%d", count );

    if ( count > 0 ) {
        BeaconPkgInt32( SECTION_MODULES );
        BeaconPkgInt32( count );

        for ( INT32 i = 0; i < count; i++ ) {
            BeaconPkgBytes( ( PBYTE ) entries[ i ].name, wcslen( entries[ i ].name ) * sizeof( WCHAR ) );

            ULONG_PTR entry = ( ULONG_PTR ) entries[ i ].info.EntryPoint;
            ULONG_PTR base  = ( ULONG_PTR ) entries[ i ].info.lpBaseOfDll;
            BeaconPkgBytes( ( PBYTE ) &entry, sizeof( ULONG_PTR ) );
            BeaconPkgBytes( ( PBYTE ) &base,  sizeof( ULONG_PTR ) );
            
            BeaconPkgInt32( entries[ i ].info.SizeOfImage );
        }
    }

    free( entries );
    free( hmodules );
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


extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = {};
    BeaconDataParse( &data_parser, args, argc );

    DWORD    target_pid    = ( DWORD ) BeaconDataInt( &data_parser );
    UINT32 section_flags = ( UINT32 ) BeaconDataInt( &data_parser );

    HANDLE process_handle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid );
    if ( ! process_handle || process_handle == INVALID_HANDLE_VALUE ) {
        return;
    }

    if ( section_flags & FLAG_PROTECTION ) {
        get_protection( process_handle );
    }

    if ( section_flags & FLAG_MITIGATIONS ) {
        get_mitigations( process_handle );
    }
    
    if ( section_flags & FLAG_CMDLINE ) {
        get_cmdline( process_handle );
    }

    if ( section_flags & FLAG_MODULES ) {
        get_modules( process_handle );
    }


    BeaconPkgInt32( SECTION_END );

    CloseHandle( process_handle );
}
