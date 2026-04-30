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
    SECTION_BASIC_INFO    = 0x10,
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
    FLAG_BASIC_INFO    = 1 << 15,
    FLAG_INST_CALLBACK = 1 << 16,
    FLAG_ALL           = 0xFFFFFFFF,
};

struct query_name_ctx {
    HANDLE                    dup;
    POBJECT_NAME_INFORMATION  name_info;
    ULONG                     name_size;
    BOOL                      success;
};

DWORD WINAPI query_name_thread( LPVOID param ) {
    auto ctx = ( query_name_ctx* ) param;
    ctx->success = nt_success(
        NtQueryObject( ctx->dup, ObjectNameInformation, ctx->name_info, ctx->name_size, nullptr )
    );
    return 0;
}

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
        BeaconPrintf( CALLBACK_OUTPUT, "[DEBUG] threads: snapshot failed %d", GetLastError() );
        return;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof( THREADENTRY32 );

    INT32 count = 0;

    if ( Thread32First( snapshot, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == process_id )
                count++;
        } while ( Thread32Next( snapshot, &te ) );
    }

    if ( count == 0 ) {
        CloseHandle( snapshot );
        return;
    }

    BeaconPkgInt32( SECTION_THREADS );
    BeaconPkgInt32( count );

    te.dwSize = sizeof( THREADENTRY32 );

    if ( Thread32First( snapshot, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == process_id ) {
                BeaconPkgInt32( te.th32ThreadID );
                BeaconPkgInt32( te.dwFlags );
                BeaconPkgInt32( te.dwSize );
                BeaconPkgInt32( te.tpBasePri );
                BeaconPkgInt32( te.tpDeltaPri );
            }
        } while ( Thread32Next( snapshot, &te ) );
    }

    CloseHandle( snapshot );
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
        return;
    }

    auto handle_info = ( PPROCESS_HANDLE_SNAPSHOT_INFORMATION ) buffer;
    INT32 count = ( INT32 ) handle_info->NumberOfHandles;

    if ( count == 0 ) {
        free( buffer );
        return;
    }

    struct handle_entry {
        INT32 value;
        INT32 access;
        WCHAR type_name[ 128 ];
        WCHAR obj_name[ 512 ];
    };

    auto entries = ( handle_entry* ) malloc( sizeof( handle_entry ) * count );
    if ( ! entries ) {
        free( buffer );
        return;
    }

    INT32 valid = 0;

    for ( INT32 i = 0; i < count; i++ ) {
        HANDLE dup = nullptr;

        if ( ! DuplicateHandle(
            process_handle,
            handle_info->Handles[ i ].HandleValue,
            GetCurrentProcess(),
            &dup,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        ) ) {
            continue;
        }

        memset( &entries[ valid ], 0, sizeof( handle_entry ) );
        entries[ valid ].value  = ( INT32 )( ULONG_PTR ) handle_info->Handles[ i ].HandleValue;
        entries[ valid ].access = handle_info->Handles[ i ].GrantedAccess;

        // type name
        BYTE type_buf[ 1024 ] = {};
        if ( nt_success( NtQueryObject( dup, ObjectTypeInformation, type_buf, sizeof( type_buf ), nullptr ) ) ) {
            auto type_info = ( POBJECT_TYPE_INFORMATION ) type_buf;
            if ( type_info->TypeName.Buffer && type_info->TypeName.Length > 0 ) {
                ULONG copy_len = min( type_info->TypeName.Length, ( USHORT )( 127 * sizeof( WCHAR ) ) );
                memcpy( entries[ valid ].type_name, type_info->TypeName.Buffer, copy_len );
            }
        }

        // object name — File and ALPC Port can deadlock, use timeout thread
        BOOL needs_timeout = (
            wcscmp( entries[ valid ].type_name, L"File" ) == 0 ||
            wcscmp( entries[ valid ].type_name, L"ALPC Port" ) == 0
        );

        ULONG name_size = 0x400;
        auto  name_buf  = ( POBJECT_NAME_INFORMATION ) malloc( name_size );

        if ( name_buf ) {
            BOOL got_name = FALSE;

            if ( needs_timeout ) {
                query_name_ctx ctx = {};
                ctx.dup       = dup;
                ctx.name_info = name_buf;
                ctx.name_size = name_size;
                ctx.success   = FALSE;

                HANDLE thread = CreateThread( nullptr, 0, query_name_thread, &ctx, 0, nullptr );
                if ( thread ) {
                    if ( WaitForSingleObject( thread, 100 ) == WAIT_TIMEOUT ) {
                        TerminateThread( thread, 0 );
                    } else {
                        got_name = ctx.success;
                    }
                    CloseHandle( thread );
                }
            } else {
                got_name = nt_success(
                    NtQueryObject( dup, ObjectNameInformation, name_buf, name_size, nullptr )
                );
            }

            if ( got_name && name_buf->Name.Buffer && name_buf->Name.Length > 0 ) {
                ULONG copy_len = min( name_buf->Name.Length, ( USHORT )( 511 * sizeof( WCHAR ) ) );
                memcpy( entries[ valid ].obj_name, name_buf->Name.Buffer, copy_len );
            }

            free( name_buf );
        }

        CloseHandle( dup );
        valid++;
    }

    if ( valid > 0 ) {
        BeaconPkgInt32( SECTION_HANDLES );
        BeaconPkgInt32( valid );

        for ( INT32 i = 0; i < valid; i++ ) {
            BeaconPkgInt32( entries[ i ].value );
            BeaconPkgInt32( entries[ i ].access );
            BeaconPkgBytes( ( PBYTE ) entries[ i ].type_name, wcslen( entries[ i ].type_name ) * sizeof( WCHAR ) );
            BeaconPkgBytes( ( PBYTE ) entries[ i ].obj_name,  wcslen( entries[ i ].obj_name )  * sizeof( WCHAR ) );
        }
    }

    free( entries );
    free( buffer );
}

auto get_tokens(
    _In_ HANDLE process_handle
) -> void {
    HANDLE token_handle = nullptr;

    if ( ! OpenProcessToken( process_handle, TOKEN_QUERY, &token_handle ) ) {
        return;
    }

    WCHAR       username[MAX_PATH] = { 0 };
    WCHAR       domain  [MAX_PATH] = { 0 };
    INT32       is_elevated        = 0;
    const char* level_str          = "Unknown";

    ULONG token_user_size = 0;
    GetTokenInformation( token_handle, TokenUser, nullptr, 0, &token_user_size );

    auto token_user = ( PTOKEN_USER ) malloc( token_user_size );
    if ( token_user && GetTokenInformation( token_handle, TokenUser, token_user, token_user_size, &token_user_size ) ) {
        DWORD        username_len = MAX_PATH;
        DWORD        domain_len   = MAX_PATH;
        SID_NAME_USE sid_type;

        LookupAccountSidW( nullptr, token_user->User.Sid, username, &username_len, domain, &domain_len, &sid_type );
    }

    TOKEN_ELEVATION elevation      = { 0 };
    ULONG           elevation_size = sizeof( elevation );
    if ( GetTokenInformation( token_handle, TokenElevation, &elevation, sizeof( elevation ), &elevation_size ) ) {
        is_elevated = elevation.TokenIsElevated;
    }

    ULONG integrity_size = 0;
    GetTokenInformation( token_handle, TokenIntegrityLevel, nullptr, 0, &integrity_size );

    auto integrity = ( PTOKEN_MANDATORY_LABEL ) malloc( integrity_size );
    if ( integrity && GetTokenInformation( token_handle, TokenIntegrityLevel, integrity, integrity_size, &integrity_size ) ) {
        ULONG integrity_level = *GetSidSubAuthority(
            integrity->Label.Sid, ( DWORD )( UCHAR )( *GetSidSubAuthorityCount( integrity->Label.Sid ) - 1 )
        );

        if      ( integrity_level >= SECURITY_MANDATORY_SYSTEM_RID ) level_str = "System";
        else if ( integrity_level >= SECURITY_MANDATORY_HIGH_RID   ) level_str = "High";
        else if ( integrity_level >= SECURITY_MANDATORY_MEDIUM_RID ) level_str = "Medium";
        else if ( integrity_level >= SECURITY_MANDATORY_LOW_RID    ) level_str = "Low";
        else                                                         level_str = "Untrusted";
    }

    ULONG priv_size = 0;
    GetTokenInformation( token_handle, TokenPrivileges, nullptr, 0, &priv_size );

    DWORD priv_count = 0;
    auto  privs      = ( PTOKEN_PRIVILEGES ) malloc( priv_size );

    if ( privs && GetTokenInformation( token_handle, TokenPrivileges, privs, priv_size, &priv_size ) ) {
        priv_count = privs->PrivilegeCount;
    }

    BeaconPkgInt32( SECTION_TOKEN );
    BeaconPkgBytes( ( PBYTE ) username,  wcslen( username ) * sizeof( WCHAR ) );
    BeaconPkgBytes( ( PBYTE ) domain,    wcslen( domain )   * sizeof( WCHAR ) );
    BeaconPkgInt32( is_elevated );
    BeaconPkgBytes( ( PBYTE ) level_str, strlen( level_str ) );

    BeaconPkgInt32( priv_count );

    for ( DWORD i = 0; i < priv_count; i++ ) {
        WCHAR priv_name[256] = { 0 };
        DWORD priv_name_len  = 256;

        if ( LookupPrivilegeNameW( nullptr, &privs->Privileges[i].Luid, priv_name, &priv_name_len ) ) {
            BeaconPkgBytes( ( PBYTE ) priv_name, wcslen( priv_name ) * sizeof( WCHAR ) );
        } else {
            BeaconPkgBytes( ( PBYTE ) L"Unknown", 7 * sizeof( WCHAR ) );
        }

        BeaconPkgInt32( ( privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED ) ? 1 : 0 );
    }

    if ( privs )      free( privs );
    if ( token_user ) free( token_user );
    if ( integrity )  free( integrity );
    CloseHandle( token_handle );
}

auto get_env(
    _In_ HANDLE process_handle
) -> void {
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    NTSTATUS status = NtQueryInformationProcess( process_handle, ProcessBasicInformation, &basic_info, sizeof( basic_info ), nullptr );

    if ( ! nt_success( status ) ) {return;}

    if ( ! basic_info.PebBaseAddress ) {return;}

    PEB peb = { 0 };
    if ( ! ReadProcessMemory( process_handle, basic_info.PebBaseAddress, &peb, sizeof( peb ), nullptr ) ) {return;}

    if ( ! peb.ProcessParameters ) {return;}

    RTL_USER_PROCESS_PARAMETERS params = { 0 };
    if ( ! ReadProcessMemory( process_handle, peb.ProcessParameters, &params, sizeof( params ), nullptr ) ) {return;}

    if ( ! params.Environment || params.EnvironmentSize == 0 ) {return;}

    if ( params.EnvironmentSize > 0x100000 ) {return;}

    auto env_buf = ( PBYTE ) malloc( params.EnvironmentSize );
    if ( ! env_buf ) {return;}


    SIZE_T bytes_read = 0;
    if ( ! ReadProcessMemory( process_handle, params.Environment, env_buf, params.EnvironmentSize, &bytes_read ) ) {
        free( env_buf );
        return;
    }

    BeaconPkgInt32( SECTION_ENV );
    BeaconPkgBytes( env_buf, params.EnvironmentSize );

    free( env_buf );
}

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

auto get_basic_info(
    _In_ HANDLE process_handle,
    _In_ DWORD  target_pid
) -> void {
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    NTSTATUS status = NtQueryInformationProcess( process_handle, ProcessBasicInformation, &basic_info, sizeof( basic_info ), nullptr );

    if ( ! nt_success( status ) ) {
        return;
    }

    DWORD ppid = ( DWORD )( ULONG_PTR ) basic_info.InheritedFromUniqueProcessId;

    WCHAR image_path[MAX_PATH] = { 0 };
    ULONG path_size = 0;

    status = NtQueryInformationProcess( process_handle, ProcessImageFileNameWin32, nullptr, 0, &path_size );

    if ( path_size > 0 && path_size <= 0x10000 ) {
        auto path_buf = ( PUNICODE_STRING ) malloc( path_size );
        if ( path_buf ) {
            status = NtQueryInformationProcess( process_handle, ProcessImageFileNameWin32, path_buf, path_size, nullptr );

            if ( nt_success( status ) && path_buf->Buffer && path_buf->Length > 0 ) {
                USHORT copy_len = path_buf->Length / sizeof( WCHAR );
                if ( copy_len >= MAX_PATH ) copy_len = MAX_PATH - 1;
                memcpy( image_path, path_buf->Buffer, copy_len * sizeof( WCHAR ) );
                image_path[copy_len] = L'\0';
            }

            free( path_buf );
        }
    }

    WCHAR  image_name[MAX_PATH] = { 0 };
    PWCHAR src       = image_path;
    PWCHAR last_slash = wcsrchr( image_path, L'\\' );

    if ( last_slash ) {
        src = last_slash + 1;
    }

    SIZE_T src_len = wcslen( src );
    if ( src_len >= MAX_PATH ) {
        src_len = MAX_PATH - 1;
    }

    memcpy( image_name, src, src_len * sizeof( WCHAR ) );
    image_name[src_len] = L'\0';

    USHORT process_machine = 0;
    USHORT native_machine  = 0;
    INT32  arch            = 0;

    if ( IsWow64Process2( process_handle, &process_machine, &native_machine ) ) {
        if ( process_machine == IMAGE_FILE_MACHINE_I386 ) {
            arch = 1;
        } else if ( native_machine == IMAGE_FILE_MACHINE_AMD64 ) {
            arch = 2;
        } else if ( native_machine == IMAGE_FILE_MACHINE_ARM64 ) {
            arch = 3;
        }
    } else {
        BOOL is_wow64 = FALSE;
        if ( IsWow64Process( process_handle, &is_wow64 ) ) {
            arch = is_wow64 ? 1 : 2;
        }
    }

    FILETIME creation_time = { 0 };
    FILETIME exit_time     = { 0 };
    FILETIME kernel_time   = { 0 };
    FILETIME user_time     = { 0 };

    GetProcessTimes( process_handle, &creation_time, &exit_time, &kernel_time, &user_time );

    BeaconPkgInt32( SECTION_BASIC_INFO );
    BeaconPkgInt32( target_pid );
    BeaconPkgInt32( ppid );
    BeaconPkgBytes( ( PBYTE ) image_name, wcslen( image_name ) * sizeof( WCHAR ) );
    BeaconPkgBytes( ( PBYTE ) image_path, wcslen( image_path ) * sizeof( WCHAR ) );
    BeaconPkgInt32( arch );
    BeaconPkgInt32( creation_time.dwHighDateTime );
    BeaconPkgInt32( creation_time.dwLowDateTime );
}


extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = {};
    BeaconDataParse( &data_parser, args, argc );

    DWORD    target_pid    = ( DWORD ) BeaconDataInt( &data_parser );
    UINT32 section_flags = ( UINT32 ) BeaconDataInt( &data_parser );

    HANDLE process_handle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, target_pid );
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

    if ( section_flags & FLAG_THREADS ) {
        get_threads( target_pid );
    }

    if ( section_flags & FLAG_HANDLES ) {
        get_handles( process_handle );
    }

    if ( section_flags & FLAG_TOKEN ) {
        get_tokens( process_handle );
    }

    if ( section_flags & FLAG_ENV ) {
        get_env( process_handle );
    }

    if ( section_flags & FLAG_BASIC_INFO ) {
        get_basic_info( process_handle, target_pid );
    }
    
    BeaconPkgInt32( SECTION_END );

    CloseHandle( process_handle );
}
