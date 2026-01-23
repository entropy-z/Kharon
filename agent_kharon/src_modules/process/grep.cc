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

// EnumProcessModules + GetModuleFileNameExA
auto get_modules( 
    _In_ HANDLE process_handle 
) -> void {
    
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
    _In_ HANDLE process_handle 
) -> void {

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
    basicex_info.IsWow64Process;                            // arch
    basicex_info.UniqueProcessId;                           // pid
    basicex_info.BasicInfo.InheritedFromUniqueProcessId;    // ppid

    return;
}

// NtQueryInformationProcess( handle, ProcessHandleInformation ... ); # PROCESS_HANDLE_SNAPSHOT_INFORMATION
auto get_handles(
    _In_ HANDLE process_handle 
) -> void {
    PROCESS_HANDLE_SNAPSHOT_INFORMATION handle_snapshot_information = { 0 };
}

auto get_tokens(
    _In_ HANDLE process_handle 
) -> void {

}

// NtQueryInformationProcess( handle, ProcessCommandLineInformation ... ); # UNICODE_STRING
auto get_cmdline(
    _In_ HANDLE process_handle 
) -> void {

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
    if ( threads   ) get_threads( process_handle );
    if ( cmdline   ) get_cmdline( process_handle );
    if ( callbacks ) get_instcallbacks( process_handle );

    return;
}
