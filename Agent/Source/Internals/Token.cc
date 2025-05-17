#include <Kharon.h>

using namespace Root;

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