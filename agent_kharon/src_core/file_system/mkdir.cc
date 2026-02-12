#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* path = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    if ( ! CreateDirectoryW( path, nullptr ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed make directory with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Directory created!\n" );
    
    return;
}