#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* folder_path = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    if ( ! SetCurrentDirectoryW( folder_path ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed change directory error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintfW( CALLBACK_OUTPUT, L"Changed directory to: %s\n", folder_path );

    return;
}