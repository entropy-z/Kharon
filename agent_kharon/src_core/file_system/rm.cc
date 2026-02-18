#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* file_delete = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    ULONG file_attribute = GetFileAttributesW( file_delete );

    if ( file_attribute == INVALID_FILE_ATTRIBUTES ) {
        BeaconPrintfW( CALLBACK_ERROR, L"File does not exist or is inaccessible: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    if ( file_attribute & FILE_ATTRIBUTE_DIRECTORY ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Target is a directory. Recursive delete not implemented.\n" );
        return;
    }

    if ( ! DeleteFileW( file_delete ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to delete file with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintfW( CALLBACK_OUTPUT, L"File delete with success!\n" );
    
    return;
}