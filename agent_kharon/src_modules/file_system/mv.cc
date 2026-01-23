#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* src_file = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    WCHAR* dst_file = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    ULONG src_attr =  GetFileAttributesW( src_file );
    ULONG dst_attr =  GetFileAttributesW( dst_file );

    if ( src_attr == INVALID_FILE_ATTRIBUTES || dst_attr == INVALID_FILE_ATTRIBUTES ) {
        BeaconPrintf( CALLBACK_ERROR, "Source or destination file does not exist or is inaccessible: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    if ( ( dst_attr & FILE_ATTRIBUTE_DIRECTORY ) || ( src_attr & FILE_ATTRIBUTE_DIRECTORY ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Source or destination are directories. Recursive move not implemented.\n" );
        return;
    }

    if ( ! MoveFileW( src_file, dst_file ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed move file to destination with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "File moved with success!\n" );
    
    return;
}