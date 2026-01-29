#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap    data_parser    = { 0 };
    PACKAGE  format_package = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* target_dir = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    
    WIN32_FIND_DATAW find_data = { 0 };

    WCHAR  full_path[MAX_PATH*sizeof(WCHAR)] = { 0 };

    HANDLE file_handle = nullptr;
    HANDLE find_handle = FindFirstFileW( target_dir, &find_data );
    ULONG  file_size   = 0;

    SYSTEMTIME creation_time = { 0 };
    SYSTEMTIME access_time   = { 0 };
    SYSTEMTIME write_time    = { 0 };

    if ( find_handle == INVALID_HANDLE_VALUE ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to list directory: '%s' | error: (%d) %s\n", target_dir, GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    GetFullPathNameW( find_data.cFileName, MAX_PATH * sizeof(WCHAR), full_path, nullptr );

    BeaconPkgBytes( (PBYTE)full_path, wcslen( full_path ) * sizeof(WCHAR) );

    do {
        file_handle = CreateFileW( find_data.cFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0 );
        file_size   = GetFileSize( file_handle, 0 );

        CloseHandle( file_handle );

        BeaconPkgBytes( (PBYTE)find_data.cFileName, wcslen( find_data.cFileName ) * sizeof(WCHAR) );
        BeaconPkgInt32( file_size );
        BeaconPkgInt32( find_data.dwFileAttributes );

        FileTimeToSystemTime( &find_data.ftCreationTime, &creation_time );

        BeaconPkgInt16( creation_time.wDay );
        BeaconPkgInt16( creation_time.wMonth );
        BeaconPkgInt16( creation_time.wYear );
        BeaconPkgInt16( creation_time.wHour );
        BeaconPkgInt16( creation_time.wMinute );
        BeaconPkgInt16( creation_time.wSecond );

        FileTimeToSystemTime( &find_data.ftCreationTime, &access_time );

        BeaconPkgInt16( access_time.wDay );
        BeaconPkgInt16( access_time.wMonth );
        BeaconPkgInt16( access_time.wYear );
        BeaconPkgInt16( access_time.wHour );
        BeaconPkgInt16( access_time.wMinute );
        BeaconPkgInt16( access_time.wSecond );

        FileTimeToSystemTime( &find_data.ftCreationTime, &write_time );

        BeaconPkgInt16( write_time.wDay );
        BeaconPkgInt16( write_time.wMonth );
        BeaconPkgInt16( write_time.wYear );
        BeaconPkgInt16( write_time.wHour );
        BeaconPkgInt16( write_time.wMinute );
        BeaconPkgInt16( write_time.wSecond );
    } while ( FindNextFileW( find_handle, &find_data ) );

    DbgPrint("hello from bof\n");

    FindClose( find_handle );
    
    return;
}