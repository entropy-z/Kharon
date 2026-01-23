#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser    = { 0 };
    fmt   format_package = { 0 };

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

    BeaconFormatAlloc( &format_package, 0x1000 );

    GetFullPathNameW( find_data.cFileName, MAX_PATH * sizeof(WCHAR), full_path, nullptr );

    BeaconFormatAppend( &format_package, (CHAR*)full_path, wcslen( full_path ) );

    do {
        file_handle = CreateFileW( find_data.cFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0 );
        file_size   = GetFileSize( file_handle, 0 );

        CloseHandle( file_handle );

        BeaconFormatAppend( &format_package, (CHAR*)find_data.cFileName, wcslen( find_data.cFileName ) );
        BeaconFormatInt( &format_package, file_size );
        BeaconFormatInt( &format_package, find_data.dwFileAttributes );

        FileTimeToSystemTime( &find_data.ftCreationTime, &creation_time );

        BeaconFormatInt( &format_package, creation_time.wDay );
        BeaconFormatInt( &format_package, creation_time.wMonth );
        BeaconFormatInt( &format_package, creation_time.wYear );
        BeaconFormatInt( &format_package, creation_time.wHour );
        BeaconFormatInt( &format_package, creation_time.wMinute );
        BeaconFormatInt( &format_package, creation_time.wSecond );

        FileTimeToSystemTime( &find_data.ftCreationTime, &access_time );

        BeaconFormatInt( &format_package, access_time.wDay );
        BeaconFormatInt( &format_package, access_time.wMonth );
        BeaconFormatInt( &format_package, access_time.wYear );
        BeaconFormatInt( &format_package, access_time.wHour );
        BeaconFormatInt( &format_package, access_time.wMinute );
        BeaconFormatInt( &format_package, access_time.wSecond );

        FileTimeToSystemTime( &find_data.ftCreationTime, &write_time );

        BeaconFormatInt( &format_package, write_time.wDay );
        BeaconFormatInt( &format_package, write_time.wMonth );
        BeaconFormatInt( &format_package, write_time.wYear );
        BeaconFormatInt( &format_package, write_time.wHour );
        BeaconFormatInt( &format_package, write_time.wMinute );
        BeaconFormatInt( &format_package, write_time.wSecond );
    } while ( FindNextFileW( find_handle, &find_data ) );

    CloseHandle( find_handle );

    BeaconOutput( CALLBACK_OUTPUT, format_package.Original, format_package.Length );

    BeaconFormatFree( &format_package );
    
    return;
}