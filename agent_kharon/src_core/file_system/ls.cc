#include <general.h>

extern "C" auto go( char* args, int argc ) -> void 
{
    datap data_parser = { 0 };
    BeaconDataParse( &data_parser, args, argc );
    
    WCHAR* target_dir = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    
    WIN32_FIND_DATAW find_data    = { 0 };
    WCHAR full_path[MAX_PATH]     = { 0 };
    WCHAR base_dir[MAX_PATH]      = { 0 };
    WCHAR search_path[MAX_PATH]   = { 0 };
    WCHAR absolute_path[MAX_PATH] = { 0 };
    
    if ( GetFullPathNameW( target_dir, MAX_PATH, absolute_path, nullptr ) == 0 ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to resolve path: '%s' | error: (%d) %s\n", target_dir, GetLastError(), fmt_error( GetLastError() ) );
        return;
    }
    
    DWORD attribs = GetFileAttributesW( absolute_path );
    
    if ( attribs == INVALID_FILE_ATTRIBUTES ) {
        wcsncpy( search_path, absolute_path, MAX_PATH - 1 );
    }
    else if ( attribs & FILE_ATTRIBUTE_DIRECTORY ) {
        _swprintf( search_path, L"%s\\*", absolute_path );
    }
    else {
        wcsncpy( search_path, absolute_path, MAX_PATH - 1 );
    }
    
    wcsncpy( base_dir, search_path, MAX_PATH - 1 );
    WCHAR* last_slash = wcsrchr( base_dir, L'\\' );
    if ( last_slash ) {
        *( last_slash + 1 ) = L'\0';
    }
    
    HANDLE find_handle = FindFirstFileW( search_path, &find_data );
    
    if ( find_handle == INVALID_HANDLE_VALUE ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to list directory: '%s' | error: (%d) %s\n", search_path, GetLastError(), fmt_error( GetLastError() ) );
        return;
    }
    
    BeaconPkgBytes( (PBYTE)base_dir, ( wcslen( base_dir ) + 1 ) * sizeof( WCHAR ) );
    
    do {
        if ( wcscmp( find_data.cFileName, L"." ) == 0 || 
             wcscmp( find_data.cFileName, L".." ) == 0 )
        {
            continue;
        }
        
        _swprintf( full_path, L"%s%s", base_dir, find_data.cFileName );
        
        HANDLE file_handle = CreateFileW( 
            full_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr 
        );
        
        ULONG file_size = 0;
        if ( file_handle != INVALID_HANDLE_VALUE ) 
        {
            file_size = GetFileSize( file_handle, nullptr );
            CloseHandle( file_handle );
        }
        
        BeaconPkgBytes( (PBYTE)find_data.cFileName, ( wcslen( find_data.cFileName ) + 1 ) * sizeof( WCHAR ) );
        BeaconPkgInt32( file_size );
        BeaconPkgInt32( find_data.dwFileAttributes );
        
        // Timestamps
        SYSTEMTIME creation_time = { 0 };
        SYSTEMTIME access_time   = { 0 };
        SYSTEMTIME write_time    = { 0 };
        
        FileTimeToSystemTime( &find_data.ftCreationTime, &creation_time );
        FileTimeToSystemTime( &find_data.ftLastAccessTime, &access_time );
        FileTimeToSystemTime( &find_data.ftLastWriteTime, &write_time );
        
        BeaconPkgInt16( creation_time.wMonth );
        BeaconPkgInt16( creation_time.wDay );
        BeaconPkgInt16( creation_time.wYear );
        BeaconPkgInt16( creation_time.wHour );
        BeaconPkgInt16( creation_time.wMinute );
        BeaconPkgInt16( creation_time.wSecond );
        
        BeaconPkgInt16( access_time.wMonth );
        BeaconPkgInt16( access_time.wDay );
        BeaconPkgInt16( access_time.wYear );
        BeaconPkgInt16( access_time.wHour );
        BeaconPkgInt16( access_time.wMinute );
        BeaconPkgInt16( access_time.wSecond );
        
        BeaconPkgInt16( write_time.wMonth );
        BeaconPkgInt16( write_time.wDay );
        BeaconPkgInt16( write_time.wYear );
        BeaconPkgInt16( write_time.wHour );
        BeaconPkgInt16( write_time.wMinute );
        BeaconPkgInt16( write_time.wSecond );
        
    } while ( FindNextFileW( find_handle, &find_data ) );
    
    FindClose( find_handle );
}