#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* file_path = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    ULONG  file_size = 0;
    ULONG  file_read = 0;
    PVOID  file_buff = nullptr;
    ULONG  file_attr = GetFileAttributesW( file_path );

    if ( file_attr == INVALID_FILE_ATTRIBUTES || file_attr == INVALID_FILE_ATTRIBUTES ) {
        BeaconPrintfW( CALLBACK_ERROR, L"File does not exist or is inaccessible: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    if ( file_attr & FILE_ATTRIBUTE_DIRECTORY ) {
        BeaconPrintfW( CALLBACK_ERROR, L"File is directories. Not possible to read.\n" );
        return;
    }

    HANDLE file_handle = CreateFileW( file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
    if ( file_handle == INVALID_HANDLE_VALUE )  {
        BeaconPrintfW( CALLBACK_ERROR, L"File does not exist or is inaccessible (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    file_size = GetFileSize( file_handle, 0 );
    file_buff = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, file_size + 1 );

    if ( ! ReadFile( file_handle, file_buff, file_size, &file_read, 0 ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed read file error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    CloseHandle( file_handle );

    ((CHAR*)(file_buff))[file_size] = '\0';

    BeaconPrintf( CALLBACK_OUTPUT, "%s", file_buff );

    HeapFree( GetProcessHeap(), 0, file_buff );

    return;
}