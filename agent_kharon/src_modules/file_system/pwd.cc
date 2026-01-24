#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    ULONG  current_dir_sz = 0;
    WCHAR* current_dir    = nullptr;

    current_dir_sz = GetCurrentDirectoryW( current_dir_sz, current_dir );
    if ( ! current_dir_sz ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to get current directory with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    current_dir = (WCHAR*)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, current_dir_sz );

    if( ! GetCurrentDirectoryW( current_dir_sz, current_dir ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed tp get current directory with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Current directory is %ls\n", current_dir );

    HeapFree( GetProcessHeap(), 0, current_dir );

    return;
}