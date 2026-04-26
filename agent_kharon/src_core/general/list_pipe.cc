#include <general.h>

// Case-insensitive wide-char substring match
static auto wstr_icontains( WCHAR* haystack, WCHAR* needle ) -> BOOL {
    if ( !needle || !needle[0] ) return TRUE;

    for ( ULONG i = 0; haystack[i]; i++ ) {
        BOOL match = TRUE;
        for ( ULONG j = 0; needle[j]; j++ ) {
            if ( !haystack[i + j] ) { match = FALSE; break; }
            WCHAR a = haystack[i + j];
            WCHAR b = needle[j];
            if ( a >= L'A' && a <= L'Z' ) a += 32;
            if ( b >= L'A' && b <= L'Z' ) b += 32;
            if ( a != b ) { match = FALSE; break; }
        }
        if ( match ) return TRUE;
    }
    return FALSE;
}

extern "C" auto go( char* args, int argc ) -> void {
    datap parser = { 0 };
    BeaconDataParse( &parser, args, argc );
    WCHAR* filter = (WCHAR*)BeaconDataExtract( &parser, nullptr );

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW( L"\\\\.\\pipe\\*", &fd );
    if ( h == INVALID_HANDLE_VALUE ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to enumerate pipes: %d\n", GetLastError() );
        return;
    }

    int count = 0;
    do {
        if ( filter && filter[0] ) {
            if ( !wstr_icontains( fd.cFileName, filter ) ) continue;
        }
        BeaconPrintfW( CALLBACK_OUTPUT, L"  \\\\.\\pipe\\%s\n", fd.cFileName );
        count++;
    } while ( FindNextFileW( h, &fd ) );

    FindClose( h );
    BeaconPrintf( CALLBACK_OUTPUT, "\n[+] Found %d pipe(s)\n", count );
}
