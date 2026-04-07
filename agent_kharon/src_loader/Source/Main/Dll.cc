#include <Kharon.h>

EXTERN_C auto DLLEXPORT Runner( VOID ) -> VOID {
    EntryLoader();
}

auto WINAPI DllMain(
    HINSTANCE DllInstance,
    ULONG     Reason, 
    PVOID     Reserved
) -> BOOL {
    switch( Reason ) { 
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            if (Reserved != nullptr)
            {
                break;
            }
            break;
    }
    return TRUE;
}