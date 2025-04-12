#include <Ground.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, 
    DWORD     Reason,     
    LPVOID    Reserved 
) {
    switch( Reason ) { 
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}