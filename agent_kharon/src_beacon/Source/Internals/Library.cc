#include <Kharon.h>

auto DECLFN Library::Load(
    _In_ PCHAR LibName
) -> UPTR {
    if ( Self->Config.Syscall ) {
        return (UPTR)Self->Spf->Call( (UPTR)Self->Krnl32.LoadLibraryA, 0, (UPTR)LibName );
    }
    
    return (UPTR)Self->Krnl32.LoadLibraryA( LibName );
}
