#include <General.hpp>

auto DECLFN Mem::Copy(
    _In_ PVOID Dst,
    _In_ PVOID Src,
    _In_ UPTR  Size
) -> PVOID {
    return __builtin_memcpy( Dst, Src, Size );
}

auto DECLFN Mem::Set(
    _In_ PVOID Addr,
    _In_ UCHAR Val,
    _In_ UPTR  Size
) -> void {
    return __stosb( (UCHAR*)Addr, (UCHAR)Val, Size );
}

auto DECLFN Mem::Zero(
    _In_ PVOID Addr,
    _In_ UPTR  Size
) -> void {
    return __stosb( (UCHAR*)( Addr ), 0, (SIZE_T)Size );
}

extern "C" void* DECLFN memset(void* dest, int val, size_t count) {
    unsigned char* ptr = (unsigned char*)dest;
    while (count--) *ptr++ = (unsigned char)val;
    return dest;
}

extern "C" void* DECLFN memcpy(void* dest, const void* src, size_t count) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (count--) *d++ = *s++;
    return dest;
}

auto DECLFN Str::StartsWith(
    BYTE* Str, 
    BYTE* Prefix
) -> BOOL {
    if (!Str || !Prefix) {
        return FALSE;
    }

    while (*Prefix) {
        if (*Str != *Prefix) {
            return FALSE; 
        }
        ++Str;
        ++Prefix;
    }
    return TRUE;
}

auto DECLFN Str::CompareW( 
    LPCWSTR Str1, 
    LPCWSTR Str2 
) -> INT {
    while ( *Str1 && ( *Str1 == *Str2 ) ) {
        ++Str1;
        ++Str2;
    }
    return static_cast<INT>( *Str1 ) - static_cast<INT>( *Str2 );
}

auto DECLFN Str::LengthA( 
    LPCSTR String 
) -> SIZE_T {
    LPCSTR End = String;
    while (*End) ++End;
    return End - String;
}

auto DECLFN Str::LengthW( 
    LPCWSTR String 
) -> SIZE_T {
    if (!String) {  
        return 0;
    }

    LPCWSTR End = String;
    while (*End) {
        ++End;
    }
    return static_cast<SIZE_T>(End - String);
}

auto DECLFN Str::CharToWChar( 
    PWCHAR Dest, 
    PCHAR  Src, 
    SIZE_T MaxAllowed 
) -> SIZE_T {
    SIZE_T Length = MaxAllowed;
    while ( --Length > 0 ) {
        if ( !( *Dest++ = static_cast<WCHAR>( *Src++ ) ) ) {
            return MaxAllowed - Length - 1;
        }
    }
    return MaxAllowed - Length;
}

auto DECLFN LoadModule(
    _In_ const ULONG LibHash
) -> UPTR {
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }

        if ( HashStr<WCHAR>( Entry->BaseDllName.Buffer ) == LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
     } )
 
     return 0;
}
 
auto DECLFN LoadApi(
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

    // Check if export table exists
    if ( !ExpDir || !ExpDir->NumberOfNames ) {
        return 0;
    }

    for ( int i = 0; i < ExpDir->NumberOfNames; i++ ) {
        SymbName = reinterpret_cast<PSTR>( ModBase + ExpNames[ i ] );

        if ( HashStr( SymbName ) != SymbHash ) {
            continue;
        }

        FuncPtr = ModBase + ExpAddress[ ExpOrds[ i ] ];

        // Forwarded exports point to text within the export table section
        UPTR ExportSectionStart = ModBase + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
        UPTR ExportSectionEnd   = ExportSectionStart + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

        if ( FuncPtr >= ExportSectionStart && FuncPtr < ExportSectionEnd ) {
            PSTR ForwarderString = reinterpret_cast<PSTR>( FuncPtr );
            
            PSTR DotPos = ForwarderString;
            while ( *DotPos && *DotPos != '.' ) {
                DotPos++;
            }

            if ( *DotPos == '.' ) {
                // Get DLL name length
                SIZE_T DllNameLen = DotPos - ForwarderString;
                
                // Build the DLL filename
                CHAR DllName[256] = { 0 };
                for ( SIZE_T j = 0; j < DllNameLen && j < 250; j++ ) {
                    DllName[j] = ForwarderString[j];
                }
                
                if ( DllNameLen < 250 ) {
                    DllName[DllNameLen] = '\0';
                    PSTR LastDot = DllName + DllNameLen - 1;
                    while ( LastDot > DllName && *LastDot != '.' ) {
                        LastDot--;
                    }
                    if ( *LastDot != '.' ) {
                        if ( DllNameLen + 4 < 256 ) {
                            DllName[DllNameLen] = '.';
                            DllName[DllNameLen + 1] = 'd';
                            DllName[DllNameLen + 2] = 'l';
                            DllName[DllNameLen + 3] = 'l';
                            DllName[DllNameLen + 4] = '\0';
                        }
                    }
                }

                // Get the target function name
                PSTR TargetFuncName = DotPos + 1;
                
                // Load the forwarded DLL
                UPTR ForwardedModule = LoadModule( HashStr( DllName ) );
                if ( !ForwardedModule ) {
                    return FuncPtr;
                }

                UPTR TargetFuncHash = HashStr( TargetFuncName );
                FuncPtr = LoadApi( ForwardedModule, TargetFuncHash );
            }
        }

        break;
    }

    return FuncPtr;
}

auto DECLFN SectionSize(
    PVOID LibBase,
    UPTR  SecHash
) -> ULONG {
    IMAGE_NT_HEADERS*     Header = { 0 };
    IMAGE_SECTION_HEADER* SecHdr = { 0 };

    Header = (IMAGE_NT_HEADERS*)( (UPTR)( LibBase ) + ( (PIMAGE_DOS_HEADER)( LibBase ) )->e_lfanew );

    if ( Header->Signature != IMAGE_NT_SIGNATURE ) return 0;

    SecHdr = IMAGE_FIRST_SECTION( Header );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( HashStr( SecHdr[i].Name ) == SecHash ) {
            return SecHdr[i].SizeOfRawData;
        }
    }

    return 0;
} 

auto DECLFN Rnd32(
    VOID
) -> ULONG {
    UINT32 Seed = 0;

    _rdrand32_step( &Seed );
    
    return Seed;
}

auto DECLFN FindGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
) -> PVOID {
    PVOID   Gadget        = 0;
    PVOID  GadgetList[10] = { 0 };
    ULONG  GadgetCounter  = 0;
    ULONG  RndIndex       = 0;
    BYTE*  SearchBase     = nullptr;
    SIZE_T SearchSize     = 0;
    UINT16 JmpValue       = 0xff;

    SearchBase = ( (BYTE*)ModuleBase + 0x1000 );
    SearchSize = SectionSize( ModuleBase, HashStr<CHAR>(".text") );

    for ( INT i = 0; i < SearchSize - 1; i++ ) {
        if ( SearchBase[i] == JmpValue && SearchBase[i+1] == RegValue ) {
            GadgetList[GadgetCounter] = (PVOID)( (UPTR)( SearchBase ) + i ); GadgetCounter++;
            if ( GadgetCounter == 10 ) break;
        }
    }

    RndIndex = Rnd32() % GadgetCounter;
    Gadget   = GadgetList[RndIndex];

    return Gadget;
}
