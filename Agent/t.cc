#include <windows.h>

INT WINAPI WinMain(
    HINSTANCE h,
    HINSTANCE p,
    PCHAR     c,
    INT       s
) {
    UNREFERENCED_PARAMETER( h );
    UNREFERENCED_PARAMETER( p );
    UNREFERENCED_PARAMETER( c );
    UNREFERENCED_PARAMETER( s );

    INT ( *PrintLn )( PCHAR, ... ) = ( decltype( PrintLn ) )GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "DbgPrint" );

    PrintLn( "image file: %s", GetModuleHandleA( nullptr ) );

    return EXIT_SUCCESS;
}