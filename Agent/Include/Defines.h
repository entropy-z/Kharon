#ifndef DEFINES_H
#define DEFINES_H

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

/* ========= [ class macro ] ========= */

#define POST_EX_BUFFER_LENGTH 4 + 8 + 4 + 8 

#define RTL_CONSTANT_OBJECT_ATTRIBUTES ( x, y ) { sizeof(OBJECT_ATTRIBUTES), NULL, x, y, NULL, NULL }

#define G_SYM( x )	( ULONG_PTR )( StartPtr() - ( ( ULONG_PTR ) & StartPtr - ( ULONG_PTR ) x ) )

#define INT3BRK asm("int3");

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN( x ) ( ( (ULONG_PTR) x ) + ( ( PAGE_SIZE - ( ( (ULONG_PTR)x ) & ( PAGE_SIZE - 1 ) ) ) % PAGE_SIZE ) )

#ifdef DEBUG
#define KhDbg( x, ... ) { Self->Ntdll.DbgPrint( ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#define KhDbgz( x, ... ) { Ntdll.DbgPrint( ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#define KH_DBG_MSG KhDbg( "dbg" );
#else
#define KhDbgz( x, ... );
#define KhDbg( x, ... );
#define KH_DBG_MSG
#endif

#define DECLAPI( x )  decltype( x ) * x
#define DECLTYPE( x ) ( decltype( x ) )
#define DECLFN        __attribute__( ( section( ".text$B" ) ) )

#define G_PARSER          Self->Psr->Shared
#define G_PACKAGE         Self->Pkg->Global
#define BEG_BUFFER_LENGTH  0x1000
#define PIPE_BUFFER_LENGTH 0x10000

/*==============[ Dereference ]==============*/

#define C_DEFB( x )  ( * ( PBYTE )  ( x ) )
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

#endif // DEFINES_H