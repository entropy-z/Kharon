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

// #define KhHeap Heap()
// #define KhThread Kharon::Thread

#define POST_EX_BUFFER_LENGTH 4 + 8 + 4 + 8 

#define INT3BRK asm("int3");

#ifdef DEBUG
#define KhDbg( x, ... ) { Kh->Ntdll.DbgPrint( ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#define KhDbgz( x, ... ) { Ntdll.DbgPrint( ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ ); }
#else
#define KhDbgz( x, ... );
#define KhDbg( x, ... );
#endif

#define DECLAPI( x )  decltype( x ) * x
#define DECLTYPE( x ) ( decltype( x ) )
#define DECLFN        __attribute__( ( section( ".text$B" ) ) )

#define BEG_BUFFER_LENGTH  0x1000
#define PIPE_BUFFER_LENGTH 0x10000

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

#endif // DEFINES_H