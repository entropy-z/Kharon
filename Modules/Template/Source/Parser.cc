#include <Kharon.h>

using namespace Root;

auto DECLFN Parser::New( 
    _In_ PPARSER parser, 
    _In_ PBYTE   Buffer
) -> VOID {
    if ( parser == NULL )
        return;

    INT32 Length = C_DEF32( Buffer );

    parser->Original = A_PTR( Kh->Ntdll.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length ) );
    Mem::Copy( C_PTR( parser->Original ), C_PTR( U_PTR( Buffer ) + sizeof( UINT32 ) ), Length );
    parser->Buffer   = parser->Original;
    parser->Length   = Length;
    parser->Size     = Length;
}

auto DECLFN Parser::GetInt32( 
    _In_ PPARSER parser 
) -> INT32 {
    INT32 intBytes = 0;

    if ( parser->Length < 4 )
        return 0;

    Mem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

auto DECLFN Parser::GetBytes( 
    _In_ PPARSER parser, 
    _In_ PULONG  size 
) -> PBYTE {
    UINT32  Length  = 0;
    PBYTE   outdata = NULL;

    if ( parser->Length < 4 )
        return NULL;

    Mem::Copy( C_PTR( &Length ), C_PTR( parser->Buffer ), 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = B_PTR( parser->Buffer );
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

auto DECLFN Parser::Destroy( 
    _In_ PPARSER Parser 
) -> BOOL {
    if ( Parser->Original ) {
        
        return Kh->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Parser->Original );
    }

    return FALSE;
}

auto DECLFN Parser::GetStr( 
    _In_ PPARSER parser, 
    _In_ PULONG size 
) -> PCHAR {
    return ( PCHAR ) Kh->Psr->GetBytes( parser, size );
}

auto DECLFN Parser::GetWstr( 
    _In_ PPARSER parser, 
    _In_ PULONG  size 
) -> PWCHAR {
    return ( PWCHAR ) Kh->Psr->GetBytes( parser, size );
}

auto DECLFN Parser::GetInt16( 
    _In_ PPARSER parser
) -> INT16 {
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    Mem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    return intBytes;
}

auto DECLFN Parser::GetInt64( 
    _In_ PPARSER parser 
) -> INT64 {
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    Mem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    if ( !parser->Endian )
        return ( INT64 ) intBytes;
    else
        return ( INT64 ) __builtin_bswap64( intBytes );
}

auto DECLFN Parser::GetByte( 
    _In_ PPARSER parser 
) -> BYTE {
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    Mem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}