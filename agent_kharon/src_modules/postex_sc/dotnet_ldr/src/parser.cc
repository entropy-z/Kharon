#include <general.h>

    /*
        {header}
        [4 bytes] = module id
        [2 bytes] = execution method (inline:0x00 / explicit:0x100 / spawn:0x200)
        [1 bytes] = stack spoof status (enabled: 0x01 / disabled: 0x00)
        [1 bytes] = amsi/etw bypass (amsi: 0x01 / etw: 0x02 / all: 0x03 / disabled: 0x00)
        [4 bytes [buffer]] =  pipe name len + pipe buffer (WCHAR*)
        [4 bytes [buffer]] = argument to shellcode
    */

auto declfn parser::header( 
    _In_  PVOID       buff,
    _Out_ POSTEX_CTX* postex
) -> VOID {
    g_instance

    if ( buff == nullptr ) {
        return;
    }

    PBYTE bufferptr = (PBYTE)buff;

    postex->id = *(ULONG*)bufferptr;
    bufferptr += sizeof(ULONG);
    
    postex->execmethod = *(INT16*)bufferptr;
    bufferptr += sizeof(INT16);

    postex->spoof = *(INT8*)bufferptr; 
    bufferptr += sizeof(INT8);

    postex->bypassflag = *(INT8*)bufferptr;
    bufferptr += sizeof(INT8);

    postex->pipename_len = *(ULONG*)bufferptr;
    bufferptr += sizeof(ULONG);
    
    postex->pipename = (CHAR*)bufferptr;
    bufferptr += postex->pipename_len;

    postex->argc = *(ULONG*)bufferptr;
    bufferptr += sizeof(ULONG);

    postex->args = bufferptr;
}

auto declfn parser::create(
    _In_ PARSER* parser,
    _In_ PBYTE   args,
    _In_ ULONG   argc
) -> VOID {
    g_instance

    argc = *(ULONG*)(args);
    args = (PBYTE)(args + 4);

    parser->Original = (PCHAR)mm::alloc( argc );
    mm::copy( parser->Original, args, argc );
    
    parser->Buffer = parser->Original;
    parser->Length = argc;
    parser->Size   = argc;
}

auto declfn parser::pad(
    _In_  PARSER* parser,
    _Out_ ULONG   size
) -> PBYTE {
    if ( ! parser )
        return nullptr;

    if ( parser->Length < size )
        return nullptr;

    PBYTE paddata = (PBYTE)(parser->Buffer);

    parser->Buffer += size;
    parser->Length -= size;

    return paddata;
}

auto declfn parser::int32( 
    _In_ PARSER* parser 
) -> INT32 {
    g_instance

    INT32 intbytes = 0;

    mm::copy( &intbytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;
   
    return ( INT )( intbytes );
}

auto declfn parser::bytes( 
    _In_ PARSER* parser, 
    _In_ ULONG*  size 
) -> PBYTE {
    g_instance

    UINT32 length  = 0;
    PBYTE  outdata = nullptr;

    if ( parser->Length < 4 || !parser->Buffer )
        return nullptr;

    mm::copy( &length, parser->Buffer, 4 );
    parser->Buffer += 4;

    length = ( length );

    outdata = (BYTE*)( parser->Buffer );
    if ( outdata == nullptr )
        return nullptr;

    parser->Length -= 4;
    parser->Length -= length;
    parser->Buffer += length;

    if ( size != nullptr ) *size = length;

    return outdata;
}

auto declfn parser::destroy( 
    _In_ PARSER* parser 
) -> BOOL {
    if ( ! parser ) return FALSE;

    if ( parser->Original ) {
        mm::zero( parser->Original, parser->Size );
        mm::free( parser->Original );
        parser->Original = nullptr;
    }

    mm::zero( parser, sizeof( PARSER ) );

    return TRUE;
}

auto declfn parser::str( 
    _In_  PARSER* parser, 
    _Out_ ULONG*  size 
) -> PCHAR {
    return ( PCHAR ) parser::bytes( parser, size );
}

auto declfn parser::wstr( 
    _In_  PARSER* parser, 
    _Out_ ULONG*  size 
) -> PWCHAR {
     return ( PWCHAR )parser::bytes( parser, size );
}
auto declfn parser::int16( 
    _In_ PARSER* parser
) -> INT16 {
    INT16 intbytes = 0;

    if ( parser->Length < 2 )
        return 0;

    mm::copy( &intbytes, parser->Buffer, 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

   
    return ( intbytes ) ;
}

auto declfn parser::int64( 
    _In_ PARSER* parser 
) -> INT64 {
    INT64 intbytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    mm::copy( &intbytes, parser->Buffer, 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

 
    return ( INT64 )( intbytes );
}

auto declfn parser::byte( 
    _In_ PARSER* parser 
) -> BYTE {
    BYTE intbytes = 0;

    if ( parser->Length < 1 )
        return 0;

    mm::copy( &intbytes, parser->Buffer, 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intbytes;
}