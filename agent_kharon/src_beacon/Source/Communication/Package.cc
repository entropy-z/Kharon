#include <Kharon.h>

using namespace Root;

auto DECLFN Package::Base64(
  _In_      const PVOID in,
  _In_      SIZE_T inlen,
  _Out_opt_ PVOID  out,
  _In_opt_  SIZE_T outlen,
  _In_      Base64Action Action 
) -> SIZE_T {
    static const INT Base64Invs[80] = { 
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
        59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51 
    };
    
    const char B64Char[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (in == NULL || inlen == 0)
        return 0;

    switch ( Action ) {
        case Base64Action::Get_Size: {
            SIZE_T padding = (inlen % 3) ? (3 - (inlen % 3)) : 0;
            
            if (inlen > (SIZE_MAX - padding) / 4 * 3)
                return 0;
            
            return ((inlen + padding) / 3) * 4;
        }

        case Base64Action::Encode: {
            if (out == NULL || outlen == 0)
                return 0;

            SIZE_T padding = (inlen % 3) ? (3 - (inlen % 3)) : 0;
            SIZE_T elen = ((inlen + padding) / 3) * 4;

            if (outlen < elen + 1)
                return 0;

            const unsigned char* in_buf = (const unsigned char*)in;
            char* out_buf = (char*)out;
            out_buf[elen] = '\0';

            SIZE_T i, j;
            for (i = 0, j = 0; i < inlen; i += 3, j += 4) {
                UINT32 v = in_buf[i];
                v = (i + 1 < inlen) ? (v << 8) | in_buf[i + 1] : v << 8;
                v = (i + 2 < inlen) ? (v << 8) | in_buf[i + 2] : v << 8;

                out_buf[j]     = B64Char[(v >> 18) & 0x3F];
                out_buf[j + 1] = B64Char[(v >> 12) & 0x3F];
                out_buf[j + 2] = (i + 1 < inlen) ? B64Char[(v >> 6) & 0x3F] : '=';
                out_buf[j + 3] = (i + 2 < inlen) ? B64Char[v & 0x3F] : '=';
            }

            return elen;
        }

        case Base64Action::Decode: {
            if (out == NULL)
                return 0;

            const char* in_buf = (const char*)in;
            unsigned char* out_buf = (unsigned char*)out;

            if (inlen % 4 != 0)
                return 0;

            SIZE_T required_size = (inlen / 4) * 3;
            for (SIZE_T k = inlen; k-- > 0;) {
                if (in_buf[k] == '=')
                    required_size--;
                else
                    break;
            }

            if (outlen < required_size)
                return 0;

            for (SIZE_T k = 0; k < inlen; k++) {
                char c = in_buf[k];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
                    return 0;
            }

            SIZE_T decoded = 0;
            for (SIZE_T i = 0; i < inlen; i += 4) {
                if ((in_buf[i] - 43) >= 80 || 
                    (in_buf[i + 1] - 43) >= 80 ||
                    (in_buf[i + 2] != '=' && (in_buf[i + 2] - 43) >= 80) ||
                    (in_buf[i + 3] != '=' && (in_buf[i + 3] - 43) >= 80)) {
                    return 0;
                }

                UINT32 v = Base64Invs[in_buf[i] - 43];
                v = (v << 6) | Base64Invs[in_buf[i + 1] - 43];
                v = (in_buf[i + 2] == '=') ? (v << 6) : (v << 6) | Base64Invs[in_buf[i + 2] - 43];
                v = (in_buf[i + 3] == '=') ? (v << 6) : (v << 6) | Base64Invs[in_buf[i + 3] - 43];

                out_buf[decoded++] = (v >> 16) & 0xFF;
                
                if (in_buf[i + 2] != '=')
                    out_buf[decoded++] = (v >> 8) & 0xFF;
                
                if (in_buf[i + 3] != '=')
                    out_buf[decoded++] = v & 0xFF;
            }

            return decoded;
        }

        default:
            return 0;
    }
}

// Base32 Encoding/Decoding (RFC 4648)
auto DECLFN Package::Base32(
    _In_      const PVOID in,
    _In_      SIZE_T inlen,
    _Out_opt_ PVOID  out,
    _In_opt_  SIZE_T outlen,
    _In_      Base32Action Action
) -> SIZE_T {
    static const char B32Char[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static const INT Base32Invs[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1
    };

    if (in == NULL || inlen == 0)
        return 0;

    switch (Action) {
        case Base32Action::Get_Size: {
            SIZE_T elen = ((inlen + 4) / 5) * 8;
            return elen;
        }

        case Base32Action::Encode: {
            if (out == NULL || outlen == 0)
                return 0;

            SIZE_T elen = ((inlen + 4) / 5) * 8;
            if (outlen < elen)
                return 0;

            const unsigned char* in_buf = (const unsigned char*)in;
            char* out_buf = (char*)out;

            SIZE_T i, j;
            for (i = 0, j = 0; i < inlen; i += 5, j += 8) {
                UINT64 v = 0;
                
                if (i + 0 < inlen) v |= ((UINT64)in_buf[i + 0] << 32);
                if (i + 1 < inlen) v |= ((UINT64)in_buf[i + 1] << 24);
                if (i + 2 < inlen) v |= ((UINT64)in_buf[i + 2] << 16);
                if (i + 3 < inlen) v |= ((UINT64)in_buf[i + 3] << 8);
                if (i + 4 < inlen) v |= ((UINT64)in_buf[i + 4] << 0);

                out_buf[j + 0] = B32Char[(v >> 35) & 0x1F];
                out_buf[j + 1] = B32Char[(v >> 30) & 0x1F];
                out_buf[j + 2] = (i + 1 < inlen) ? B32Char[(v >> 25) & 0x1F] : '=';
                out_buf[j + 3] = (i + 1 < inlen) ? B32Char[(v >> 20) & 0x1F] : '=';
                out_buf[j + 4] = (i + 2 < inlen) ? B32Char[(v >> 15) & 0x1F] : '=';
                out_buf[j + 5] = (i + 3 < inlen) ? B32Char[(v >> 10) & 0x1F] : '=';
                out_buf[j + 6] = (i + 3 < inlen) ? B32Char[(v >> 5) & 0x1F] : '=';
                out_buf[j + 7] = (i + 4 < inlen) ? B32Char[v & 0x1F] : '=';
            }

            return elen;
        }

        case Base32Action::Decode: {
            if (out == NULL || outlen == 0)
                return 0;

            const char* in_buf = (const char*)in;
            unsigned char* out_buf = (unsigned char*)out;

            if (inlen % 8 != 0)
                return 0;

            SIZE_T required_size = (inlen / 8) * 5;
            for (SIZE_T k = inlen; k-- > 0;) {
                if (in_buf[k] == '=')
                    required_size--;
                else
                    break;
            }

            if (outlen < required_size)
                return 0;

            SIZE_T decoded = 0;
            for (SIZE_T i = 0; i < inlen; i += 8) {
                UINT64 v = 0;

                for (INT k = 0; k < 8; k++) {
                    if (in_buf[i + k] == '=')
                        v = (v << 5);
                    else if (in_buf[i + k] < 128 && Base32Invs[(unsigned char)in_buf[i + k]] >= 0)
                        v = (v << 5) | Base32Invs[(unsigned char)in_buf[i + k]];
                    else
                        return 0;
                }

                out_buf[decoded++] = (v >> 32) & 0xFF;
                if (in_buf[i + 2] != '=')
                    out_buf[decoded++] = (v >> 24) & 0xFF;
                if (in_buf[i + 4] != '=')
                    out_buf[decoded++] = (v >> 16) & 0xFF;
                if (in_buf[i + 5] != '=')
                    out_buf[decoded++] = (v >> 8) & 0xFF;
                if (in_buf[i + 7] != '=')
                    out_buf[decoded++] = v & 0xFF;
            }

            return decoded;
        }

        default:
            return 0;
    }
}

// Base64URL Encoding/Decoding (RFC 4648)
auto DECLFN Package::Base64URL(
    _In_      const PVOID in,
    _In_      SIZE_T inlen,
    _Out_opt_ PVOID  out,
    _In_opt_  SIZE_T outlen,
    _In_      Base64URLAction Action
) -> SIZE_T {
    static const char B64URLChar[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    if (in == NULL || inlen == 0) {
        return 0;
    }

    switch (Action) {
        case Base64URLAction::Get_Size: {
            SIZE_T size_with_padding = ((inlen + 2) / 3) * 4;
            SIZE_T padding_count = (3 - (inlen % 3)) % 3;
            SIZE_T actual_size = size_with_padding - padding_count;
            
            return actual_size;
        }

        case Base64URLAction::Encode: {
            if (out == NULL || outlen == 0) {
                return 0;
            }

            SIZE_T size_with_padding = ((inlen + 2) / 3) * 4;
            SIZE_T padding_count = (3 - (inlen % 3)) % 3;
            SIZE_T actual_size = size_with_padding - padding_count;

            if (outlen < actual_size) {
                return 0;
            }

            const unsigned char* in_buf = (const unsigned char*)in;
            char* out_buf = (char*)out;

            SIZE_T out_idx = 0;
            SIZE_T i = 0;
                        
            for (i = 0; i + 3 <= inlen; i += 3) {
                UINT32 v = (in_buf[i] << 16) | (in_buf[i + 1] << 8) | in_buf[i + 2];
                
                out_buf[out_idx++] = B64URLChar[(v >> 18) & 0x3F];
                out_buf[out_idx++] = B64URLChar[(v >> 12) & 0x3F];
                out_buf[out_idx++] = B64URLChar[(v >> 6) & 0x3F];
                out_buf[out_idx++] = B64URLChar[v & 0x3F];
            }
                        
            if (i < inlen) {
                SIZE_T remaining = inlen - i;
                UINT32 v = 0;
                
                if (remaining == 1) {
                    v = in_buf[i] << 16;
                    out_buf[out_idx++] = B64URLChar[(v >> 18) & 0x3F];
                    out_buf[out_idx++] = B64URLChar[(v >> 12) & 0x3F];
                } else if (remaining == 2) {
                    v = (in_buf[i] << 16) | (in_buf[i + 1] << 8);
                    out_buf[out_idx++] = B64URLChar[(v >> 18) & 0x3F];
                    out_buf[out_idx++] = B64URLChar[(v >> 12) & 0x3F];
                    out_buf[out_idx++] = B64URLChar[(v >> 6) & 0x3F];
                }
            }

            return out_idx;
        }

        case Base64URLAction::Decode: {
            if (out == NULL || outlen == 0) {
                return 0;
            }

            const char* in_buf = (const char*)in;
            unsigned char* out_buf = (unsigned char*)out;

            SIZE_T remainder = inlen % 4;
            
            if (remainder == 1) {
                return 0;
            }

            SIZE_T groups = inlen / 4;
            SIZE_T required_size = groups * 3;
            
            if (remainder == 2) required_size += 1;
            else if (remainder == 3) required_size += 2;
            
            if (outlen < required_size) {
                return 0;
            }

            auto CharToVal = [&](unsigned char c, bool& valid) -> UINT32 {
                valid = true;
                if (c >= 'A' && c <= 'Z') return c - 'A';           // A-Z = 0-25
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;      // a-z = 26-51
                if (c >= '0' && c <= '9') return c - '0' + 52;      // 0-9 = 52-61
                if (c == '-') return 62;                            // - = 62 (Base64URL)
                if (c == '_') return 63;                            // _ = 63 (Base64URL)
                valid = false;
                KhDbg("Base64URL::Decode - Invalid character: %c (0x%02X)", c, c);
                return 0;
            };

            SIZE_T decoded = 0;
            SIZE_T i = 0;
            bool valid = true;
            
            for (i = 0; i + 4 <= inlen; i += 4) {
                UINT32 v = 0;
                UINT32 v0, v1, v2, v3;
                
                v0 = CharToVal(in_buf[i], valid);
                if (!valid) return 0;
                
                v1 = CharToVal(in_buf[i + 1], valid);
                if (!valid) return 0;
                
                v2 = CharToVal(in_buf[i + 2], valid);
                if (!valid) return 0;
                
                v3 = CharToVal(in_buf[i + 3], valid);
                if (!valid) return 0;
                
                v = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

                out_buf[decoded++] = (v >> 16) & 0xFF;
                out_buf[decoded++] = (v >> 8) & 0xFF;
                out_buf[decoded++] = v & 0xFF;
            }

            KhDbg("Base64URL::Decode - Processed full groups - Output so far: %zu", decoded);

            if (i < inlen) {
                SIZE_T chars_left = inlen - i;
                UINT32 v = 0;
                UINT32 v0, v1, v2;
                
                if (chars_left >= 2) {
                    v0 = CharToVal(in_buf[i], valid);
                    if (!valid) return 0;
                    
                    v1 = CharToVal(in_buf[i + 1], valid);
                    if (!valid) return 0;
                    
                    v = (v0 << 18) | (v1 << 12);
                    
                    if (chars_left >= 3) {
                        v2 = CharToVal(in_buf[i + 2], valid);
                        if (!valid) return 0;
                        
                        v |= (v2 << 6);
                    }
                    
                    out_buf[decoded++] = (v >> 16) & 0xFF;
                    
                    if (chars_left >= 3) {
                        out_buf[decoded++] = (v >> 8) & 0xFF;
                    }
                }
            }

            return decoded;
        }

        default: {
            return 0;
        }
    }
}

// Hex Encoding/Decoding
auto DECLFN Package::Hex(
    _In_      const PVOID in,
    _In_      SIZE_T inlen,
    _Out_opt_ PVOID  out,
    _In_opt_  SIZE_T outlen,
    _In_      HexAction Action
) -> SIZE_T {
    static const char HexChar[17] = "0123456789ABCDEF";

    if (in == NULL || inlen == 0)
        return 0;

    switch (Action) {
        case HexAction::Get_Size: {
            return inlen * 2;
        }
        
        case HexAction::Encode: {
            if (out == NULL || outlen == 0)
                return 0;

            SIZE_T hlen = inlen * 2;
            if (outlen < hlen)
                return 0;

            const unsigned char* in_buf = (const unsigned char*)in;
            char* out_buf = (char*)out;

            for (SIZE_T i = 0; i < inlen; i++) {
                out_buf[i * 2]     = HexChar[(in_buf[i] >> 4) & 0x0F];
                out_buf[i * 2 + 1] = HexChar[in_buf[i] & 0x0F];
            }

            return hlen;
        }

        case HexAction::Decode: {
            if (out == NULL || outlen == 0)
                return 0;

            if (inlen % 2 != 0)
                return 0;

            SIZE_T required_size = inlen / 2;
            if (outlen < required_size)
                return 0;

            const char* in_buf = (const char*)in;
            unsigned char* out_buf = (unsigned char*)out;

            for (SIZE_T i = 0; i < inlen; i += 2) {
                unsigned char high = 0, low = 0;

                // Parse high nibble
                if (in_buf[i] >= '0' && in_buf[i] <= '9')
                    high = in_buf[i] - '0';
                else if (in_buf[i] >= 'A' && in_buf[i] <= 'F')
                    high = in_buf[i] - 'A' + 10;
                else if (in_buf[i] >= 'a' && in_buf[i] <= 'f')
                    high = in_buf[i] - 'a' + 10;
                else
                    return 0;

                // Parse low nibble
                if (in_buf[i + 1] >= '0' && in_buf[i + 1] <= '9')
                    low = in_buf[i + 1] - '0';
                else if (in_buf[i + 1] >= 'A' && in_buf[i + 1] <= 'F')
                    low = in_buf[i + 1] - 'A' + 10;
                else if (in_buf[i + 1] >= 'a' && in_buf[i + 1] <= 'f')
                    low = in_buf[i + 1] - 'a' + 10;
                else
                    return 0;

                out_buf[i / 2] = (high << 4) | low;
            }

            return required_size;
        }

        default:
            return 0;
    }
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
    Package->Buffer = PTR( KhReAlloc( Package->Buffer, Package->Length + sizeof( INT16 ) ) );

    Int16ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT16 );
}

auto DECLFN Package::Int32( 
    _In_ PPACKAGE Package, 
    _In_ INT32    dataInt 
) -> VOID {
    Package->Buffer = PTR( KhReAlloc( Package->Buffer, Package->Length + sizeof( INT32 ) ) );

    Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( INT32 );
}

auto DECLFN Package::Int64( 
    _In_ PPACKAGE Package, 
    _In_ INT64    dataInt 
) -> VOID {
    Package->Buffer = PTR( KhReAlloc(
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

    Package         = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );
    Package->Buffer = KhAlloc( sizeof( BYTE ) );
    Package->Length = 0;

    this->Bytes( Package, UC_PTR( UUID ), 36 );
    this->Int16( Package, CommandID );

    Package->TaskUUID = UUID;

    return Package;
}

auto DECLFN Package::Checkin( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PPACKAGE)KhAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = KhAlloc( sizeof( BYTE ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, (BYTE)Action::Task::Checkin );

    return Package;
}

auto DECLFN Package::PostJobs( VOID ) -> PACKAGE* {
    PACKAGE* Package = NULL;

    Package          = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( KhAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, (BYTE)Action::Task::PostTask );

    return Package;
}

auto DECLFN Package::NewTask( 
    VOID
) -> PPACKAGE {
    PPACKAGE Package = NULL;

    Package          = (PPACKAGE)KhAlloc( sizeof( PACKAGE ) );
    Package->Buffer  = PTR( KhAlloc( sizeof( BYTE ) ) );
    Package->Length  = 0;
    Package->Encrypt = FALSE;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, (BYTE)Action::Task::GetTask );

    return Package;
}

auto DECLFN Package::Destroy( 
    _In_ PPACKAGE Package 
) -> VOID {
    if ( ! Package ) return;

    if ( Package->Buffer ) {
        KhFree( Package->Buffer );
        Package->Buffer = nullptr;
        Package->Length = 0;
    }

    if ( Package ) {
        KhFree( Package );
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
    PVOID  RetBuffer     = nullptr;
    UINT64 Retsize       = 0;

    ULONG EncryptOffset  = 36; // agent_id size
    ULONG PlainLen       = Package->Length - EncryptOffset;
    ULONG PaddedLen      = Self->Crp->CalcPadding( PlainLen );
    ULONG TotalPacketLen = EncryptOffset + PaddedLen;

    MM_INFO SendData = { 0 };
    MM_INFO RecvData = { 0 };

    Package->Buffer = KhReAlloc( Package->Buffer, TotalPacketLen );
    Package->Length = TotalPacketLen;

    // prepare for pack encrypted buffer
    PBYTE EncBuffer = (PBYTE)Self->Mm->Alloc( nullptr, TotalPacketLen, MEM_COMMIT, PAGE_READWRITE );
    if ( ! EncBuffer ) return FALSE;

    Mem::Copy( EncBuffer, Package->Buffer, EncryptOffset );
    Mem::Copy( EncBuffer + EncryptOffset, B_PTR( Package->Buffer ) + EncryptOffset, PlainLen );

    // encrypt it
    Self->Crp->AddPadding( EncBuffer + EncryptOffset, PlainLen, PaddedLen );
    Self->Crp->Encrypt( EncBuffer + EncryptOffset, PaddedLen );

    // if not connected, send the encryption key into 16 final bytes
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

    SendData.Ptr  = (PBYTE)EncBuffer;
    SendData.Size = TotalPacketLen;

    if ( Self->Tsp->Send( &SendData, &RecvData ) ) {
        Success = TRUE;
    }

    Self->Mm->Free( EncBuffer, TotalPacketLen, MEM_RELEASE );
    
    if ( Success && RecvData.Ptr && RecvData.Size ) {
        UCHAR* DecryptBuff   = RecvData.Ptr + EncryptOffset;
        ULONG  DecryptLength = (ULONG)RecvData.Size - EncryptOffset;

        if ( DecryptLength == 0 ) { 
            KhDbg("Invalid decrypt length: %lu", DecryptLength);
            if ( RecvData.Ptr ) KhFree( RecvData.Ptr );
            return FALSE;
        }

        Self->Crp->Decrypt( DecryptBuff, DecryptLength );
         
        *Response = RecvData.Ptr;
        *Size     = RecvData.Size;
        
        Success = TRUE;
    } else if ( RecvData.Ptr ) {        
        KhFree( RecvData.Ptr );
        Success = FALSE;
    }

    return Success;
}

auto DECLFN Package::Byte( 
    _In_ PPACKAGE Package, 
    _In_ BYTE     dataInt 
) -> VOID {
    Package->Buffer = KhReAlloc( Package->Buffer, Package->Length + sizeof( BYTE ) );
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
    Package->Buffer = A_PTR( KhReAlloc(
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

    Package->Buffer = PTR( KhReAlloc( Package->Buffer, Package->Length + Size ) );

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
    PACKAGE* Package = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( KhAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, UC_PTR( Self->Session.AgentID ), 36 );
    this->Byte( Package, (BYTE)Action::Task::QuickOut );

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
    
    PACKAGE* Package = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );

    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, Message, VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "failed get the formated message size" ); goto _KH_END;
    }

    MsgBuff = (CHAR*)KhAlloc( MsgSize +1 );

    if ( Self->Msvcrt.vsnprintf( MsgBuff, MsgSize, Message, VaList ) < 0 ) {
        KhDbg( "failed formating string" ); goto _KH_END;
    }

    Package->Buffer = PTR( KhAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, (BYTE)Action::Task::QuickMsg );

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
    if ( MsgBuff ) KhFree( MsgBuff );

    return result;   
}

auto DECLFN Package::SendMsgA(
    _In_ ULONG Type,
    _In_ CHAR* Message
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( KhAlloc( sizeof( BYTE ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, (BYTE)Action::Task::QuickMsg );

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

auto DECLFN Package::SendMsgW(
    _In_ ULONG  Type,
    _In_ WCHAR* Message
) -> BOOL {
    PACKAGE* Package = (PACKAGE*)KhAlloc( sizeof( PACKAGE ) );

    Package->Buffer = PTR( KhAlloc( sizeof( WCHAR ) ) );
    Package->Length = 0;

    this->Pad( Package, (PUCHAR)Self->Session.AgentID, 36 );
    this->Byte( Package, (BYTE)Action::Task::QuickMsg );

    if ( PROFILE_C2 == PROFILE_SMB ) {
        // this->Pad( Package, (PUCHAR)SmbUUID, 36 );
    }

    this->Pad( Package, (UCHAR*)Self->Jbs->CurrentUUID, 36 );
    this->Int32( Package, Type );
    this->Wstr( Package, Message );

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

    parser->Original = A_PTR( KhAlloc( size ) );
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

    parser->Original = A_PTR( KhAlloc( size ) );
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

    if ( parser->Length < 4 )
        return 0;

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
        if ( Self->Hp->CheckPtr( Parser->Original ) ) {
            Success = KhFree( Parser->Original );
        }
        Parser->Original = nullptr;
        Parser->Length   = 0;
    }

    if ( Parser ) {
        if ( Self->Hp->CheckPtr( Parser ) ) { 
            Success = KhFree( Parser );
        }

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