#include <Kharon.h>

auto DECLFN Crypt::Cycle(
    PBYTE      Block,
    LOKY_CRYPT Mode
) -> VOID {
    UINT32 Left  = (UINT32(Block[0]) << 24) | (UINT32(Block[1]) << 16) | (UINT32(Block[2]) << 8) | UINT32(Block[3]);
    UINT32 Right = (UINT32(Block[4]) << 24) | (UINT32(Block[5]) << 16) | (UINT32(Block[6]) << 8) | UINT32(Block[7]);

    if (Mode == LokyEnc) {
        for (INT32 i = 0; i < NUM_ROUNDS; ++i) {
            UINT32 tmp = Right;
            Right = Left ^ (Right + UINT32(this->LokKey[i % sizeof(this->LokKey)]));
            Left = tmp;
        }
    } else {
        for (INT32 i = NUM_ROUNDS - 1; i >= 0; --i) {
            UINT32 tmp = Left;
            Left = Right ^ (Left + UINT32(this->LokKey[i % sizeof(this->LokKey)]));
            Right = tmp;
        }
    }

    Block[0] = (Left >> 24) & 0xFF;
    Block[1] = (Left >> 16) & 0xFF;
    Block[2] = (Left >> 8)  & 0xFF;
    Block[3] = Left & 0xFF;
    Block[4] = (Right >> 24) & 0xFF;
    Block[5] = (Right >> 16) & 0xFF;
    Block[6] = (Right >> 8)  & 0xFF;
    Block[7] = Right & 0xFF;
}

auto DECLFN Crypt::CalcPadding(
    ULONG Length
) -> ULONG {
    ULONG PadLen = (Length % BLOCK_SIZE == 0) ? BLOCK_SIZE : (BLOCK_SIZE - (Length % BLOCK_SIZE));
    return Length + PadLen;
}

auto DECLFN Crypt::AddPadding(
    PBYTE Block,
    ULONG Length,
    ULONG TotalSize
) -> VOID {
    UCHAR PadLen = (UCHAR)(TotalSize - Length);
    for (ULONG i = Length; i < TotalSize; ++i) {
        Block[i] = PadLen;
    }
}

auto DECLFN Crypt::Decrypt(
    PBYTE Block,
    ULONG &Length
) -> VOID {
    if (Length < BLOCK_SIZE) return;

    for (ULONG i = 0; i < Length; i += BLOCK_SIZE) {
        this->Cycle(Block + i, LokyDec);
    }

    this->RmPadding(Block, Length);
}

auto DECLFN Crypt::RmPadding(
    PBYTE Block,
    ULONG &Length
) -> VOID {
    if (Length < BLOCK_SIZE) return;

    UCHAR PadLen = Block[Length - 1];

    if (PadLen == 0 || PadLen > BLOCK_SIZE || Length < PadLen) return;

    for (ULONG i = Length - PadLen; i < Length; ++i) {
        if (Block[i] != PadLen) return;
    }

    Length -= PadLen;
}

auto DECLFN Crypt::Encrypt(
    PBYTE Block,
    ULONG Length
) -> VOID {
    ULONG TotalSize = this->CalcPadding(Length);
    this->AddPadding(Block, Length, TotalSize);

    for (ULONG i = 0; i < TotalSize; i += BLOCK_SIZE) {
        this->Cycle(Block + i, LokyEnc);
    }
}


auto DECLFN Crypt::Xor( 
    _In_opt_ BYTE*  Bin, 
    _In_     SIZE_T BinSize
) -> VOID {
    for ( SIZE_T i = 0x00, j = 0x00; i < BinSize; i++, j++ ) {
        if ( j == sizeof( this->XorKey ) )
            j = 0x00;

        if ( i % 2 == 0 )
            Bin[i] = Bin[i] ^ this->XorKey[j];
        else
            Bin[i] = Bin[i] ^ this->XorKey[j] ^ j;
    }
}
