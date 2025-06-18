#include <Kharon.h>

#define BLOCK_SIZE 8
#define NUM_ROUNDS 16

auto DECLFN Crypt::Cycle( 
    BYTE* Block, 
    LOKY_CRYPT Loky 
) -> VOID {
    UINT32 Left  = ( (UINT32)Block[0] << 24 ) | ( (UINT32)Block[1] << 16 ) | ( (UINT32)Block[2] << 8 ) | (UINT32)Block[3];
    UINT32 Right = ( (UINT32)Block[4] << 24 ) | ( (UINT32)Block[5] << 16 ) | ( (UINT32)Block[6] << 8 ) | (UINT32)Block[7];

    if ( Loky == LokyEnc ) {
        for ( INT32 Round = 0; Round < NUM_ROUNDS; Round++ ) {
            UINT32 Temp = Right;
            Right = Left ^ ( Right + ( (UINT32)this->LokKey[Round % sizeof(this->LokKey)] ) );
            Left  = Temp;
        }
    }
    else if ( Loky == LokyDec ) {
        for ( INT32 Round = NUM_ROUNDS - 1; Round >= 0; Round-- ) {
            UINT32 Temp  = Left;
            Left  = Right ^ ( Left + ( (UINT32)this->LokKey[Round % sizeof(this->LokKey)] ) );
            Right = Temp;
        }
    }

    Block[0] = ( ( Left >> 24 ) & 0xFF );
    Block[1] = ( ( Left >> 16 ) & 0xFF );
    Block[2] = ( ( Left >>  8 ) & 0xFF );
    Block[3] = ( Left & 0xFF);
    Block[4] = ( ( Right >> 24 ) & 0xFF );
    Block[5] = ( ( Right >> 16 ) & 0xFF );
    Block[6] = ( ( Right >>  8 ) & 0xFF );
    Block[7] = ( Right & 0xFF );
}

auto DECLFN Crypt::AddPadding( 
    UCHAR** Block, 
    ULONG* Length 
) -> VOID {
    ULONG PadLen = (*Length % BLOCK_SIZE) == 0 ? BLOCK_SIZE : (BLOCK_SIZE - (*Length % BLOCK_SIZE));
        
    UCHAR* newBlock = (UCHAR*)Self->Hp->ReAlloc(*Block - 36, *Length + 36 + PadLen);
    if (!newBlock) {
        return;
    }
    
    *Block = newBlock + 36;
    
    for (ULONG i = *Length; i < *Length + PadLen; i++) {
        (*Block)[i] = (UCHAR)PadLen;
    }
    
    *Length += PadLen;
}

auto DECLFN Crypt::Decrypt(
    UCHAR* Block, 
    ULONG* Length 
) -> VOID {
    if (*Length < BLOCK_SIZE) {
        return;
    }

    ULONG blocks_to_process = (*Length / BLOCK_SIZE) * BLOCK_SIZE;
    
    for (ULONG i = 0; i < blocks_to_process; i += BLOCK_SIZE) {
        this->Cycle(Block + i, LokyDec);
    }

    if (blocks_to_process > 0) {
        this->RmPadding(Block, &blocks_to_process);
        *Length = blocks_to_process;
        return;
    }
    
    return;
}

auto DECLFN Crypt::RmPadding(
    UCHAR* Block, 
    ULONG* Length 
) -> VOID {
    if (*Length < BLOCK_SIZE) return;

    UCHAR PadLen = Block[*Length - 1];
    
    if (PadLen == 0 || PadLen > BLOCK_SIZE || *Length < PadLen) {
        return;
    }

    for (ULONG i = *Length - PadLen; i < *Length; i++) {
        if (Block[i] != PadLen) {
            return;
        }
    }

    *Length -= PadLen;
}

auto DECLFN Crypt::Encrypt( 
    UCHAR** Block, 
    ULONG*  Length 
) -> VOID {
    this->AddPadding( Block, Length );
    
    for ( ULONG i = 0; i < *Length; i += BLOCK_SIZE ) {
        this->Cycle( *Block + i, LokyEnc );
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
