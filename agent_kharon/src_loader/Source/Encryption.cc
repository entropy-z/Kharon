#include <Kharon.h>

#if ENCRYPTION_TYPE == ENCRYPTION_XOR

static UCHAR Key[] = XOR_KEY;

static INT XorDecrypt(
    const UCHAR   *Encrypted,
    INT           EncryptedLen,
    const UCHAR   *Key,
    INT           KeyLen,
    UCHAR         *Output
) {
    if (!Encrypted || !Key || !Output || EncryptedLen <= 0 || KeyLen <= 0)
        return -1;

    for (INT i = 0; i < EncryptedLen; i++)
        Output[i] = Encrypted[i] ^ Key[i % KeyLen];

    return EncryptedLen;
}

auto Encryption::Decrypt( const UCHAR* Encrypted, INT EncryptedLen, UCHAR* Output ) -> INT {
    return XorDecrypt(Encrypted, EncryptedLen, Key, sizeof(Key), Output);
}

#elif ENCRYPTION_TYPE == ENCRYPTION_NONE

auto Encryption::Decrypt( const UCHAR* Encrypted, INT EncryptedLen, UCHAR* Output ) -> INT {
    if (!Encrypted || !Output || EncryptedLen <= 0)
        return -1;

    for (INT i = 0; i < EncryptedLen; i++)
        Output[i] = Encrypted[i];

    return EncryptedLen;
}

#endif