#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <windows.h>

#define ENCRYPTION_NONE 0x00
#define ENCRYPTION_XOR  0x01

#ifndef ENCRYPTION_TYPE
#define ENCRYPTION_TYPE ENCRYPTION_XOR
#endif

#ifndef XOR_KEY
#define XOR_KEY { 0 }
#endif

namespace Encryption {
    auto Decrypt( const UCHAR* Encrypted, INT EncryptedLen, UCHAR* Output ) -> INT;
}

#endif // ENCRYPTION_H