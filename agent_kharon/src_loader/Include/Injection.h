#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

#define INJECTION_TECHNIQUE_CLASSIC 0x10
#define INJECTION_TECHNIQUE_STOMPER 0x20

#ifndef INJECTION_TECHNIQUE
#define INJECTION_TECHNIQUE INJECTION_TECHNIQUE_CLASSIC
#endif // INJECTION_TECHNIQUE


#define SHELLCODE_SECTION_OTHER 0x01
#define SHELLCODE_SECTION_RSRC 0x02

#ifndef SHELLCODE_SECTION_LOCATION
#define SHELLCODE_SECTION_LOCATION SHELLCODE_SECTION_RSRC
#endif

namespace Injection {
    auto Main( uint8_t * , size_t ) -> VOID;
    auto Classic( VOID ) -> VOID;
    auto Stomper( uint8_t * , size_t ) -> VOID;
}

#endif // INJECTION_H