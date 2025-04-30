#include <Kharon.h>

auto DECLFN HwbpEng::SetDr7(
    _In_ UPTR ActVal,
    _In_ UPTR NewVal,
    _In_ INT  StartPos,
    _In_ INT  BitsCount
) -> UPTR {
    UPTR Mask  = ( 1UL << BitsCount ) - 1UL;
    return ( ActVal & ~( Mask << StartPos ) ) | ( NewVal << StartPos );
}

auto DECLFN HwbpEng::Install(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback,
    _In_ ULONG ThreadID
) -> BOOL {
    PDESCRIPTOR_HOOK NewEntry = nullptr;

    NewEntry = (PDESCRIPTOR_HOOK)Self->Hp->Alloc( sizeof( DESCRIPTOR_HOOK ) );

    Self->Krnl32.EnterCriticalSection( &CritSec );

    NewEntry->Drx           = Drx;
    NewEntry->ThreadID      = ThreadID;
    NewEntry->Address = Address;
    NewEntry->Detour  = ( decltype(NewEntry->Detour) )Callback;

    if ( !Threads ) {
        Threads = NewEntry;
    } else {
        PDESCRIPTOR_HOOK Current = Threads;
        while ( Current->Next ) {
            Current = Current->Next;
        }
        Current->Next  = NewEntry;
        NewEntry->Prev = Current;
    }

    Self->Krnl32.LeaveCriticalSection( &CritSec );

    return Self->Hwbp->Insert( Address, Drx, TRUE, ThreadID );
}

auto DECLFN HwbpEng::SetBreak(
    _In_ ULONG ThreadID,
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ BOOL  Init
) -> BOOL {
    CONTEXT Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    ULONG   Code   = STATUS_UNSUCCESSFUL;
    HANDLE  Handle = INVALID_HANDLE_VALUE;

    if ( ThreadID != Self->Session.ThreadID ) {
        Handle = Self->Td->Open( THREAD_ALL_ACCESS, FALSE, ThreadID );
    } else {
        Handle = NtCurrentThread();
    }

    Code = Self->Ntdll.NtGetContextThread( Handle, &Ctx );

    if ( Initialized ) {
        ( &Ctx.Dr0 )[Drx] = Address;
        Ctx.Dr7 = SetDr7( Ctx.Dr7, ( Drx * 2 ), 1, 1 );
    } else {
        if ( ( &Ctx.Dr0 )[Drx] == Address ) {
            ( &Ctx.Dr0 )[Drx] = 0ull;
            Ctx.Dr7 = SetDr7( Ctx.Dr7, ( Drx * 2 ), 1, 0 );
        }
    }

    Code = Self->Ntdll.NtSetContextThread( Handle, &Ctx );

    if ( Handle && Handle != NtCurrentThread() ) {
        Self->Ntdll.NtClose( Handle );
    }

    return Code;
}

auto DECLFN HwbpEng::RmBreak(
    _In_ UPTR  Address,
    _In_ ULONG ThreadID
) -> BOOL {
    PDESCRIPTOR_HOOK Current = Threads;

    Self->Krnl32.EnterCriticalSection( &CritSec );

    ULONG   Flag  = 0;
    INT8    Drx   = -1;
    BOOL    Found = FALSE;

    while ( Current ) {
        if ( Current->Address == Address && Current->ThreadID == ThreadID ) {
            Found = TRUE;

            Drx = Current->Drx;

            if ( Current == Threads ) {
                Threads = Current->Next;
            }

            if ( Current->Next ) {
                Current->Next->Prev = Current->Prev;
            }

            if ( Current->Prev ) {
                Current->Prev->Next = Current->Next;
            }

            if ( Current ) {
                Self->Hp->Free( Current, sizeof( DESCRIPTOR_HOOK) );
            }
        }

        if ( Current ) {
            Current = Current->Next;
        }
    }

    Self->Krnl32.LeaveCriticalSection( &CritSec );

    if ( Found ) {
        Flag = Insert( Address, Drx, FALSE, ThreadID );
    }

    return Flag;
}

auto DECLFN HwbpEng::GetArg(
    _In_ PCONTEXT Ctx,
    _In_ ULONG    Idx
) -> UPTR {
#ifdef _WIN64
    switch ( Idx ) {
        case 1: {
            return Ctx->Rcx;
        }
        case 2: {
            return Ctx->Rdx;
        }
        case 3: {
            return Ctx->R8;
        }
        case 4: {
            return Ctx->R9;
        }
    }

    return C_DEF64( Ctx->Rsp + ( Idx * sizeof( PVOID ) ) );
#else
    return C_DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) );
#endif
}

auto DECLFN HwbpEng::SetArg(
    _In_ PCONTEXT Ctx,
    _In_ UPTR     Val,
    _In_ ULONG    Idx
) -> VOID {
#ifdef _WIN64
switch ( Idx ) {
    case 1: {
        Ctx->Rcx = Val; return;
    }
    case 2: {
        Ctx->Rdx = Val; return;
    }
    case 3: {
        Ctx->R8 = Val; return;
    }
    case 4: {
        Ctx->R9 = Val; return;
    }
}
    C_DEF64( Ctx->Rsp + ( Idx * sizeof( PVOID ) ) ) = Val;
#else
    C_DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) ) = Val;
#endif
}

auto DECLFN HwbpEng::BlockReal(
    _In_ PCONTEXT Ctx
) -> VOID {
    const unsigned char Ret = { 0xC3 };
#ifdef _WIN64
    Ctx->Rip = (UPTR)&Ret;
#else
    Ctx->Eip = (UPTR)&Ret;
#endif
}

auto DECLFN HwbpEng::Insert(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ BOOL  Init,
    _In_ ULONG ThreadID
) -> BOOL {
    
}

auto DECLFN HwbpEng::Init( VOID ) -> BOOL {
    if ( Initialized ) return TRUE;

    if ( !CritSec.DebugInfo ) {
        Self->Krnl32.InitializeCriticalSection( &CritSec );
    }

    Mem::Zero( U_PTR( &CritSec ), sizeof( CRITICAL_SECTION ) );
    Mem::Zero( U_PTR( Threads ), sizeof( DESCRIPTOR_HOOK ) );

    Handler = Self->Krnl32.AddVectoredExceptionHandler( 
        1, (PVECTORED_EXCEPTION_HANDLER)&MainHandler 
    );

    Self->Krnl32.InitializeCriticalSection( &CritSec );
    Initialized = TRUE;

    return TRUE;
}

auto DECLFN HwbpEng::Clean( VOID ) -> BOOL {
    if ( !Initialized ) return TRUE;

    Self->Krnl32.EnterCriticalSection( &CritSec );

    PDESCRIPTOR_HOOK Current = Threads;

    while ( Current ) {
        RmBreak( Current->Address, Current->ThreadID );
        Current = Current->Next;
    }

    Self->Krnl32.LeaveCriticalSection( &CritSec );

    if ( Handler ) Self->Krnl32.RemoveVectoredContinueHandler( Handler ); 

    Self->Krnl32.DeleteCriticalSection( &CritSec );

    Initialized = FALSE;

    return TRUE;
}

auto DECLFN HwbpEng::MainHandler( 
    _In_ PEXCEPTION_POINTERS e 
) -> LONG {
    BOOL Solutioned = FALSE;
    PDESCRIPTOR_HOOK Current = Threads;

    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) goto _KH_END;

    Self->Krnl32.EnterCriticalSection( &CritSec );

    while ( Current ) {
        if ( Current->ThreadID != 0 && Current->ThreadID != Self->Session.ThreadID ) {
            Current->Processed = TRUE;
        }

        // if ( !SetBreak( Self->Session.ThreadID, Current->Address, Current->Detour, Current->Drx ) ) {
            // goto _KH_END;
        // }

        VOID ( *Detour )( PCONTEXT ) = Current->Detour;
        Detour( e->ContextRecord );

        // if ( !SetBreak( Self->Session.ThreadID, Current->Address, Detour,  ) )
    }

_KH_END:
    return EXCEPTION_CONTINUE_SEARCH;
}

auto DECLFN HwbpEng::Etw(
    _In_ PEXCEPTION_POINTERS e
) -> LONG {

}

auto DECLFN HwbpEng::Amsi(
    _In_ PEXCEPTION_POINTERS e
) -> LONG {

}