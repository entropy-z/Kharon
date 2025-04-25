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

auto DECLFN HwbpEng::SetBreak(
    _In_ HANDLE Handle,
    _In_ UPTR   Address,
    _In_ PVOID  Detour,
    _In_ INT8   Drx
) -> BOOL {
    CONTEXT Ctx  = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    ULONG   Code = STATUS_UNSUCCESSFUL;

    Code = Self->Ntdll.NtGetContextThread( Handle, &Ctx );

    switch ( Drx ) {
        case Dr0: {
            Ctx.Dr0 = Address; break;
        }
        case Dr1: {
            Ctx.Dr1 = Address; break;
        }
        case Dr2: {
            Ctx.Dr2 = Address; break;
        }
        case Dr3: {
            Ctx.Dr3 = Address; break;
        }
    }

    Threads->Hook[Drx].Address = Address;
    Threads->Hook[Drx].Detour  = ( decltype( Threads->Hook[Drx].Detour ) )Detour;

    Ctx.Dr7 = SetDr7( Ctx.Dr7, ( Drx * 2 ), 1, 1 );

    Code = Self->Ntdll.NtSetContextThread( Handle, &Ctx );

    return Code;
}

auto DECLFN HwbpEng::RmBreak(
    _In_ HANDLE Handle,
    _In_ INT8   Drx
) -> BOOL {
    CONTEXT Ctx  = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    ULONG   Code = STATUS_UNSUCCESSFUL;

    Code = Self->Ntdll.NtGetContextThread( Handle, &Ctx );

    switch ( Drx ) {
        case Dr0: {
            Ctx.Dr0 = 0; break;
        }
        case Dr1: {
            Ctx.Dr0 = 0; break;
        }
        case Dr2: {
            Ctx.Dr0 = 0; break;
        }
        case Dr3: {
            Ctx.Dr0 = 0; break;
        }
    }

    Ctx.Dr7 = SetDr7( Ctx.Dr7, ( Drx * 2 ), 1, 0 );

    Code = Self->Ntdll.NtSetContextThread( Handle, &Ctx );

    return Code;
}

auto DECLFN HwbpEng::GetFuncArg(
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

auto DECLFN HwbpEng::SetFuncArg(
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

auto DECLFN HwbpEng::MainHandler( 
    _In_ PEXCEPTION_POINTERS e 
) -> LONG {
    if ( e->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
        if (
             U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr0 ||
             U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr1 || 
             U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr2 ||  
             U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr3
        ) {
            INT8 Drx = -1;
            VOID ( *Detour )( PCONTEXT ) = nullptr;

            if ( U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr0 ) Drx = Dr0;
            if ( U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr1 ) Drx = Dr1;
            if ( U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr2 ) Drx = Dr2;
            if ( U_PTR( e->ExceptionRecord->ExceptionAddress ) == e->ContextRecord->Dr3 ) Drx = Dr3;
            // TODO

            RmBreak( Threads->Handle, Drx );

            Detour = Threads->Hook[Drx].Detour;
            Detour( e->ContextRecord );

            SetBreak( Threads->Handle, U_PTR( e->ExceptionRecord->ExceptionAddress ), C_PTR( Threads->Hook[Drx].Address ), Drx );

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

auto DECLFN HwbpEng::EtwHandler(
    _In_ PCONTEXT
) -> LONG {

}

auto DECLFN HwbpEng::AmsiHandler(
    _In_ PCONTEXT
) -> LONG {

}