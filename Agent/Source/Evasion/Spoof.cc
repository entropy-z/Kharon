#include <Kharon.h>

EXTERN_C UPTR SpoofCall( ... );

auto DECLFN Spoof::Call(
    _In_ UPTR Fnc, 
    _In_ UPTR Ssn, 
    _In_ UPTR Arg1,
    _In_ UPTR Arg2,
    _In_ UPTR Arg3,
    _In_ UPTR Arg4,
    _In_ UPTR Arg5,
    _In_ UPTR Arg6,
    _In_ UPTR Arg7,
    _In_ UPTR Arg8,
    _In_ UPTR Arg9,
    _In_ UPTR Arg10,
    _In_ UPTR Arg11,
    _In_ UPTR Arg12
) -> UPTR {
    KhDbg( "RtlUserThreadStart+0x21" );
    KhDbg( "Pointer    : %p", this->Setup.First.Ptr )
    KhDbg( "Stack  Size: %u", this->Setup.First.Size );
    KhDbg( "======================================" )

    KhDbg( "BaseThreadInitThunk+0x14" );
    KhDbg( "Pointer    : %p", this->Setup.Second.Ptr )
    KhDbg( "Stack  Size: %u", this->Setup.Second.Size );
    KhDbg( "======================================" )

    do {
        this->Setup.Gadget.Ptr  = Self->Usf->FindGadget( Self->KrnlBase.Handle, 0x23 );
        this->Setup.Gadget.Size = (UPTR)this->StackSizeWrapper( this->Setup.Gadget.Ptr );
    } while ( ! this->Setup.Gadget.Size );

    KhDbg( "Gadget" );
    KhDbg( "Pointer    : %p", this->Setup.Gadget.Ptr )
    KhDbg( "Stack  Size: %u", this->Setup.Gadget.Size );
    KhDbg( "======================================" )

    Setup.ArgCount = 8;

    return SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, (PVOID)&this->Setup, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12 );
}

auto DECLFN Spoof::StackSizeWrapper(
    _In_ UPTR RetAddress
) -> UPTR {
    LONG Status  = STATUS_SUCCESS;
    UPTR ImgBase = 0;

    RUNTIME_FUNCTION*     RtmFunction = { nullptr };
    UNWIND_HISTORY_TABLE* HistoryTbl  = { nullptr };

    if ( ! RetAddress ) {
        KhDbg("Invalid RetAddress");
        return (UPTR)nullptr;
    }

    KhDbg("Looking up function entry for RetAddress 0x%p", RetAddress);
    RtmFunction = Self->Ntdll.RtlLookupFunctionEntry( 
        (UPTR)RetAddress, &ImgBase, HistoryTbl 
    );
    if ( ! RtmFunction ) {
        KhDbg("No function entry found for RetAddress 0x%p", RetAddress);
        return (UPTR)nullptr;
    }

    KhDbg("Found function entry at 0x%p, calling StackSize", RtmFunction);
    KhDbg( "======================================" )
    return StackSize( (UPTR)RtmFunction, ImgBase );
}

auto DECLFN Spoof::StackSize(
    _In_ UPTR RtmFunction,
    _In_ UPTR ImgBase
) -> UPTR {
    STACK_FRAME  Stack   = { 0 };
    UNWIND_INFO* UwInfo  = (UNWIND_INFO*)( reinterpret_cast<RUNTIME_FUNCTION*>( RtmFunction )->UnwindData + ImgBase );
    UNWIND_CODE* UwCode  = UwInfo->UnwindCode;
    REG_CTX      Context = { 0 };

    ULONG FrameOffset = 0;
    ULONG Total       = 0;
    ULONG Index       = 0;
    UBYTE UnwOp       = 0;
    UBYTE OpInfo      = 0;
    ULONG CodeCount   = UwInfo->CountOfCodes;

    KhDbg("Processing unwind info at 0x%p with %d codes", UwInfo, CodeCount);

    while ( Index < CodeCount ) {
        UnwOp  = UwInfo->UnwindCode[Index].UnwindOp;
        OpInfo = UwInfo->UnwindCode[Index].OpInfo;

        switch ( UnwOp ) {
            case UWOP_PUSH_NONVOL: {
                Stack.TotalSize += 8;
                if ( OpInf::Rbp ) {
                    Stack.PushRbp      = TRUE;
                    Stack.CountOfCodes = CodeCount;
                    Stack.PushRbpIdx   = Index + 1;
                    KhDbg("UWOP_PUSH_NONVOL for RBP at index %d", Index);
                }
                break;
            }
            case UWOP_ALLOC_LARGE: {
                Index++;
                FrameOffset = UwCode[Index].FrameOffset;

                if ( OpInfo == 0 ) {
                    FrameOffset *= 8; 
                    KhDbg("UWOP_ALLOC_LARGE (small) adding %X %d bytes", FrameOffset, FrameOffset);
                } else if ( OpInfo == 1 ) {
                    Index++;
                    FrameOffset += UwCode[Index].FrameOffset << 16;
                    KhDbg("UWOP_ALLOC_LARGE (large) adding [%X] %d bytes", FrameOffset, FrameOffset);
                }

                Stack.TotalSize += FrameOffset; break;
            }
            case UWOP_ALLOC_SMALL: {
                ULONG size = ( ( OpInfo * 8 ) + 8 );
                KhDbg("UWOP_ALLOC_SMALL adding %X %d bytes", size, size);
                Stack.TotalSize += size; break;
            }
            case UWOP_SET_FPREG: {
                Stack.SetsFramePtr = TRUE; 
                KhDbg("UWOP_SET_FPREG detected");
                break;
            }
            case UWOP_SAVE_NONVOL: {
                Index += 1; 
                KhDbg("UWOP_SAVE_NONVOL at index %d", Index);
                break;
            }
            default:
                KhDbg("Unknown unwind op %d at index %d", UnwOp, Index);
                break; 
        }

        Index += 1;
    }

    if ( UwInfo->Flags & UNW_FLAG_CHAININFO ) {
        Index = UwInfo->CountOfCodes;
        if ( Index & 1 ) Index += 1;

        KhDbg("Chained unwind info detected, continuing at index %d", Index);
        RtmFunction = (UPTR)( reinterpret_cast<RUNTIME_FUNCTION*>( &UwInfo->UnwindCode[Index] ) );
        return this->StackSize( RtmFunction, ImgBase );
    }
    
    Stack.TotalSize += 8;
    KhDbg("Final stack size calculated as %d bytes", Stack.TotalSize);
    KhDbg( "======================================" )

    return (UPTR)Stack.TotalSize;
}