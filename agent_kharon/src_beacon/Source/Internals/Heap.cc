#include <Kharon.h>

using namespace Root;

auto DECLFN Heap::Crypt( VOID ) -> VOID {
    HEAP_NODE* Current = this->Node;

    while ( Current ) {
        if ( Current->Block && Current->Size > 0 ) {
            Self->Crp->Xor( B_PTR( Current->Block ), Current->Size );
        }

        Current = Current->Next;
    }
}

auto DECLFN Heap::Alloc(
    _In_ ULONG Size
) -> PVOID {
    if ( Size == 0 ) return NULL;

    PVOID Block = Self->Ntdll.RtlAllocateHeap( PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Size );
    if ( !Block ) return NULL; 

    HEAP_NODE* NewNode = (HEAP_NODE*)Self->Ntdll.RtlAllocateHeap(
        PTR( Self->Session.HeapHandle  ),
        HEAP_ZERO_MEMORY,
        sizeof( HEAP_NODE )
    );
    if ( ! NewNode ) {
        return NULL;
    }

    NewNode->Block = Block;
    NewNode->Size  = Size;
    NewNode->Next  = NULL;

    if ( ! this->Node ) {
        this->Node = NewNode;
    } else {
        HEAP_NODE* Current = this->Node;
        while ( Current->Next ) {
            Current = Current->Next;
        }
        Current->Next = NewNode;
    }

    Count++;
    return Block;
}

auto DECLFN Heap::ReAlloc(
    _In_ PVOID Block,
    _In_ ULONG Size
) -> PVOID {
    PVOID ReBlock = Self->Ntdll.RtlReAllocateHeap( PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Block, Size );

    HEAP_NODE* Current = this->Node;

    while ( Current ) {
        if ( Current->Block == Block ) {
            Current->Block = ReBlock;
            Current->Size  = Size;
            break;
        }

        Current = Current->Next;
    }

    return ReBlock;
}

auto DECLFN Heap::CheckPtr( PVOID Ptr ) -> BOOL {
    HEAP_NODE* Current = this->Node;

    while ( Current ) {
        if ( Current->Block == Ptr ) {
            return TRUE;
        }

        Current = Current->Next;
    }

    return FALSE;
}

auto DECLFN Heap::Free(
    _In_ PVOID Block
) -> BOOL {
    if ( !Block ) return FALSE;

    HEAP_NODE* Current  = this->Node;
    HEAP_NODE* Previous = NULL;
    BOOL Result = FALSE;

    while ( Current ) {
        if ( Current->Block == Block ) {
            if ( Current->Block ) {
                Mem::Zero( U_PTR( Current->Block ), Current->Size );
                Result = Self->Ntdll.RtlFreeHeap( PTR( Self->Session.HeapHandle ), 0, Current->Block );
                Current->Block = nullptr;
                Current->Size  = 0;
            }

            if ( Previous ) {
                Previous->Next = Current->Next;
            } else {
                Node = Current->Next;
            }

            Result = Self->Ntdll.RtlFreeHeap( PTR( Self->Session.HeapHandle ), 0, Current );
            Current = nullptr;
            this->Count--;
            break;
        }

        Previous = Current;
        Current  = Current->Next;
    }

    return Result;
}

auto DECLFN Heap::Clean( VOID ) -> VOID {
    HEAP_NODE* Current = this->Node;

    while ( Current ) {
        this->Free( Current->Block );
        Current = Current->Next;
    }
}