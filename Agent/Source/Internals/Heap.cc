#include <Kharon.h>

using namespace Root;

auto DECLFN Heap::Crypt( VOID ) -> VOID {
    PHEAP_NODE Current = Node;

    while ( Current ) {
        if ( Current->Block && Current->Size > 0 ) {
            Self->Usf->Xor(
                B_PTR( Current->Block ),
                Current->Size,
                Key, sizeof( Key )
            );
        }

        Current = Current->Next;
    }
}

auto DECLFN Heap::Alloc(
    _In_ ULONG Size
) -> PVOID {
    if (Size == 0) return NULL;

    PVOID Block = Self->Ntdll.RtlAllocateHeap(C_PTR(Self->Session.HeapHandle), HEAP_ZERO_MEMORY, Size);
    if (!Block) return NULL;  // Falha na alocação

    PHEAP_NODE NewNode = (PHEAP_NODE)Self->Ntdll.RtlAllocateHeap(
        C_PTR(Self->Session.HeapHandle),
        HEAP_ZERO_MEMORY,
        sizeof(HEAP_NODE)
    );
    if (!NewNode) {
        Self->Ntdll.RtlFreeHeap(C_PTR(Self->Session.HeapHandle), 0, Block);
        return NULL;
    }

    NewNode->Block = Block;
    NewNode->Size  = Size;
    NewNode->Next  = NULL;

    if (!Node) {
        Node = NewNode;
    } else {
        PHEAP_NODE Current = Node;
        while (Current->Next) {
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
    PVOID ReBlock = Self->Ntdll.RtlReAllocateHeap( C_PTR( Self->Session.HeapHandle ), HEAP_ZERO_MEMORY, Block, Size );

    PHEAP_NODE Current = Node;

    while ( Current ) {
        if ( Current->Block = Block ) {
            Current->Block = ReBlock;
            Current->Size  = Size;
            break;
        }

        Current = Current->Next;
    }

    return ReBlock;
}

auto DECLFN Heap::Free(
    _In_ PVOID Block
) -> BOOL {
    if (!Block) return FALSE;

    PHEAP_NODE Current = Node;
    PHEAP_NODE Previous = NULL;
    BOOL Result = FALSE;

    while ( Current ) {
        if ( Current->Block == Block ) {
            if ( Current->Block ) {
                Mem::Zero( U_PTR( Current->Block ), Current->Size );
                Result = Self->Ntdll.RtlFreeHeap( C_PTR( Self->Session.HeapHandle ), 0, Current->Block );
                if ( !Result ) {
                    break;
                }
            }

            if ( Previous ) {
                Previous->Next = Current->Next;
            } else {
                Node = Current->Next;
            }

            Self->Ntdll.RtlFreeHeap( C_PTR( Self->Session.HeapHandle ), 0, Current );
            Count--;
            break;
        }

        Previous = Current;
        Current  = Current->Next;
    }

    return Result;
}