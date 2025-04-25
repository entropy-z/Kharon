#include <Kharon.h>

auto DECLFN Socket::Exist(
    _In_ ULONG ServerID
) -> BOOL {
    KhDbg( "dbg" );
    PSOCKET_CTX Current = Ctx;

    if ( !Current ) return FALSE;

    while ( Current ) {
        if ( Current->ServerID == ServerID ) 
            return TRUE;
        Current = Current->Next;
    }
    return FALSE;
}

auto DECLFN Socket::Get(
    _In_ ULONG  ServerID
) -> SOCKET {
    PSOCKET_CTX Current = Ctx;

    if ( !Current ) return FALSE;

    while ( Current ) {
        if ( Current->ServerID == ServerID ) return Current->Socket;
        Current = Current->Next;
    }
    return NULL;
}

auto DECLFN Socket::Add(
    _In_ ULONG  ServerID,
    _In_ SOCKET Socket
) -> ERROR_CODE {
    if ( Exist( ServerID ) ) {
        return ERROR_ALREADY_EXISTS; 
    }

    PSOCKET_CTX newCtx = (PSOCKET_CTX)Self->Hp->Alloc( sizeof( SOCKET_CTX ) );
    if (!newCtx) {
        return ERROR_OUTOFMEMORY;
    }

    newCtx->Socket   = Socket;
    newCtx->ServerID = ServerID;
    newCtx->Next     = Ctx; 
    Ctx              = newCtx;
    Count++;

    return ERROR_SUCCESS;
}

auto DECLFN Socket::RmCtx(
    _In_ ULONG ServerID
) -> ERROR_CODE {
    PSOCKET_CTX* Prev    = &Ctx;
    PSOCKET_CTX  Current = Ctx;

    while ( Current ) {
        if ( Current->ServerID == ServerID ) {
            *Prev = Current->Next;
            Self->Hp->Free( Current, sizeof( SOCKET_CTX) ); 
            Count--;
            return ERROR_SUCCESS;
        }
        Prev = &Current->Next;
        Current = Current->Next;
    }
    return ERROR_NOT_FOUND;
}