#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>

#define KEY_SEPARATOR			L" ,\t\n"
#define HEADER_ROW				0
#define WMI_QUERY_LANGUAGE		L"WQL"
#define WMI_NAMESPACE_CIMV2		L"root\\cimv2"
#define RESOURCE_FMT_STRING		L"\\\\%s\\%s"
#define RESOURCE_LOCAL_HOST		L"."
#define ERROR_RESULT			L"*ERROR*"
#define EMPTY_RESULT			L"(EMPTY)"
#define NULL_RESULT				L"(NULL)"

typedef struct _Wmi {
	IWbemServices* pWbemServices;
	IWbemLocator* pWbemLocator;
	IEnumWbemClassObject* pEnumerator;
	BSTR bstrLanguage;
	BSTR bstrNameSpace;
	BSTR bstrNetworkResource;
	BSTR bstrQuery;
} WMI;

HRESULT Wmi_Initialize(WMI* pWmi)
{
	HRESULT	hr = S_OK;

	pWmi->pWbemServices = NULL;
	pWmi->pWbemLocator  = NULL;
	pWmi->pEnumerator   = NULL;
	pWmi->bstrLanguage  = NULL;
	pWmi->bstrNameSpace = NULL;
	pWmi->bstrQuery     = NULL;
	
	pWmi->bstrLanguage  = SysAllocString( WMI_QUERY_LANGUAGE );
	pWmi->bstrNameSpace = SysAllocString( WMI_NAMESPACE_CIMV2 );

	hr = CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
	if ( hr == RPC_E_CHANGED_MODE ) {
    		hr = S_OK;
	} else if (FAILED(hr)) {
    		BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx", hr);
    		goto fail;
	}
	
    hr = CoInitializeSecurity( //Failure of this function does not necessarily mean we failed to initialize, it will fail on repeated calls, but the values from the original call are retained
			NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL
        );
        if (FAILED(hr))
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to set security, token impersonation may not work\n");
        }
	
	hr = S_OK;

fail:

	return hr;
}

HRESULT wmi_query(
	LPWSTR pwszServer,
	LPWSTR pwszNameSpace,	
	LPWSTR pwszQuery,
	LPWSTR pwszResource
)
{
	HRESULT	hr						= S_OK;
	WMI		m_WMI;
	size_t	ullColumnsSize			= 0;
	LPWSTR	lpwszColumns			= NULL;	
	BSTR**	ppbstrResults			= NULL;
	DWORD	dwRowCount				= 0;
	DWORD	dwColumnCount			= 0;
	DWORD	dwCurrentRowIndex		= 0;
	DWORD	dwCurrentColumnIndex	= 0;

	// Initialize COM
	hr = Wmi_Initialize(&m_WMI);
	if (FAILED(hr))
	{
		// BeaconPrintf(CALLBACK_ERROR, "Wmi_Initialize failed: 0x%08lx", hr);
		goto fail;
	}

	// Connect to WMI on host
	hr = Wmi_Connect(&m_WMI, pwszResource);
	if (FAILED(hr))
	{
		// BeaconPrintf(CALLBACK_ERROR, "Wmi_Connect failed: 0x%08lx", hr);
		goto fail;
	}

	// Run the WMI query
	hr = Wmi_Query(&m_WMI, pwszQuery);
	if (FAILED(hr))
	{
		// BeaconPrintf(CALLBACK_ERROR, "Wmi_Query failed: 0x%08lx", hr);
		goto fail;
	}

	// Parse the results
	hr = Wmi_ParseAllResults(&m_WMI, &ppbstrResults, &dwRowCount, &dwColumnCount);
	if (FAILED(hr))
	{
		// BeaconPrintf(CALLBACK_ERROR, "Wmi_ParseAllResults failed: 0x%08lx", hr);
		goto fail;
	}

	// Display the resuls in CSV format
	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
            if ( 0 == dwCurrentColumnIndex )		
            {
    			internal_printf( "%S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );			
            }
            else
            {
                internal_printf( ", %S", ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex] );    			
            }
		}
		internal_printf( "\n" );
	}

	hr = S_OK;

fail:

	for (dwCurrentRowIndex = 0; dwCurrentRowIndex < dwRowCount; dwCurrentRowIndex++)
	{
		for (dwCurrentColumnIndex = 0; dwCurrentColumnIndex < dwColumnCount; dwCurrentColumnIndex++)
		{
			SAFE_FREE(ppbstrResults[dwCurrentRowIndex][dwCurrentColumnIndex]);
		}
		HeapFree(GetProcessHeap(), 0, ppbstrResults[dwCurrentRowIndex]);
	}
	
	if (ppbstrResults)
	{
		HeapFree(GetProcessHeap(), 0, ppbstrResults);
		ppbstrResults = NULL;
	}

	Wmi_Finalize(&m_WMI);
	
	return hr;
}

int main() {
    wmi_query( "" )
}