#include <wbemcli.h>
#include <combaseapi.h>
#include <stdio.h>

#include <Win32.h>

int main() {
    HRESULT Result = S_OK;

    IWbemLocator*  Locator  = NULL;
    IWbemServices* Services = NULL;

    BSTR CmdLn  = L"";
    BSTR Usr    = L"";
    BSTR Passwd = L"";
    BSTR Host   = SysAllocString( L"DESKTOP-7E5JCIR" ); 
    BSTR Domain = L"";

    PWCH  ProgId = (PWCH)HeapAlloc( GetProcessHeap(), 0, 5000 );
    BSTR  wClsid = SysAllocString( L"{dc12a687-737f-11cf-884d-00aa004b2e24}" );
    BSTR  wIid   = SysAllocString( L"{4590f811-1d3a-11d0-891f-00aa004b2e24}" );
    CLSID Clsid  = { 0 };
    IID   Iid    = { 0 };

    CLSIDFromString( wClsid, &Clsid );
    printf( "result: %X\n", Result );

    CLSIDFromString( wIid, &Iid );

    Result = CoInitializeEx( 0, COINIT_APARTMENTTHREADED );
    // if ( Result = RPC_E_CHANGED_MODE ) {
        printf( "result: %X %d\n", Result, __LINE__ );
    // }

    printf( "result: %X %d\n", Result, __LINE__ );

    Result = CoCreateInstance( Clsid, 0, CLSCTX_INPROC_SERVER, Iid, (PVOID*)&Locator );

    Result = ProgIDFromCLSID( Clsid, &ProgId );
    printf( "result: %X\n", Result );

    printf( "CLSID : %S\n", wClsid );
    printf( "IID   : %S\n", wIid );
    printf( "ProgID: %S\n", ProgId );

    Locator->ConnectServer( Host, NULL, NULL, 0, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, &Services );

    // CoSetProxyBlanket( Services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,  )
}