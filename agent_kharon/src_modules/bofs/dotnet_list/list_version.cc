#include <general.h>
#include <dotnet.h>

auto VersionList( VOID ) -> VOID {
    HRESULT HResult = S_OK;

    WCHAR FmVersion[MAX_PATH] = { 0 };
    ULONG FmBuffLen = MAX_PATH;

    ICLRRuntimeInfo* RtmInfo     = { 0 };
    IUnknown*        EnumRtm     = { 0 };
    IEnumUnknown*    EnumUkwn    = { 0 };
    ICLRMetaHost*    MetaHost    = { 0 };

    //
    // host clr in the process
    //
    HResult = CLRCreateInstance(
        xCLSID.CLRMetaHost, xIID.ICLRMetaHost, (PVOID*)&MetaHost
    );
    if ( FAILED( HResult ) ) goto _BOF_END;

    //
    //  packet the versions
    //
    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( FAILED( HResult ) ) goto _BOF_END;

    while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
        if ( !EnumRtm ) continue;
        if ( SUCCEEDED( EnumRtm->QueryInterface( xIID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {

            if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                BeaconPrintf( CALLBACK_NO_PRE_MSG, "[+] Supported Version: %S\n", FmVersion );
            }
        }
    }

_BOF_END:
    if ( FAILED( HResult ) ) {
        WCHAR* ErrorMsg = fmt_error( HResult );
        BeaconPrintfW( CALLBACK_ERROR, L"Error to get installed .NET version (%x): %s\n", HResult, ErrorMsg );
        if ( ErrorMsg ) LocalFree( ErrorMsg );
    }

    if ( MetaHost ) MetaHost->Release();
    if ( EnumUkwn ) EnumUkwn->Release();
    if ( EnumRtm  ) EnumRtm->Release();
    if ( RtmInfo  ) RtmInfo->Release();

    return;
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    return VersionList();
}