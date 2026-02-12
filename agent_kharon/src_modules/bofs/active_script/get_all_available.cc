#include <general.h>
#include <activescript.h>

EXTERN_C auto Entry( int argc, char** argv ) -> VOID {
    GUID xCLSID_StdComponentCategoriesMgr = {0x0002E005, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

    CHAR* cScript     = nullptr;
    CHAR* cTargetlang = nullptr;

    WCHAR* wScript     = nullptr;
    WCHAR* wTargetLang = nullptr;

    RunScript( L"VBScript", wScript );

    return;
}

void RunScript( WCHAR* Language, WCHAR* ScriptContent ) {
    MyActiveScriptSite* mActiveScript = new MyActiveScriptSite();
    IActiveScriptParse* ActiveParse   = nullptr;
    IActiveScript*      ActiveEng     = nullptr; 

    IID xIID_IActiveScriptSite = {0xdb01a1e3, 0xa42b, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

    CLSID   LanguageId = { 0 };
    HRESULT Result     = S_OK;

    Result = CLSIDFromProgID( Language, &LanguageId );
    if ( FAILED( Result ) ) return;

    CoInitializeEx( nullptr, COINIT_MULTITHREADED );

    Result = CoCreateInstance( 
        LanguageId, 0, CLSCTX_INPROC_SERVER,
        IID_IActiveScript, (PVOID*)&ActiveEng
    );
    if ( FAILED( Result ) ) return;

    Result = ActiveEng->QueryInterface( 
        IID_IActiveScriptParse, (PVOID*)&ActiveParse 
    );
    if ( FAILED( Result ) ) return;

    ActiveParse->InitNew();

    ActiveEng->SetScriptSite( mActiveScript );

    Result = ActiveParse->ParseScriptText( 
        ScriptContent, nullptr, nullptr, 
        nullptr, 0, 0, 0, nullptr, nullptr
    );
    if ( FAILED( Result ) ) return;

    ActiveEng->SetScriptState( SCRIPTSTATE_CONNECTED );

    return;
}
