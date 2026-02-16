#include <windows.h>
#include <stdio.h>

#include <initguid.h>
#include <shlwapi.h>
#include <comcat.h>
#include <objbase.h>
#include <activscp.h>

#define DECLFN __attribute__( ( section( ".text$B" ) ) )

auto DisplayScriptsEngs( VOID ) -> VOID;
auto RunScript( WCHAR* Language, WCHAR* ScriptContent ) -> VOID;

class MyActiveScriptSite : public IActiveScriptSite, public IActiveScriptSiteWindow {
private:
    ULONG m_cRef;

public:
    MyActiveScriptSite() : m_cRef(1) {}

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if ( ppv == nullptr ) return E_POINTER;

        IID  xIID_IUnknown = {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

        if (
            IsEqualIID( riid, xIID_IUnknown )          || 
            IsEqualIID( riid, IID_IActiveScriptSite )
        ) {
            *ppv = static_cast<IActiveScriptSite*>( this );
        } 
        else if ( IsEqualIID( riid, IID_IActiveScriptSiteWindow ) ) {
            *ppv = static_cast<IActiveScriptSiteWindow*>( this );
        }
        else {
            *ppv = nullptr;
            return E_NOINTERFACE;
        }

        AddRef();
        return S_OK;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release() override {
        ULONG refCount = InterlockedDecrement(&m_cRef);
        if (refCount == 0) {
            delete this;
        }
        return refCount;
    }

    STDMETHODIMP GetLCID(LCID *plcid) override { 
        return E_NOTIMPL; 
    }

    STDMETHODIMP GetItemInfo(
        LPCOLESTR pstrName,
        DWORD dwReturnMask,
        IUnknown **ppiunkItem,
        ITypeInfo **ppti
    ) override {
        return TYPE_E_ELEMENTNOTFOUND;
    }

    STDMETHODIMP GetDocVersionString(BSTR *pbstrVersion) override { 
        return E_NOTIMPL; 
    }

    STDMETHODIMP OnScriptTerminate(
        const VARIANT *pvarResult,
        const EXCEPINFO *pexcepinfo
    ) override { 
        return S_OK; 
    }

    STDMETHODIMP OnStateChange(SCRIPTSTATE ssScriptState) override { 
        return S_OK; 
    }

    STDMETHODIMP OnScriptError(IActiveScriptError *pscripterror) override {
        return S_OK;
    }

    STDMETHODIMP OnEnterScript() override { 
        return S_OK; 
    }

    STDMETHODIMP OnLeaveScript() override { 
        return S_OK; 
    }

    STDMETHODIMP GetWindow(HWND *phwnd) override {
        *phwnd = nullptr; 
        return S_OK;
    }

    STDMETHODIMP EnableModeless(BOOL fEnable) override {
        return S_OK;
    }
};
