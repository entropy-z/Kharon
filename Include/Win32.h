#ifndef WIN32_H
#define WIN32_H

#include <windows.h>

/* ========== [ Structs ] ========== */

typedef ULONG       ERROR_CODE;
typedef UINT_PTR    UPTR;

#define KhGetError()     NtCurrentTeb()->LastErrorValue;
#define KhSetError( x )  NtCurrentTeb()->LastErrorValue = x;
#define KhRetError( x )  KhSetError( x ); return KhGetError();
#define KhRetSuccess     KhSetError( ERROR_SUCCESS ); return KhGetError();

typedef struct {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef struct {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)( PVOID ThreadParameter );

typedef struct _ACTIVATION_CONTEXT_DATA {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef VOID (NTAPI *PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ PVOID ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext,
    _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification
);

#define WIN32_CLIENT_INFO_LENGTH 62

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct {
    LONG RefCount;
    ULONG Flags;
    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP StorageMap;
    PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;

typedef struct { 
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

#define STATIC_UNICODE_BUFFER_LENGTH 261

typedef struct _TELEMETRY_COVERAGE_HEADER
{
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    struct
    {
        USHORT TracingEnabled : 1;
        USHORT Reserved1 : 15;
    };
    ULONG HashTableEntries;
    ULONG HashIndexMask;
    ULONG TableUpdateVersion;
    ULONG TableSizeInBytes;
    ULONG LastResetTick;
    ULONG ResetRound;
    ULONG Reserved2;
    ULONG RecordedCount;
    ULONG Reserved3[4];
    ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, *PTELEMETRY_COVERAGE_HEADER;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)( VOID );

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _SILO_USER_SHARED_DATA {
    ULONG ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForeRootProcessId;
    NT_PRODUCT_TYPE NtProductType;
    ULONG SuiteMask;
    ULONG SharedUserSessionId; // since RS2
    BOOLEAN IsMultiSessionSku;
    BOOLEAN IsStateSeparationEnabled;
    WCHAR NtSystemRoot[260];
    USHORT UserModeGlobalLogger[16];
    ULONG TimeZoneId; // since 21H2
    LONG TimeZoneBiasStamp;
    KSYSTEM_TIME TimeZoneBias;
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, *PSILO_USER_SHARED_DATA;

typedef struct _WER_RECOVERY_INFO {
    ULONG Length;
    PVOID Callback;
    PVOID Parameter;
    HANDLE Started;
    HANDLE Finished;
    HANDLE InProgress;
    LONG LastError;
    BOOL Successful;
    ULONG PingInterval;
    ULONG Flags;
} WER_RECOVERY_INFO, *PWER_RECOVERY_INFO;

typedef struct _WER_FILE {
    USHORT Flags;
    WCHAR Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

typedef struct _WER_MEMORY {
    PVOID Address;
    ULONG Size;
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER {
    PVOID Next;
    USHORT Flags;
    union {
      WER_FILE File;
      WER_MEMORY Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

typedef struct _WER_METADATA {
    PVOID Next;
    WCHAR Key[64];
    WCHAR Value[128];
} WER_METADATA, *PWER_METADATA;

typedef struct _WER_DUMP_COLLECTION {
    PVOID Next;
    ULONG ProcessId;
    ULONG ThreadId;
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_RUNTIME_DLL {
    PVOID Next;
    ULONG Length;
    PVOID Context;
    WCHAR CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

typedef struct _WER_HEAP_MAIN_HEADER {
    WCHAR Signature[16];
    LIST_ENTRY Links;
    HANDLE Mutex;
    PVOID FreeHeap;
    ULONG FreeCount;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

typedef struct _WER_PEB_HEADER_BLOCK {
    LONG Length;
    WCHAR Signature[16];
    WCHAR AppDataRelativePath[64];
    WCHAR RestartCommandLine[RESTART_MAX_CMD_LINE];
    WER_RECOVERY_INFO RecoveryInfo;
    PWER_GATHER Gather;
    PWER_METADATA MetaData;
    PWER_RUNTIME_DLL RuntimeDll;
    PWER_DUMP_COLLECTION DumpCollection;
    LONG GatherCount;
    LONG MetaDataCount;
    LONG DumpCount;
    LONG Flags;
    WER_HEAP_MAIN_HEADER MainHeader;
    PVOID Reserved;
} WER_PEB_HEADER_BLOCK, *PWER_PEB_HEADER_BLOCK;

typedef struct _LEAP_SECOND_DATA *PLEAP_SECOND_DATA;

typedef enum _LDR_HOT_PATCH_STATE {
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, *PLDR_HOT_PATCH_STATE;

typedef _Function_class_(LDR_INIT_ROUTINE)
BOOLEAN NTAPI LDR_INIT_ROUTINE( PVOID DllHandle, ULONG Reason, PVOID Context );

typedef LDR_INIT_ROUTINE* PLDR_INIT_ROUTINE;

typedef struct _LDR_SERVICE_TAG_RECORD {
    struct _LDR_SERVICE_TAG_RECORD *Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST {
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE {
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef struct _LDRP_LOAD_CONTEXT *PLDRP_LOAD_CONTEXT;

typedef struct _RTL_BALANCED_NODE{
    union
    {
        struct _RTL_BALANCED_NODE *Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE *Left;
            struct _RTL_BALANCED_NODE *Right;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    } DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    PLDRP_LOAD_CONTEXT LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    PVOID OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason; // since WIN8
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum; // since 22H1
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    //
    // The process was cloned with an inherited address space.
    //
    BOOLEAN InheritedAddressSpace;

    //
    // The process has image file execution options (IFEO).
    //
    BOOLEAN ReadImageFileExecOptions;

    //
    // The process has a debugger attached.
    //
    BOOLEAN BeingDebugged;

    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;            // The process uses large image regions (4 MB).
            BOOLEAN IsProtectedProcess : 1;             // The process is a protected process.
            BOOLEAN IsImageDynamicallyRelocated : 1;    // The process image base address was relocated.
            BOOLEAN SkipPatchingUser32Forwarders : 1;   // The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.
            BOOLEAN IsPackagedProcess : 1;              // The process is a packaged store process (APPX/MSIX).
            BOOLEAN IsAppContainer : 1;                 // The process has an AppContainer token.
            BOOLEAN IsProtectedProcessLight : 1;        // The process is a protected process (light).
            BOOLEAN IsLongPathAwareProcess : 1;         // The process is long path aware.
        };
    };

    //
    // Handle to a mutex for synchronization.
    //
    HANDLE Mutant;

    //
    // Pointer to the base address of the process image.
    //
    PVOID ImageBaseAddress;

    //
    // Pointer to the process loader data.
    //
    PPEB_LDR_DATA Ldr;

    //
    // Pointer to the process parameters.
    //
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    //
    // Reserved.
    //
    PVOID SubSystemData;

    //
    // Pointer to the process default heap.
    //
    PVOID ProcessHeap;

    //
    // Pointer to a critical section used to synchronize access to the PEB.
    //
    PRTL_CRITICAL_SECTION FastPebLock;

    //
    // Pointer to a singly linked list used by ATL.
    //
    PSLIST_HEADER AtlThunkSListPtr;

    //
    // Pointer to the Image File Execution Options key.
    //
    PVOID IFEOKey;

    //
    // Cross process flags.
    //
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;                 // The process is part of a job.
            ULONG ProcessInitializing : 1;          // The process is initializing.
            ULONG ProcessUsingVEH : 1;              // The process is using VEH.
            ULONG ProcessUsingVCH : 1;              // The process is using VCH.
            ULONG ProcessUsingFTH : 1;              // The process is using FTH.
            ULONG ProcessPreviouslyThrottled : 1;   // The process was previously throttled.
            ULONG ProcessCurrentlyThrottled : 1;    // The process is currently throttled.
            ULONG ProcessImagesHotPatched : 1;      // The process images are hot patched. // RS5
            ULONG ReservedBits0 : 24;
        };
    };

    //
    // User32 KERNEL_CALLBACK_TABLE (ntuser.h)
    //
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    //
    // Reserved.
    //
    ULONG SystemReserved;

    //
    // Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    //
    ULONG AtlThunkSListPtr32;

    //
    // Pointer to the API Set Schema.
    //
    PAPI_SET_NAMESPACE ApiSetMap;

    //
    // Counter for TLS expansion.
    //
    ULONG TlsExpansionCounter;

    //
    // Pointer to the TLS bitmap.
    //
    PRTL_BITMAP TlsBitmap;

    //
    // Bits for the TLS bitmap.
    //
    ULONG TlsBitmapBits[2];

    //
    // Reserved for CSRSS.
    //
    PVOID ReadOnlySharedMemoryBase;

    //
    // Pointer to the USER_SHARED_DATA for the current SILO.
    //
    PSILO_USER_SHARED_DATA SharedData;

    //
    // Reserved for CSRSS.
    //
    PVOID* ReadOnlyStaticServerData;

    //
    // Pointer to the ANSI code page data. (PCPTABLEINFO)
    //
    PVOID AnsiCodePageData;

    //
    // Pointer to the OEM code page data. (PCPTABLEINFO)
    //
    PVOID OemCodePageData;

    //
    // Pointer to the Unicode case table data. (PNLSTABLEINFO)
    //
    PVOID UnicodeCaseTableData;

    //
    // The total number of system processors.
    //
    ULONG NumberOfProcessors;

    //
    // Global flags for the system.
    //
    union
    {
        ULONG NtGlobalFlag;
        struct
        {
            ULONG StopOnException : 1;          // FLG_STOP_ON_EXCEPTION
            ULONG ShowLoaderSnaps : 1;          // FLG_SHOW_LDR_SNAPS
            ULONG DebugInitialCommand : 1;      // FLG_DEBUG_INITIAL_COMMAND
            ULONG StopOnHungGUI : 1;            // FLG_STOP_ON_HUNG_GUI
            ULONG HeapEnableTailCheck : 1;      // FLG_HEAP_ENABLE_TAIL_CHECK
            ULONG HeapEnableFreeCheck : 1;      // FLG_HEAP_ENABLE_FREE_CHECK
            ULONG HeapValidateParameters : 1;   // FLG_HEAP_VALIDATE_PARAMETERS
            ULONG HeapValidateAll : 1;          // FLG_HEAP_VALIDATE_ALL
            ULONG ApplicationVerifier : 1;      // FLG_APPLICATION_VERIFIER
            ULONG MonitorSilentProcessExit : 1; // FLG_MONITOR_SILENT_PROCESS_EXIT
            ULONG PoolEnableTagging : 1;        // FLG_POOL_ENABLE_TAGGING
            ULONG HeapEnableTagging : 1;        // FLG_HEAP_ENABLE_TAGGING
            ULONG UserStackTraceDb : 1;         // FLG_USER_STACK_TRACE_DB
            ULONG KernelStackTraceDb : 1;       // FLG_KERNEL_STACK_TRACE_DB
            ULONG MaintainObjectTypeList : 1;   // FLG_MAINTAIN_OBJECT_TYPELIST
            ULONG HeapEnableTagByDll : 1;       // FLG_HEAP_ENABLE_TAG_BY_DLL
            ULONG DisableStackExtension : 1;    // FLG_DISABLE_STACK_EXTENSION
            ULONG EnableCsrDebug : 1;           // FLG_ENABLE_CSRDEBUG
            ULONG EnableKDebugSymbolLoad : 1;   // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
            ULONG DisablePageKernelStacks : 1;  // FLG_DISABLE_PAGE_KERNEL_STACKS
            ULONG EnableSystemCritBreaks : 1;   // FLG_ENABLE_SYSTEM_CRIT_BREAKS
            ULONG HeapDisableCoalescing : 1;    // FLG_HEAP_DISABLE_COALESCING
            ULONG EnableCloseExceptions : 1;    // FLG_ENABLE_CLOSE_EXCEPTIONS
            ULONG EnableExceptionLogging : 1;   // FLG_ENABLE_EXCEPTION_LOGGING
            ULONG EnableHandleTypeTagging : 1;  // FLG_ENABLE_HANDLE_TYPE_TAGGING
            ULONG HeapPageAllocs : 1;           // FLG_HEAP_PAGE_ALLOCS
            ULONG DebugInitialCommandEx : 1;    // FLG_DEBUG_INITIAL_COMMAND_EX
            ULONG DisableDbgPrint : 1;          // FLG_DISABLE_DBGPRINT
            ULONG CritSecEventCreation : 1;     // FLG_CRITSEC_EVENT_CREATION
            ULONG LdrTopDown : 1;               // FLG_LDR_TOP_DOWN
            ULONG EnableHandleExceptions : 1;   // FLG_ENABLE_HANDLE_EXCEPTIONS
            ULONG DisableProtDlls : 1;          // FLG_DISABLE_PROTDLLS
        } NtGlobalFlags;
    };

    //
    // Timeout for critical sections.
    //
    LARGE_INTEGER CriticalSectionTimeout;

    //
    // Reserved size for heap segments.
    //
    SIZE_T HeapSegmentReserve;

    //
    // Committed size for heap segments.
    //
    SIZE_T HeapSegmentCommit;

    //
    // Threshold for decommitting total free heap.
    //
    SIZE_T HeapDeCommitTotalFreeThreshold;

    //
    // Threshold for decommitting free heap blocks.
    //
    SIZE_T HeapDeCommitFreeBlockThreshold;

    //
    // Number of process heaps.
    //
    ULONG NumberOfHeaps;

    //
    // Maximum number of process heaps.
    //
    ULONG MaximumNumberOfHeaps;

    //
    // Pointer to an array of process heaps. ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //
    PVOID* ProcessHeaps;

    //
    // Pointer to the system GDI shared handle table.
    //
    PVOID GdiSharedHandleTable;

    //
    // Pointer to the process starter helper.
    //
    PVOID ProcessStarterHelper;

    //
    // The maximum number of GDI function calls during batch operations (GdiSetBatchLimit)
    //
    ULONG GdiDCAttributeList;

    //
    // Pointer to the loader lock critical section.
    //
    PRTL_CRITICAL_SECTION LoaderLock;

    //
    // Major version of the operating system.
    //
    ULONG OSMajorVersion;

    //
    // Minor version of the operating system.
    //
    ULONG OSMinorVersion;

    //
    // Build number of the operating system.
    //
    USHORT OSBuildNumber;

    //
    // CSD version of the operating system.
    //
    USHORT OSCSDVersion;

    //
    // Platform ID of the operating system.
    //
    ULONG OSPlatformId;

    //
    // Subsystem version of the current process image (PE Headers).
    //
    ULONG ImageSubsystem;

    //
    // Major version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMajorVersion;

    //
    // Minor version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMinorVersion;

    //
    // Affinity mask for the current process.
    //
    KAFFINITY ActiveProcessAffinityMask;

    //
    // Temporary buffer for GDI handles accumulated in the current batch.
    //
    GDI_HANDLE_BUFFER GdiHandleBuffer;

    //
    // Pointer to the post-process initialization routine available for use by the application.
    //
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    //
    // Pointer to the TLS expansion bitmap.
    //
    PRTL_BITMAP TlsExpansionBitmap;

    //
    // Bits for the TLS expansion bitmap. TLS_EXPANSION_SLOTS
    //
    ULONG TlsExpansionBitmapBits[32];

    //
    // Session ID of the current process.
    //
    ULONG SessionId;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlags;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlagsUser;

    //
    // Pointer to the Application SwitchBack Compatibility Engine.
    //
    PVOID pShimData;

    //
    // Pointer to the Application Compatibility Engine. // APPCOMPAT_EXE_DATA
    //
    PVOID AppCompatInfo;

    //
    // CSD version string of the operating system.
    //
    UNICODE_STRING CSDVersion;

    //
    // Pointer to the process activation context.
    //
    PACTIVATION_CONTEXT_DATA ActivationContextData;

    //
    // Pointer to the process assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;

    //
    // Pointer to the system default activation context.
    //
    PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;

    //
    // Pointer to the system assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

    //
    // Minimum stack commit size.
    //
    SIZE_T MinimumStackCommit;

    //
    // since 19H1 (previously FlsCallback to FlsHighIndex)
    //
    PVOID SparePointers[2];

    //
    // Pointer to the patch loader data.
    //
    PVOID PatchLoaderData;

    //
    // Pointer to the CHPE V2 process information. CHPEV2_PROCESS_INFO
    //
    PVOID ChpeV2ProcessInfo;

    //
    // Packaged process feature state.
    //
    union
    {
        ULONG AppModelFeatureState;
        struct
        {
            ULONG ForeRootBoostProcesses : 1;
            ULONG AppModelFeatureStateReserved : 31;
        };
    };

    //
    // SpareUlongs
    //
    ULONG SpareUlongs[2];

    //
    // Active code page.
    //
    USHORT ActiveCodePage;

    //
    // OEM code page.
    //
    USHORT OemCodePage;

    //
    // Code page case mapping.
    //
    USHORT UseCaseMapping;

    //
    // Unused NLS field.
    //
    USHORT UnusedNlsField;

    //
    // Pointer to the application WER registration data.
    //
    PWER_PEB_HEADER_BLOCK WerRegistrationData;

    //
    // Pointer to the application WER assert pointer.
    //
    PVOID WerShipAssertPtr;

    //
    // Pointer to the EC bitmap on ARM64. (Windows 11 and above)
    //
    union
    {
        PVOID pContextData; // Pointer to the switchback compatibility engine (Windows 7 and below)
        PVOID EcCodeBitMap; // Pointer to the EC bitmap on ARM64 (Windows 11 and above) // since WIN11
    };

    //
    // Reserved.
    //
    PVOID pImageHeaderHash;

    //
    // ETW tracing flags.
    //
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;       // ETW heap tracing enabled.
            ULONG CritSecTracingEnabled : 1;    // ETW lock tracing enabled.
            ULONG LibLoaderTracingEnabled : 1;  // ETW loader tracing enabled.
            ULONG SpareTracingBits : 29;
        };
    };

    //
    // Reserved for CSRSS.
    //
    ULONGLONG CsrServerReadOnlySharedMemoryBase;

    //
    // Pointer to the thread pool worker list lock.
    //
    PRTL_CRITICAL_SECTION TppWorkerpListLock;

    //
    // Pointer to the thread pool worker list.
    //
    LIST_ENTRY TppWorkerpList;

    //
    // Wait on address hash table. (RtlWaitOnAddress)
    //
    PVOID WaitOnAddressHashTable[128];

    //
    // Pointer to the telemetry coverage header. // since RS3
    //
    PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader;

    //
    // Cloud file flags. (ProjFs and Cloud Files) // since RS4
    //
    ULONG CloudFileFlags;

    //
    // Cloud file diagnostic flags.
    //
    ULONG CloudFileDiagFlags;

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Reserved for placeholder compatibility mode.
    //
    CHAR PlaceholderCompatibilityModeReserved[7];

    //
    // Pointer to leap second data. // since RS5
    //
    PLEAP_SECOND_DATA LeapSecondData;

    //
    // Leap second flags.
    //
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1; // Leap seconds enabled.
            ULONG Reserved : 31;
        };
    };

    //
    // Global flags for the process.
    //
    ULONG NtGlobalFlag2;

    //
    // Extended feature disable mask (AVX). // since WIN11
    //
    ULONGLONG ExtendedFeatureDisableMask;
} PEB, * PPEB;

/**
 * Thread Environment Block (TEB) structure.
 *
 * \remarks https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
 */
typedef struct _TEB {
    NT_TIB NtTib;

    //
    // Reserved.
    //
    PVOID EnvironmentPointer;

    //
    // Client ID for this thread.
    //
    CLIENT_ID ClientId;

    //
    // A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    //
    PVOID ActiveRpcHandle;

    //
    // A pointer to the __declspec(thread) local storage array.
    //
    PVOID ThreadLocalStoragePointer;

    //
    // A pointer to the Process Environment Block (PEB), which contains information about the process.
    //
    PPEB ProcessEnvironmentBlock;

    //
    // The previous Win32 error value for this thread.
    //
    ULONG LastErrorValue;

    //
    // The number of critical sections currently owned by this thread.
    //
    ULONG CountOfOwnedCriticalSections;

    //
    // Reserved.
    //
    PVOID CsrClientThread;

    //
    // Reserved.
    //
    PVOID Win32ThreadInfo;

    //
    // Reserved.
    //
    ULONG User32Reserved[26];

    //
    // Reserved.
    //
    ULONG UserReserved[5];

    //
    // Reserved.
    //
    PVOID WOW32Reserved;

    //
    // The LCID of the current thread. (Kernel32!GetThreadLocale)
    //
    LCID CurrentLocale;

    //
    // Reserved.
    //
    ULONG FpSoftwareStatusRegister;

    //
    // Reserved.
    //
    PVOID ReservedForDebuggerInstrumentation[16];

#ifdef _WIN64
    //
    // Reserved.
    //
    PVOID SystemReserved1[25];

    //
    // Per-thread fiber local storage. (Teb->HasFiberData)
    //
    PVOID HeapFlsData;

    //
    // Reserved.
    //
    ULONG_PTR RngState[4];
#else
    //
    // Reserved.
    //
    PVOID SystemReserved1[26];
#endif

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Indicates whether placeholder hydration is always explicit.
    //
    BOOLEAN PlaceholderHydrationAlwaysExplicit;

    //
    // Reserved.
    //
    CHAR PlaceholderReserved[10];

    //
    // The process ID (PID) that the current COM server thread is acting on behalf of.
    //
    ULONG ProxiedProcessId;

    //
    // Pointer to the activation context stack for the current thread.
    //
    ACTIVATION_CONTEXT_STACK ActivationStack;

    //
    // Opaque operation on behalf of another user or process.
    //
    UCHAR WorkingOnBehalfTicket[8];

    //
    // The last exception status for the current thread.
    //
    NTSTATUS ExceptionCode;

    //
    // Pointer to the activation context stack for the current thread.
    //
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    //
    // The stack pointer (SP) of the current system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackSp;

    //
    // The program counter (PC) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousPc;

    //
    // The stack pointer (SP) of the previous system call or exception during instrumentation.
    //
    ULONG_PTR InstrumentationCallbackPreviousSp;

#ifdef _WIN64
    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Indicates the state of the system call or exception instrumentation callback.
    //
    BOOLEAN InstrumentationCallbackDisabled;

#ifdef _WIN64
    //
    // Indicates the state of alignment exceptions for unaligned load/store operations.
    //
    BOOLEAN UnalignedLoadStoreExceptions;
#endif

#ifndef _WIN64
    //
    // SpareBytes.
    //
    UCHAR SpareBytes[23];

    //
    // The miniversion ID of the current transacted file operation.
    //
    ULONG TxFsContext;
#endif

    //
    // Reserved for GDI.
    //
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;

    //
    // Reserved for User32.
    //
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];

    //
    // Reserved for opengl32.dll
    //
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    //
    // The previous status value for this thread.
    //
    NTSTATUS LastStatusValue;

    //
    // A static string for use by the application.
    //
    UNICODE_STRING StaticUnicodeString;

    //
    // A static buffer for use by the application.
    //
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

    //
    // The maximum stack size and indicates the base of the stack.
    //
    PVOID DeallocationStack;

    //
    // Data for Thread Local Storage. (TlsGetValue)
    //
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];

    //
    // Reserved.
    //
    LIST_ENTRY TlsLinks;

    //
    // Reserved for NTVDM.
    //
    PVOID Vdm;

    //
    // Reserved.
    //
    PVOID ReservedForNtRpc;

    //
    // Reserved.
    //
    PVOID DbgSsReserved[2];

    //
    // The error mode for the current thread. (GetThreadErrorMode)
    //
    ULONG HardErrorMode;

    //
    // Reserved.
    //
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif

    //
    // Reserved.
    //
    GUID ActivityId;

    //
    // The service creating the thread (svchost).
    //
    PVOID SubProcessTag;

    //
    // Reserved.
    //
    PVOID PerflibData;

    //
    // Reserved.
    //
    PVOID EtwTraceData;

    //
    // The address of a socket handle during a blocking socket operation. (WSAStartup)
    //
    HANDLE WinSockData;

    //
    // The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    //
    ULONG GdiBatchCount;

    //
    // The preferred processor for the curremt thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    //
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    //
    // The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    //
    ULONG GuaranteedStackBytes;

    //
    // Reserved.
    //
    PVOID ReservedForPerf;

    //
    // tagSOleTlsData.
    //
    PVOID ReservedForOle;

    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID *TlsExpansionSlots;
#ifdef _WIN64
    PVOID ChpeV2CpuAreaInfo; // CHPEV2_CPUAREA_INFO // previously DeallocationBStore
    PVOID Unused; // previously BStoreLimit
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;

    //
    // Reserved for FLS (RtlProcessFlsData).
    //
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter; // Win11
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
    PVOID SchedulerSharedDataSlot; // 24H2
    PVOID HeapWalkContext;
    GROUP_AFFINITY PrimaryGroupAffinity;
    ULONG Rcu[2];
} TEB, *PTEB;

typedef VOID (NTAPI* PPS_APC_ROUTINE)(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
);

typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation, // MEMORY_PREFETCH_INFORMATION
    VmPagePriorityInformation, // MEMORY_PAGE_PRIORITY_INFORMATION
    VmCfgCallTargetInformation, // CFG_CALL_TARGET_LIST_INFORMATION // REDSTONE2
    VmPageDirtyStateInformation, // REDSTONE3
    VmImageHotPatchInformation, // 19H1
    VmPhysicalContiguityInformation, // 20H1
    VmVirtualMachinePrepopulateInformation,
    VmRemoveFromWorkingSetInformation,
    MaxVmInfoClass
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

/* ========== [ Expands ] ========== */

#define NtCurrentProcess() ( (HANDLE) (LONG_PTR)-1 )
#define NtCurrentThread()  ( (HANDLE) (LONG_PTR)-2 )

#define NtCurrentPeb() ( NtCurrentTeb()->ProcessEnvironmentBlock )

#define NT_SUCCESS( Status )  ( ( (NTSTATUS) (Status) ) >= 0 )

/* ========== [ Functions ] ========== */

NTSYSAPI ULONG    NTAPI DbgPrint( PCSTR Format, ... );
NTSYSAPI NTSTATUS NTAPI NtClose( _In_ HANDLE Handle );
NTSYSAPI PVOID    NTAPI RtlAllocateHeap( _In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size );
NTSYSAPI PVOID    NTAPI RtlReAllocateHeap( _In_ PVOID HeapHandle, _In_ ULONG Flags, PVOID BaseAddress, _In_ SIZE_T Size );
NTSYSAPI ULONG    NTAPI RtlFreeHeap( _In_ PVOID HeapHandle, _In_opt_ ULONG Flags, PVOID BaseAddress );
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory( _In_ HANDLE ProcessHandle, _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG PageProtection );
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory( _In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer, _In_ SIZE_T NumberOfBytesToWrite, _Out_opt_ PSIZE_T NumberOfBytesWritten );
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory( _In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG FreeType );
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory( _In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress, _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtection, _Out_ PULONG OldProtection );
NTSYSAPI NTSTATUS NTAPI NtCreateSection( _Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection, _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle );
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection( _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize, _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG PageProtection );
// NTSYSAPI void     NTAPI RtlCopyMemory( void* Destination, const void* Source, size_t Length );
// NTSYSAPI void     NTAPI RtlFillMemory( void* Destination, size_t Length, int Fill );
NTSYSAPI NTSTATUS NTAPI NtOpenProcess( _Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId );
NTSYSAPI NTSTATUS NTAPI NtOpenThread( _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PCLIENT_ID ClientId );
NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx( _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PUSER_THREAD_START_ROUTINE StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_ SIZE_T ZeroBits, _In_ SIZE_T StackSize, _In_ SIZE_T MaximumStackSize, _In_opt_ PPS_ATTRIBUTE_LIST AttributeList );
NTSYSAPI VOID     NTAPI RtlExitUserThread( _In_ NTSTATUS ExitStatus ); 
NTSYSAPI VOID     NTAPI RtlExitUserProcess( _In_ NTSTATUS ExitStatus );
NTSYSAPI NTSTATUS NTAPI NtGetContextThread( _In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext );
NTSYSAPI NTSTATUS NTAPI NtSetContextThread( _In_ HANDLE ThreadHandle, _In_ PCONTEXT ThreadContext );
NTSYSAPI NTSTATUS NTAPI NtCreateEvent( _Out_ PHANDLE EventHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ EVENT_TYPE EventType, _In_ BOOLEAN InitialState );
NTSYSAPI NTSTATUS NTAPI NtContinue( _In_ PCONTEXT ContextRecord, _In_ BOOLEAN TestAlert );
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject( _In_ HANDLE Handle, _In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER Timeout );
NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject( _In_ HANDLE SignalHandle, _In_ HANDLE WaitHandle, _In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER Timeout );
NTSYSAPI NTSTATUS NTAPI NtTestAlert( VOID );
NTSYSAPI NTSTATUS NTAPI NtAlertResumeThread( _In_ HANDLE ThreadHandle, _Out_opt_ PULONG PreviousSuspendCount );
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread( _In_ HANDLE ThreadHandle, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID ApcArgument1, _In_opt_ PVOID ApcArgument2, _In_opt_ PVOID ApcArgument3 );
NTSYSAPI NTSTATUS NTAPI RtlCreateTimer( _In_ HANDLE TimerQueueHandle, _Out_ PHANDLE Handle, _In_ WAITORTIMERCALLBACKFUNC Function, _In_opt_ PVOID Context, _In_ ULONG DueTime, _In_ ULONG Period, _In_ ULONG Flags );
NTSYSAPI NTSTATUS NTAPI RtlCreateTimerQueue( _Out_ PHANDLE TimerQueueHandle );
NTSYSAPI NTSTATUS NTAPI NtSetInformationVirtualMemory( _In_ HANDLE ProcessHandle, _In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, _In_ SIZE_T NumberOfEntries, _In_reads_(NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses, _In_reads_bytes_(VmInformationLength) PVOID VmInformation, _In_ ULONG VmInformationLength );
NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress( HMODULE ModuleHandle, PANSI_STRING FunctionName OPTIONAL, WORD Oridinal, PVOID *FunctionAddress );
NTSYSAPI NTSTATUS NTAPI LdrLoadDll( PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle );

#endif // WIN32_H          