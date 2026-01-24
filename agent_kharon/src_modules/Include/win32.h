#ifndef WIN32_H
#define WIN32_H

#include <windows.h>

#define nt_success( status )  ( ( (NTSTATUS) (status) ) >= 0 )

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,                        // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits,                             // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters,                              // q: IO_COUNTERS
    ProcessVmCounters,                              // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes,                                   // q: KERNEL_USER_TIMES
    ProcessBasePriority,                            // s: KPRIORITY
    ProcessRaisePriority,                           // s: ULONG
    ProcessDebugPort,                               // q: HANDLE
    ProcessExceptionPort,                           // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken,                             // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation,                          // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize,                                 // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode,                    // qs: ULONG
    ProcessIoPortHandlers,                          // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
    ProcessPooledUsageAndLimits,                    // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch,                         // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,                            // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup,               // s: BOOLEAN
    ProcessPriorityClass,                           // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,                         // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount,                             // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask,                            // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost,                           // qs: ULONG
    ProcessDeviceMap,                               // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation,                      // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation,                   // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information,                        // q: ULONG_PTR
    ProcessImageFileName,                           // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled,                   // q: ULONG
    ProcessBreakOnTermination,                      // qs: ULONG
    ProcessDebugObjectHandle,                       // q: HANDLE // 30
    ProcessDebugFlags,                              // qs: ULONG
    ProcessHandleTracing,                           // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority,                              // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags,                            // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation,                          // qs: PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie,                                  // q: ULONG
    ProcessImageInformation,                        // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime,                               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority,                            // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback,                 // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation,                   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx,                       // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32,                      // q: UNICODE_STRING
    ProcessImageFileMapping,                        // q: HANDLE (input)
    ProcessAffinityUpdateMode,                      // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode,                    // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation,                        // q: USHORT[]
    ProcessTokenVirtualizationEnabled,              // s: ULONG
    ProcessConsoleHostProcess,                      // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation,                       // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation,                       // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy,                        // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,         // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode,                      // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount,                          // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles,                       // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl,                       // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable,                             // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,                   // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation,                  // q: UNICODE_STRING // 60
    ProcessProtectionInformation,                   // q: PS_PROTECTION
    ProcessMemoryExhaustion,                        // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation,                        // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation,                  // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation,                // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
    ProcessAllowedCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
    ProcessSubsystemProcess,                        // s: void // EPROCESS->SubsystemProcess
    ProcessJobMemoryInformation,                    // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate,                               // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose,    // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,                    // q: PROCESS_IUM_CHALLENGE_RESPONSE
    ProcessChildProcessInformation,                 // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation,         // q: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation,                    // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues,                            // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
    ProcessPowerThrottlingState,                    // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessActivityThrottlePolicy,                  // qs: PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
    ProcessWin32kSyscallFilterInformation,          // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets,             // s: BOOLEAN // 80
    ProcessWakeInformation,                         // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
    ProcessEnergyTrackingState,                     // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory,          // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,                 // q: ULONG
    ProcessTelemetryCoverage,                       // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging,                // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation,                       // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection,                            // q: HANDLE
    ProcessDebugAuthInformation,                    // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
    ProcessSystemResourceManagement,                // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber,                          // q: ULONGLONG
    ProcessLoaderDetour,                            // qs: Obsolete // since RS5
    ProcessSecurityDomainInformation,               // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation,       // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging,                           // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation,                   // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation,              // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation,          // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation,                // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets,            // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges,      // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange,                       // s: Obsolete // since WIN11
    ProcessApplyStateChange,                        // s: Obsolete
    ProcessEnableOptionalXStateFeatures,            // s: ULONG64 // EnableProcessOptionalXStateFeatures
    ProcessAltPrefetchParam,                        // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,                     // s: HANDLE
    ProcessPriorityClassEx,                         // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation,                   // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority,                     // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority,                   // q: ULONG
    ProcessSchedulerSharedData,                     // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters,                       // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue,               // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
    ProcessEnclaveAddressSpaceRestriction,          // qs: // since 25H2
    ProcessAvailableCpus,                           // q: PROCESS_AVAILABLE_CPUS_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;  // The version of the instrumentation callback information.
    ULONG Reserved; // Reserved for future use.
    PVOID Callback; // Pointer to the callback function.
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef struct _PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY2
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG AssemblyManifestRedirectionTrust : 1;
            ULONG ReservedFlags : 31;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY2, *PPROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY2;

typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
    PROCESS_MITIGATION_POLICY Policy;
    union
    {
        PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
        PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
        PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY UserShadowStackPolicy;
        PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;
        PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY UserPointerAuthPolicy;
        PROCESS_MITIGATION_SEHOP_POLICY SEHOPPolicy;
        PROCESS_MITIGATION_ACTIVATION_CONTEXT_TRUST_POLICY2 ActivationContextTrustPolicy;
    };
} PROCESS_MITIGATION_POLICY_INFORMATION, *PPROCESS_MITIGATION_POLICY_INFORMATION;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;         // The value of the handle.
    SIZE_T HandleCount;         // The number of references to the handle.
    SIZE_T PointerCount;        // The number of pointers to the handle.
    ACCESS_MASK GrantedAccess;  // The access rights granted to the handle.
    ULONG ObjectTypeIndex;      // The index of the object type.
    ULONG HandleAttributes;     // The attributes of the handle.
    ULONG Reserved;             // Reserved for future use.
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _LEAP_SECOND_DATA *PLEAP_SECOND_DATA;

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

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCH    Buffer;
} STRING, *PSTRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
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

typedef _Function_class_(FN_DISPATCH)
NTSTATUS NTAPI FN_DISPATCH(
    _In_opt_ PVOID Context
);

typedef FN_DISPATCH* PFN_DISPATCH;

typedef struct _KERNEL_CALLBACK_TABLE
{
    PFN_DISPATCH __fnCOPYDATA;
    PFN_DISPATCH __fnCOPYGLOBALDATA;
    PFN_DISPATCH __fnEMPTY1;
    PFN_DISPATCH __fnNCDESTROY;
    PFN_DISPATCH __fnDWORDOPTINLPMSG;
    PFN_DISPATCH __fnINOUTDRAG;
    PFN_DISPATCH __fnGETTEXTLENGTHS1;
    PFN_DISPATCH __fnINCNTOUTSTRING;
    PFN_DISPATCH __fnINCNTOUTSTRINGNULL;
    PFN_DISPATCH __fnINLPCOMPAREITEMSTRUCT;
    PFN_DISPATCH __fnINLPCREATESTRUCT;
    PFN_DISPATCH __fnINLPDELETEITEMSTRUCT;
    PFN_DISPATCH __fnINLPDRAWITEMSTRUCT;
    PFN_DISPATCH __fnPOPTINLPUINT1;
    PFN_DISPATCH __fnPOPTINLPUINT2;
    PFN_DISPATCH __fnINLPMDICREATESTRUCT;
    PFN_DISPATCH __fnINOUTLPMEASUREITEMSTRUCT;
    PFN_DISPATCH __fnINLPWINDOWPOS;
    PFN_DISPATCH __fnINOUTLPPOINT51;
    PFN_DISPATCH __fnINOUTLPSCROLLINFO;
    PFN_DISPATCH __fnINOUTLPRECT;
    PFN_DISPATCH __fnINOUTNCCALCSIZE;
    PFN_DISPATCH __fnINOUTLPPOINT52;
    PFN_DISPATCH __fnINPAINTCLIPBRD;
    PFN_DISPATCH __fnINSIZECLIPBRD;
    PFN_DISPATCH __fnINDESTROYCLIPBRD;
    PFN_DISPATCH __fnINSTRINGNULL1;
    PFN_DISPATCH __fnINSTRINGNULL2;
    PFN_DISPATCH __fnINDEVICECHANGE;
    PFN_DISPATCH __fnPOWERBROADCAST;
    PFN_DISPATCH __fnINLPUAHDRAWMENU1;
    PFN_DISPATCH __fnOPTOUTLPDWORDOPTOUTLPDWORD1;
    PFN_DISPATCH __fnOPTOUTLPDWORDOPTOUTLPDWORD2;
    PFN_DISPATCH __fnOUTDWORDINDWORD;
    PFN_DISPATCH __fnOUTLPRECT;
    PFN_DISPATCH __fnOUTSTRING;
    PFN_DISPATCH __fnPOPTINLPUINT3;
    PFN_DISPATCH __fnPOUTLPINT;
    PFN_DISPATCH __fnSENTDDEMSG;
    PFN_DISPATCH __fnINOUTSTYLECHANGE1;
    PFN_DISPATCH __fnHkINDWORD;
    PFN_DISPATCH __fnHkINLPCBTACTIVATESTRUCT;
    PFN_DISPATCH __fnHkINLPCBTCREATESTRUCT;
    PFN_DISPATCH __fnHkINLPDEBUGHOOKSTRUCT;
    PFN_DISPATCH __fnHkINLPMOUSEHOOKSTRUCTEX1;
    PFN_DISPATCH __fnHkINLPKBDLLHOOKSTRUCT;
    PFN_DISPATCH __fnHkINLPMSLLHOOKSTRUCT;
    PFN_DISPATCH __fnHkINLPMSG;
    PFN_DISPATCH __fnHkINLPRECT;
    PFN_DISPATCH __fnHkOPTINLPEVENTMSG;
    PFN_DISPATCH __xxxClientCallDelegateThread;
    PFN_DISPATCH __ClientCallDummyCallback1;
    PFN_DISPATCH __ClientCallDummyCallback2;
    PFN_DISPATCH __fnSHELLWINDOWMANAGEMENTCALLOUT;
    PFN_DISPATCH __fnSHELLWINDOWMANAGEMENTNOTIFY;
    PFN_DISPATCH __ClientCallDummyCallback3;
    PFN_DISPATCH __xxxClientCallDitThread;
    PFN_DISPATCH __xxxClientEnableMMCSS;
    PFN_DISPATCH __xxxClientUpdateDpi;
    PFN_DISPATCH __xxxClientExpandStringW;
    PFN_DISPATCH __ClientCopyDDEIn1;
    PFN_DISPATCH __ClientCopyDDEIn2;
    PFN_DISPATCH __ClientCopyDDEOut1;
    PFN_DISPATCH __ClientCopyDDEOut2;
    PFN_DISPATCH __ClientCopyImage;
    PFN_DISPATCH __ClientEventCallback;
    PFN_DISPATCH __ClientFindMnemChar;
    PFN_DISPATCH __ClientFreeDDEHandle;
    PFN_DISPATCH __ClientFreeLibrary;
    PFN_DISPATCH __ClientGetCharsetInfo;
    PFN_DISPATCH __ClientGetDDEFlags;
    PFN_DISPATCH __ClientGetDDEHookData;
    PFN_DISPATCH __ClientGetListboxString;
    PFN_DISPATCH __ClientGetMessageMPH;
    PFN_DISPATCH __ClientLoadImage;
    PFN_DISPATCH __ClientLoadLibrary;
    PFN_DISPATCH __ClientLoadMenu;
    PFN_DISPATCH __ClientLoadLocalT1Fonts;
    PFN_DISPATCH __ClientPSMTextOut;
    PFN_DISPATCH __ClientLpkDrawTextEx;
    PFN_DISPATCH __ClientExtTextOutW;
    PFN_DISPATCH __ClientGetTextExtentPointW;
    PFN_DISPATCH __ClientCharToWchar;
    PFN_DISPATCH __ClientAddFontResourceW;
    PFN_DISPATCH __ClientThreadSetup;
    PFN_DISPATCH __ClientDeliverUserApc;
    PFN_DISPATCH __ClientNoMemoryPopup;
    PFN_DISPATCH __ClientMonitorEnumProc;
    PFN_DISPATCH __ClientCallWinEventProc;
    PFN_DISPATCH __ClientWaitMessageExMPH;
    PFN_DISPATCH __ClientCallDummyCallback4;
    PFN_DISPATCH __ClientCallDummyCallback5;
    PFN_DISPATCH __ClientImmLoadLayout;
    PFN_DISPATCH __ClientImmProcessKey;
    PFN_DISPATCH __fnIMECONTROL;
    PFN_DISPATCH __fnINWPARAMDBCSCHAR;
    PFN_DISPATCH __fnGETTEXTLENGTHS2;
    PFN_DISPATCH __ClientCallDummyCallback6;
    PFN_DISPATCH __ClientLoadStringW;
    PFN_DISPATCH __ClientLoadOLE;
    PFN_DISPATCH __ClientRegisterDragDrop;
    PFN_DISPATCH __ClientRevokeDragDrop;
    PFN_DISPATCH __fnINOUTMENUGETOBJECT;
    PFN_DISPATCH __ClientPrinterThunk;
    PFN_DISPATCH __fnOUTLPCOMBOBOXINFO;
    PFN_DISPATCH __fnOUTLPSCROLLBARINFO;
    PFN_DISPATCH __fnINLPUAHDRAWMENU2;
    PFN_DISPATCH __fnINLPUAHDRAWMENUITEM;
    PFN_DISPATCH __fnINLPUAHDRAWMENU3;
    PFN_DISPATCH __fnINOUTLPUAHMEASUREMENUITEM;
    PFN_DISPATCH __fnINLPUAHDRAWMENU4;
    PFN_DISPATCH __fnOUTLPTITLEBARINFOEX;
    PFN_DISPATCH __fnTOUCH;
    PFN_DISPATCH __fnGESTURE;
    PFN_DISPATCH __fnPOPTINLPUINT4;
    PFN_DISPATCH __fnPOPTINLPUINT5;
    PFN_DISPATCH __xxxClientCallDefaultInputHandler;
    PFN_DISPATCH __fnEMPTY2;
    PFN_DISPATCH __ClientRimDevCallback;
    PFN_DISPATCH __xxxClientCallMinTouchHitTestingCallback;
    PFN_DISPATCH __ClientCallLocalMouseHooks;
    PFN_DISPATCH __xxxClientBroadcastThemeChange;
    PFN_DISPATCH __xxxClientCallDevCallbackSimple;
    PFN_DISPATCH __xxxClientAllocWindowClassExtraBytes;
    PFN_DISPATCH __xxxClientFreeWindowClassExtraBytes;
    PFN_DISPATCH __fnGETWINDOWDATA;
    PFN_DISPATCH __fnINOUTSTYLECHANGE2;
    PFN_DISPATCH __fnHkINLPMOUSEHOOKSTRUCTEX2;
    PFN_DISPATCH __xxxClientCallDefWindowProc;
    PFN_DISPATCH __fnSHELLSYNCDISPLAYCHANGED;
    PFN_DISPATCH __fnHkINLPCHARHOOKSTRUCT;
    PFN_DISPATCH __fnINTERCEPTEDWINDOWACTION;
    PFN_DISPATCH __xxxTooltipCallback;
    PFN_DISPATCH __xxxClientInitPSBInfo;
    PFN_DISPATCH __xxxClientDoScrollMenu;
    PFN_DISPATCH __xxxClientEndScroll;
    PFN_DISPATCH __xxxClientDrawSize;
    PFN_DISPATCH __xxxClientDrawScrollBar;
    PFN_DISPATCH __xxxClientHitTestScrollBar;
    PFN_DISPATCH __xxxClientTrackInit;
} KERNEL_CALLBACK_TABLE, *PKERNEL_CALLBACK_TABLE;

typedef struct _API_SET_NAMESPACE
{
    ULONG Version; // API_SET_SCHEMA_VERSION_V6
    ULONG Size;
    ULONG Flags; // API_SET_SCHEMA_FLAGS_*
    ULONG Count;
    ULONG EntryOffset; // to API_SET_NAMESPACE_ENTRY[Count], from this struct base
    ULONG HashOffset; // to API_SET_HASH_ENTRY[Count], from this struct base
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef struct _SILO_USER_SHARED_DATA
{
    ULONG ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForegroundProcessId;
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

#define MAXIMUM_LEADBYTES 12

typedef struct _CPTABLEINFO
{
    USHORT CodePage;                        // Specifies the code page number.
    USHORT MaximumCharacterSize;            // Specifies the maximum length in bytes of a character.
    USHORT DefaultChar;                     // Specifies the default character (MB).
    USHORT UniDefaultChar;                  // Specifies the default character (Unicode).
    USHORT TransDefaultChar;                // Specifies the translation of the default character (Unicode).
    USHORT TransUniDefaultChar;             // Specifies the translation of the Unicode default character (MB).
    USHORT DBCSCodePage;                    // Specifies non-zero for DBCS code pages.
    UCHAR LeadByte[MAXIMUM_LEADBYTES];      // Specifies the lead byte ranges.
    PUSHORT MultiByteTable;                 // Specifies a pointer to a MB translation table.
    PVOID WideCharTable;                    // Specifies a pointer to a WC translation table.
    PUSHORT DBCSRanges;                     // Specifies a pointer to DBCS ranges.
    PUSHORT DBCSOffsets;                    // Specifies a pointer to DBCS offsets.
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO
{
    CPTABLEINFO OemTableInfo;               // Specifies OEM table.
    CPTABLEINFO AnsiTableInfo;              // Specifies an ANSI table.
    PUSHORT UpperCaseTable;                 // Specifies an 844 format uppercase table.
    PUSHORT LowerCaseTable;                 // Specifies an 844 format lowercase table.
} NLSTABLEINFO, *PNLSTABLEINFO;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];


typedef struct tagSDBQUERYRESULT
{
    ULONG Exes[16];
    ULONG ExeFlags[16];
    ULONG Layers[8];
    ULONG LayerFlags;
    ULONG AppHelp;
    ULONG ExeCount;
    ULONG LayerCount;
    GUID ID;
    ULONG ExtraFlags;
    ULONG CustomSDBMap;
    GUID DB[16];
} SDBQUERYRESULT, *PSDBQUERYRESULT;

typedef struct _AFD_SWITCH_CONTEXT
{
    LONG EventsActive;
    LONG RcvCount;
    LONG ExpCount;
    LONG SndCount;
    BOOLEAN SelectFlag;
} AFD_SWITCH_CONTEXT, *PAFD_SWITCH_CONTEXT;

typedef struct tagSWITCH_CONTEXT_ATTRIBUTE
{
    ULONG_PTR ContextUpdateCounter;
    BOOL AllowContextUpdate;
    BOOL EnableTrace;
    HANDLE EtwHandle;
} SWITCH_CONTEXT_ATTRIBUTE, *PSWITCH_CONTEXT_ATTRIBUTE;

typedef struct tagSWITCH_CONTEXT_DATA
{
    ULONGLONG OsMaxVersionTested;
    ULONG TargetPlatform;
    ULONGLONG ContextMinimum;
    GUID Platform;
    GUID MinPlatform;
    ULONG ContextSource;
    ULONG ElementCount;
    GUID Elements[48];
} SWITCH_CONTEXT_DATA, * PSWITCH_CONTEXT_DATA;

typedef struct tagSWITCH_CONTEXT
{
    SWITCH_CONTEXT_ATTRIBUTE Attribute;
    SWITCH_CONTEXT_DATA Data;
} SWITCH_CONTEXT, *PSWITCH_CONTEXT;

typedef struct _SDB_CSTRUCT_COBALT_PROCFLAG
{
    KAFFINITY AffinityMask;
    ULONG CPUIDEcxOverride;
    ULONG CPUIDEdxOverride;
    USHORT ProcessorGroup;
    USHORT FastSelfModThreshold;
    USHORT Reserved1;
    UCHAR Reserved2;
    UCHAR BackgroundWork : 5;
    UCHAR CPUIDBrand : 4;
    UCHAR Reserved3 : 4;
    UCHAR RdtscScaling : 3;
    UCHAR Reserved4 : 2;
    UCHAR UnalignedAtomicApproach : 2;
    UCHAR Win11Atomics : 2;
    UCHAR RunOnSingleCore : 1;
    UCHAR X64CPUID : 1;
    UCHAR PatchUnaligned : 1;
    UCHAR InterpreterOrJitter : 1;
    UCHAR ForceSegmentHeap : 1;
    UCHAR Reserved5 : 1;
    UCHAR Reserved6 : 1;
    union
    {
        ULONGLONG Group1AsUINT64;
        struct _SDB_CSTRUCT_COBALT_PROCFLAG* Specified;
    };
} SDB_CSTRUCT_COBALT_PROCFLAG, *PSDB_CSTRUCT_COBALT_PROCFLAG;

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _WER_RECOVERY_INFO
{
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

typedef struct _WER_METADATA
{
    PVOID Next;
    WCHAR Key[64];
    WCHAR Value[128];
} WER_METADATA, *PWER_METADATA;

typedef struct _WER_FILE
{
    USHORT Flags;
    WCHAR Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

typedef struct _WER_MEMORY
{
    PVOID Address;
    ULONG Size;
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER
{
    PVOID Next;
    USHORT Flags;
    union
    {
      WER_FILE File;
      WER_MEMORY Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

typedef struct _WER_RUNTIME_DLL
{
    PVOID Next;
    ULONG Length;
    PVOID Context;
    WCHAR CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

typedef struct _WER_DUMP_COLLECTION
{
    PVOID Next;
    ULONG ProcessId;
    ULONG ThreadId;
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_HEAP_MAIN_HEADER
{
    WCHAR Signature[16];
    LIST_ENTRY Links;
    HANDLE Mutex;
    PVOID FreeHeap;
    ULONG FreeCount;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

typedef struct _WER_PEB_HEADER_BLOCK
{
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

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

// typedef struct _APPCOMPAT_EXE_DATA
// {
//     ULONG_PTR Reserved[65];
//     ULONG Size;
//     ULONG Magic;
//     BOOL LoadShimEngine;
//     USHORT ExeType;
//     SDBQUERYRESULT SdbQueryResult;
//     ULONG_PTR DbgLogChannels[128];
//     SWITCH_CONTEXT SwitchContext;
//     ULONG ParentProcessId;
//     WCHAR ParentImageName[260];
//     WCHAR ParentCompatLayers[256];
//     WCHAR ActiveCompatLayers[256];
//     ULONG ImageFileSize;
//     ULONG ImageCheckSum;
//     BOOL LatestOs;
//     BOOL PackageId;
//     BOOL SwitchBackManifest;
//     BOOL UacManifest;
//     BOOL LegacyInstaller;
//     ULONG RunLevel;
//     ULONG_PTR WinRTFlags;
//     PVOID HookCOM;
//     PVOID ComponentOnDemandEvent;
//     PVOID Quirks;
//     ULONG QuirksSize;
//     SDB_CSTRUCT_COBALT_PROCFLAG CobaltProcFlags;
//     ULONG FullMatchDbSizeCb;
//     ULONG FullMatchDbOffset;
// } APPCOMPAT_EXE_DATA;

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

typedef struct _APPCOMPAT_EXE_DATA
{
    ULONG_PTR Reserved[65];
    ULONG Size;
    ULONG Magic;
    BOOL LoadShimEngine;
    USHORT ExeType;
    SDBQUERYRESULT SdbQueryResult;
    ULONG_PTR DbgLogChannels[128];
    SWITCH_CONTEXT SwitchContext;
    ULONG ParentProcessId;
    WCHAR ParentImageName[260];
    WCHAR ParentCompatLayers[256];
    WCHAR ActiveCompatLayers[256];
    ULONG ImageFileSize;
    ULONG ImageCheckSum;
    BOOL LatestOs;
    BOOL PackageId;
    BOOL SwitchBackManifest;
    BOOL UacManifest;
    BOOL LegacyInstaller;
    ULONG RunLevel;
    ULONG_PTR WinRTFlags;
    PVOID HookCOM;
    PVOID ComponentOnDemandEvent;
    PVOID Quirks;
    ULONG QuirksSize;
    SDB_CSTRUCT_COBALT_PROCFLAG CobaltProcFlags;
    ULONG FullMatchDbSizeCb;
    ULONG FullMatchDbOffset;
} APPCOMPAT_EXE_DATA;

typedef struct _GDI_HANDLE_ENTRY
{
    union
    {
        PVOID Object;
        PVOID NextFree;
    };
    union
    {
        struct
        {
            USHORT ProcessId;
            USHORT Lock : 1;
            USHORT Count : 15;
        };
        ULONG Value;
    } Owner;
    USHORT Unique;
    UCHAR Type;
    UCHAR Flags;
    PVOID UserPointer;
} GDI_HANDLE_ENTRY, *PGDI_HANDLE_ENTRY;

typedef _Function_class_(PS_POST_PROCESS_INIT_ROUTINE)
VOID NTAPI PS_POST_PROCESS_INIT_ROUTINE(
    VOID
);

typedef PS_POST_PROCESS_INIT_ROUTINE* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _PEB
{
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
            BOOLEAN IsAppContainerProcess : 1;          // The process has an AppContainer token.
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
    // Handle to the Image File Execution Options key.
    //
    HANDLE IFEOKey;

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
        PKERNEL_CALLBACK_TABLE KernelCallbackTable;
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
    // Pointer to the ANSI code page data.
    //
    PCPTABLEINFO AnsiCodePageData;

    //
    // Pointer to the OEM code page data.
    //
    PCPTABLEINFO OemCodePageData;

    //
    // Pointer to the Unicode case table data.
    //
    PNLSTABLEINFO UnicodeCaseTableData;

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
    PGDI_HANDLE_ENTRY GdiSharedHandleTable;

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
    // Pointer to the Application Compatibility Engine.
    //
    APPCOMPAT_EXE_DATA* AppCompatInfo;

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
    ULONG AppModelFeatureState;

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
    PVOID ImageHeaderHash;

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
} PEB, *PPEB;

typedef LONG KPRIORITY, *PKPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;                    // The exit status of the process. (GetExitCodeProcess)
    PPEB PebBaseAddress;                    // A pointer to the process environment block (PEB) of the process.
    KAFFINITY AffinityMask;                 // The affinity mask of the process. (GetProcessAffinityMask) (deprecated)
    KPRIORITY BasePriority;                 // The base priority of the process. (GetPriorityClass)
    HANDLE UniqueProcessId;                 // The unique identifier of the process. (GetProcessId)
    HANDLE InheritedFromUniqueProcessId;    // The unique identifier of the parent process.
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION
{
    _In_ SIZE_T Size; // The size of the structure, in bytes. This member must be set to sizeof(PROCESS_EXTENDED_BASIC_INFORMATION).
    union
    {
        PROCESS_BASIC_INFORMATION BasicInfo;
        struct
        {
            NTSTATUS ExitStatus;                    // The exit status of the process. (GetExitCodeProcess)
            PPEB PebBaseAddress;                    // A pointer to the process environment block (PEB) of the process.
            KAFFINITY AffinityMask;                 // The affinity mask of the process. (GetProcessAffinityMask) (deprecated)
            KPRIORITY BasePriority;                 // The base priority of the process. (GetPriorityClass)
            HANDLE UniqueProcessId;                 // The unique identifier of the process. (GetProcessId)
            HANDLE InheritedFromUniqueProcessId;    // The unique identifier of the parent process.
        };
    };
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG IsFrozen : 1;
            ULONG IsBackground : 1; // WIN://BGKD
            ULONG IsStronglyNamed : 1; // WIN://SYSAPPID
            ULONG IsSecureProcess : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG IsTrustedApp : 1; // since 24H2
            ULONG SpareBits : 22;
        };
    };
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength
);

NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(
    _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength
);

NTSYSCALLAPI BOOL WINAPI EnumProcessModules(
  _In_  HANDLE  hProcess, _Out_ HMODULE *lphModule,
  _In_  DWORD   cb, _Out_ LPDWORD lpcbNeeded
);

#endif // WIN32_H