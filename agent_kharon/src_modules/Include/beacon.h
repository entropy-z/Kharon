#pragma once
#include <windows.h>

#define CALLBACK_NO_PRE_MSG  0x4f
#define CALLBACK_OUTPUT      0x0
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

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

typedef struct {
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    ULONG   Reserved1;
    PVOID   Reserved2;
} PACKAGE, *PPACKAGE;


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

    DECLSPEC_IMPORT VOID BeaconPkgBytes( PBYTE Buffer, ULONG Length );
    DECLSPEC_IMPORT VOID BeaconPkgInt8( INT8 Data );
    DECLSPEC_IMPORT VOID BeaconPkgInt16( INT16 Data );
    DECLSPEC_IMPORT VOID BeaconPkgInt32( INT32 Data );
    DECLSPEC_IMPORT VOID BeaconPkgInt64( INT64 Data );

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