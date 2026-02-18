#ifndef EXTERNS_H
#define EXTERNS_H

#include <win32.h>

#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <wsmandisp.h>
#include <netfw.h>
#include <combaseapi.h>
#include <wbemcli.h>
#include <wlanapi.h>

typedef union _WSMAN_RESPONSE_DATA WSMAN_RESPONSE_DATA;

#define WSMAN_API_VERSION_1_1
#include <wsman.h>

#define DFR(module, function) DECLSPEC_IMPORT decltype(function) module##$##function;

EXTERN_C DECLSPEC_IMPORT INT WINAPI DNSAPI$DnsGetCacheDataTable(PVOID Data);

extern "C" {
    // ==================== WLANAPI ====================
    DFR(WLANAPI, WlanOpenHandle)
    DFR(WLANAPI, WlanEnumInterfaces)
    DFR(WLANAPI, WlanGetProfile)
    DFR(WLANAPI, WlanFreeMemory)
    DFR(WLANAPI, WlanGetProfileList)
    DFR(WLANAPI, WlanCloseHandle)

    // ==================== KERNEL32 ====================
    DFR(KERNEL32, VirtualAlloc)
    DFR(KERNEL32, VirtualAllocEx)
    DFR(KERNEL32, VirtualProtect)
    DFR(KERNEL32, VirtualProtectEx)
    DFR(KERNEL32, VirtualQuery)
    DFR(KERNEL32, VirtualQueryEx)
    DFR(KERNEL32, WriteProcessMemory)
    DFR(KERNEL32, ReadProcessMemory)
    DFR(KERNEL32, LoadLibraryW)

    DFR(KERNEL32, CreateEventW)
    DFR(KERNEL32, SetEvent)

    DFR(KERNEL32, OpenProcess)
    DFR(KERNEL32, GetCurrentProcess)
    DFR(KERNEL32, CreateProcessW)
    DFR(KERNEL32, GetExitCodeProcess)
    DFR(KERNEL32, GetExitCodeThread)
    DFR(KERNEL32, TerminateProcess)
    DFR(KERNEL32, TerminateThread)
    DFR(KERNEL32, GetProcessId)

    DFR(KERNEL32, EnumProcessModules)
    DFR(KERNEL32, GetModuleFileNameW)
    DFR(KERNEL32, K32GetModuleFileNameExA)

    DFR(KERNEL32, GlobalLock)
    DFR(KERNEL32, GlobalUnlock)

    DFR(KERNEL32, CreateThread)
    DFR(KERNEL32, CreateRemoteThread)

    DFR(KERNEL32, InitializeProcThreadAttributeList)
    DFR(KERNEL32, UpdateProcThreadAttribute)
    DFR(KERNEL32, DeleteProcThreadAttributeList)

    DFR(KERNEL32, GetProcessHeap)
    DFR(KERNEL32, GetProcessHeaps)
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, HeapReAlloc)
    DFR(KERNEL32, HeapFree)

    DFR(KERNEL32, DeleteCriticalSection)
    DFR(KERNEL32, EnterCriticalSection)
    DFR(KERNEL32, LeaveCriticalSection)

    DFR(KERNEL32, FileTimeToSystemTime)
    DFR(KERNEL32, CreatePipe)
    DFR(KERNEL32, DuplicateHandle)
    DFR(KERNEL32, CreateFileW)
    DFR(KERNEL32, CreateFileA)
    DFR(KERNEL32, PeekNamedPipe)
    DFR(KERNEL32, SetHandleInformation)
    DFR(KERNEL32, GetFullPathNameW)
    DFR(KERNEL32, CreateDirectoryW)
    DFR(KERNEL32, SetCurrentDirectoryW)
    DFR(KERNEL32, GetFileAttributesW)
    DFR(KERNEL32, GetCurrentDirectoryW)
    DFR(KERNEL32, GetFileSize)
    DFR(KERNEL32, SetStdHandle)
    DFR(KERNEL32, GetStdHandle)
    DFR(KERNEL32, ReadFile)
    DFR(KERNEL32, WriteFile)
    DFR(KERNEL32, CopyFileW)
    DFR(KERNEL32, MoveFileW)
    DFR(KERNEL32, DeleteFileW)
    DFR(KERNEL32, FindFirstFileW)
    DFR(KERNEL32, FindNextFileW)
    DFR(KERNEL32, FindClose)
    DFR(KERNEL32, SetFileInformationByHandle)

    DFR(KERNEL32, IsWow64Process)
    DFR(KERNEL32, WaitForSingleObject)

    DFR(KERNEL32, CloseHandle)
    DFR(KERNEL32, GetLastError)
    DFR(KERNEL32, FormatMessageW)

    DFR(KERNEL32, GetEnvironmentStringsW)
    DFR(KERNEL32, FreeEnvironmentStringsW)
    DFR(KERNEL32, WideCharToMultiByte)
    DFR(KERNEL32, QueryFullProcessImageNameA)

    // ==================== NTDLL ====================
    DFR(NTDLL, DbgPrint)
    DFR(NTDLL, NtQuerySystemInformation)
    DFR(NTDLL, NtSetInformationProcess)
    DFR(NTDLL, NtQueryInformationToken)
    DFR(NTDLL, NtQueryInformationProcess)
    DFR(NTDLL, NtOpenSection)
    DFR(NTDLL, NtCreateSection)
    DFR(NTDLL, NtMapViewOfSection)
    DFR(NTDLL, NtUnmapViewOfSection)
    DFR(NTDLL, NtQueryInformationFile)

    // ==================== ADVAPI32 ====================
    DFR(ADVAPI32, CreateProcessWithLogonW)
    DFR(ADVAPI32, CreateProcessWithTokenW)
    DFR(ADVAPI32, OpenProcessToken)
    DFR(ADVAPI32, AdjustTokenPrivileges)
    DFR(ADVAPI32, LookupPrivilegeValueW)
    DFR(ADVAPI32, LookupAccountSidW)
    DFR(ADVAPI32, OpenSCManagerA)
    DFR(ADVAPI32, CreateServiceA)
    DFR(ADVAPI32, StartServiceA)
    DFR(ADVAPI32, CloseServiceHandle)
    DFR(ADVAPI32, RegOpenKeyExA)
    DFR(ADVAPI32, RegSetValueExA)

    // ==================== MSVCRT ====================
    DFR(MSVCRT, malloc)
    DFR(MSVCRT, realloc)
    DFR(MSVCRT, free)
    DFR(MSVCRT, memset)
    DFR(MSVCRT, memcpy)
    DFR(MSVCRT, memcmp)
    DFR(MSVCRT, wcslen)
    DFR(MSVCRT, wcsncpy)
    DFR(MSVCRT, strlen)
    DFR(MSVCRT, sprintf)
    DFR(MSVCRT, wcsstr)
    DFR(MSVCRT, wcsrchr)
    DFR(MSVCRT, _swprintf)
    DFR(MSVCRT, wcscpy)
    DFR(MSVCRT, wcscat)
    DFR(MSVCRT, wcscmp)
    DFR(MSVCRT, printf)
    DFR(MSVCRT, wprintf)
    DFR(MSVCRT, vsnprintf)

    // ==================== IPHLPAPI ====================
    DFR(IPHLPAPI, GetNetworkParams)
    DFR(IPHLPAPI, GetAdaptersInfo)
    DFR(IPHLPAPI, GetIpForwardTable)

    // ==================== WS2_32 ====================
    DFR(WS2_32, inet_ntoa)

    // ==================== NETAPI32 ====================
    DFR(NETAPI32, NetUserAdd)

    // ==================== OLE32 ====================
    DFR(OLE32, CoInitializeSecurity)
    DFR(OLE32, CoCreateInstance)
    DFR(OLE32, StringFromGUID2)
    DFR(OLE32, CoInitializeEx)
    DFR(OLE32, CoUninitialize)
    DFR(OLE32, CLSIDFromString)
    DFR(OLE32, IIDFromString)
    DFR(OLE32, CoSetProxyBlanket)

    // ==================== OLEAUT32 ====================
    DFR(OLEAUT32, VariantInit)
    DFR(OLEAUT32, VariantClear)
    DFR(OLEAUT32, SysFreeString)
    DFR(OLEAUT32, SysAllocString)

    // ==================== USER32 ====================
    DFR(USER32, GetDC)
    DFR(USER32, ReleaseDC)
    DFR(USER32, OpenClipboard)
    DFR(USER32, GetClipboardData)
    DFR(USER32, CloseClipboard)
    DFR(USER32, GetSystemMetrics)

    // ==================== GDI32 ====================
    DFR(GDI32, BitBlt)
    DFR(GDI32, SelectObject)
    DFR(GDI32, CreateDIBSection)
    DFR(GDI32, CreateCompatibleDC)
    DFR(GDI32, GetObjectW)
    DFR(GDI32, GdiFlush)
    DFR(GDI32, GetCurrentObject)
    DFR(GDI32, DeleteDC)
    DFR(GDI32, DeleteObject)

    // ==================== WSMSVC ====================
    DFR(WSMSVC, WSManInitialize)
    DFR(WSMSVC, WSManCreateSession)
    DFR(WSMSVC, WSManCreateShell)
    DFR(WSMSVC, WSManRunShellCommand)
    DFR(WSMSVC, WSManReceiveShellOutput)
    DFR(WSMSVC, WSManCloseOperation)
    DFR(WSMSVC, WSManCloseCommand)
    DFR(WSMSVC, WSManCloseSession)
    DFR(WSMSVC, WSManDeinitialize)
    DFR(WSMSVC, WSManCloseShell)
}

// ==================== WLANAPI MACROS ====================
#define WlanOpenHandle      WLANAPI$WlanOpenHandle
#define WlanEnumInterfaces  WLANAPI$WlanEnumInterfaces
#define WlanGetProfile      WLANAPI$WlanGetProfile
#define WlanFreeMemory      WLANAPI$WlanFreeMemory
#define WlanGetProfileList  WLANAPI$WlanGetProfileList
#define WlanCloseHandle     WLANAPI$WlanCloseHandle

// ==================== KERNEL32 MACROS ====================
#define VirtualAlloc                      KERNEL32$VirtualAlloc
#define VirtualAllocEx                    KERNEL32$VirtualAllocEx
#define VirtualProtect                    KERNEL32$VirtualProtect
#define VirtualProtectEx                  KERNEL32$VirtualProtectEx
#define ReadProcessMemory                 KERNEL32$ReadProcessMemory
#define WriteProcessMemory                KERNEL32$WriteProcessMemory
#define LoadLibraryW                      KERNEL32$LoadLibraryW

#define VirtualQuery    KERNEL32$VirtualQuery
#define VirtualQueryEx  KERNEL32$VirtualQueryEx

#define CreateEventW                      KERNEL32$CreateEventW
#define SetEvent                          KERNEL32$SetEvent

#define OpenProcess                       KERNEL32$OpenProcess
#define GetCurrentProcess                 KERNEL32$GetCurrentProcess
#define CreateProcessW                    KERNEL32$CreateProcessW
#define GetExitCodeProcess                KERNEL32$GetExitCodeProcess
#define GetExitCodeThread                 KERNEL32$GetExitCodeThread
#define TerminateThread                   KERNEL32$TerminateThread
#define TerminateProcess                  KERNEL32$TerminateProcess
#define GetProcessId                      KERNEL32$GetProcessId

#define EnumProcessModules                KERNEL32$EnumProcessModules
#define GetModuleFileNameW                KERNEL32$GetModuleFileNameW

#define CreateThread                      KERNEL32$CreateThread
#define CreateRemoteThread                KERNEL32$CreateRemoteThread

#define InitializeProcThreadAttributeList KERNEL32$InitializeProcThreadAttributeList
#define UpdateProcThreadAttribute         KERNEL32$UpdateProcThreadAttribute
#define DeleteProcThreadAttributeList     KERNEL32$DeleteProcThreadAttributeList

#define GetProcessHeap                    KERNEL32$GetProcessHeap
#define GetProcessHeaps                   KERNEL32$GetProcessHeaps
#define HeapAlloc                         KERNEL32$HeapAlloc
#define HeapReAlloc                       KERNEL32$HeapReAlloc
#define HeapFree                          KERNEL32$HeapFree

#define DeleteCriticalSection             KERNEL32$DeleteCriticalSection
#define EnterCriticalSection              KERNEL32$EnterCriticalSection
#define LeaveCriticalSection              KERNEL32$LeaveCriticalSection

#define GlobalLock      KERNEL32$GlobalLock
#define GlobalUnlock    KERNEL32$GlobalUnlock

#define FileTimeToSystemTime              KERNEL32$FileTimeToSystemTime
#define CreatePipe                        KERNEL32$CreatePipe
#define DuplicateHandle                   KERNEL32$DuplicateHandle
#define CreateFileW                       KERNEL32$CreateFileW
#define CreateFileA                       KERNEL32$CreateFileA
#define PeekNamedPipe                     KERNEL32$PeekNamedPipe
#define SetHandleInformation              KERNEL32$SetHandleInformation
#define GetFullPathNameW                  KERNEL32$GetFullPathNameW
#define CreateDirectoryW                  KERNEL32$CreateDirectoryW
#define SetCurrentDirectoryW              KERNEL32$SetCurrentDirectoryW
#define GetFileAttributesW                KERNEL32$GetFileAttributesW
#define GetCurrentDirectoryW              KERNEL32$GetCurrentDirectoryW
#define GetFileSize                       KERNEL32$GetFileSize
#define SetStdHandle                      KERNEL32$SetStdHandle
#define GetStdHandle                      KERNEL32$GetStdHandle
#define ReadFile                          KERNEL32$ReadFile
#define WriteFile                         KERNEL32$WriteFile
#define CopyFileW                         KERNEL32$CopyFileW
#define MoveFileW                         KERNEL32$MoveFileW
#define DeleteFileW                       KERNEL32$DeleteFileW
#define FindFirstFileW                    KERNEL32$FindFirstFileW
#define FindNextFileW                     KERNEL32$FindNextFileW
#define FindClose                         KERNEL32$FindClose
#define SetFileInformationByHandle        KERNEL32$SetFileInformationByHandle

#define IsWow64Process                    KERNEL32$IsWow64Process
#define WaitForSingleObject               KERNEL32$WaitForSingleObject

#define CloseHandle                       KERNEL32$CloseHandle
#define GetLastError                      KERNEL32$GetLastError
#define FormatMessageW                    KERNEL32$FormatMessageW

#define GetEnvironmentStringsW            KERNEL32$GetEnvironmentStringsW
#define FreeEnvironmentStringsW           KERNEL32$FreeEnvironmentStringsW
#define WideCharToMultiByte               KERNEL32$WideCharToMultiByte
#define QueryFullProcessImageNameA        KERNEL32$QueryFullProcessImageNameA

// ==================== NTDLL MACROS ====================
#define DbgPrint                          NTDLL$DbgPrint
#define NtQuerySystemInformation          NTDLL$NtQuerySystemInformation
#define NtSetInformationProcess           NTDLL$NtSetInformationProcess
#define NtQueryInformationToken           NTDLL$NtQueryInformationToken
#define NtQueryInformationProcess         NTDLL$NtQueryInformationProcess
#define NtOpenSection                     NTDLL$NtOpenSection
#define NtCreateSection                   NTDLL$NtCreateSection
#define NtMapViewOfSection                NTDLL$NtMapViewOfSection
#define NtUnmapViewOfSection              NTDLL$NtUnmapViewOfSection
#define NtQueryInformationFile            NTDLL$NtQueryInformationFile

// ==================== ADVAPI32 MACROS ====================
#define CreateProcessWithLogonW           ADVAPI32$CreateProcessWithLogonW
#define CreateProcessWithTokenW           ADVAPI32$CreateProcessWithTokenW
#define OpenProcessToken                  ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueW             ADVAPI32$LookupPrivilegeValueW
#define AdjustTokenPrivileges             ADVAPI32$AdjustTokenPrivileges
#define LookupAccountSidW                 ADVAPI32$LookupAccountSidW
#define OpenSCManagerA                    ADVAPI32$OpenSCManagerA
#define CreateServiceA                    ADVAPI32$CreateServiceA
#define StartServiceA                     ADVAPI32$StartServiceA
#define CloseServiceHandle                ADVAPI32$CloseServiceHandle
#define RegOpenKeyExA                     ADVAPI32$RegOpenKeyExA
#define RegSetValueExA                    ADVAPI32$RegSetValueExA

// ==================== MSVCRT MACROS ====================
#define malloc                            MSVCRT$malloc
#define realloc                           MSVCRT$realloc
#define free                              MSVCRT$free
#define memset                            MSVCRT$memset
#define memcmp                            MSVCRT$memcmp
#define memcpy                            MSVCRT$memcpy
#define wcslen                            MSVCRT$wcslen
#define wcsncpy                           MSVCRT$wcsncpy
#define wcsrchr                           MSVCRT$wcsrchr
#define strlen                            MSVCRT$strlen
#define sprintf                           MSVCRT$sprintf
#define _swprintf                         MSVCRT$_swprintf
#define wcsstr                            MSVCRT$wcsstr
#define wcscpy                            MSVCRT$wcscpy
#define wcscat                            MSVCRT$wcscat
#define wcscmp                            MSVCRT$wcscmp
#define printf                            MSVCRT$printf
#define wprintf                           MSVCRT$wprintf
#define vsnprintf                         MSVCRT$vsnprintf

// ==================== IPHLPAPI MACROS ====================
#define GetNetworkParams                  IPHLPAPI$GetNetworkParams
#define GetAdaptersInfo                   IPHLPAPI$GetAdaptersInfo
#define GetIpForwardTable                 IPHLPAPI$GetIpForwardTable
#define DnsGetCacheDataTable              DNSAPI$DnsGetCacheDataTable

// ==================== WS2_32 MACROS ====================
#define inet_ntoa                         WS2_32$inet_ntoa

// ==================== NETAPI32 MACROS ====================
#define NetUserAdd                        NETAPI32$NetUserAdd

// ==================== OLE32 MACROS ====================
#define CoCreateInstance                  OLE32$CoCreateInstance
#define CoInitializeSecurity              OLE32$CoInitializeSecurity
#define StringFromGUID2                   OLE32$StringFromGUID2
#define CoInitializeEx                    OLE32$CoInitializeEx
#define CoUninitialize                    OLE32$CoUninitialize
#define CLSIDFromString                   OLE32$CLSIDFromString
#define IIDFromString                     OLE32$IIDFromString
#define CoSetProxyBlanket                 OLE32$CoSetProxyBlanket

// ==================== OLEAUT32 MACROS ====================
#define VariantInit                       OLEAUT32$VariantInit
#define VariantClear                      OLEAUT32$VariantClear
#define SysFreeString                     OLEAUT32$SysFreeString
#define SysAllocString                    OLEAUT32$SysAllocString

// ==================== USER32 MACROS ====================
#define GetDC                             USER32$GetDC
#define ReleaseDC                         USER32$ReleaseDC
#define GetSystemMetrics                  USER32$GetSystemMetrics
#define OpenClipboard                     USER32$OpenClipboard
#define GetClipboardData                  USER32$GetClipboardData
#define CloseClipboard                    USER32$CloseClipboard

// ==================== GDI32 MACROS ====================
#define BitBlt                            GDI32$BitBlt
#define SelectObject                      GDI32$SelectObject
#define DeleteDC                          GDI32$DeleteDC
#define DeleteObject                      GDI32$DeleteObject
#define CreateDIBSection                  GDI32$CreateDIBSection
#define GdiFlush                          GDI32$GdiFlush
#define CreateCompatibleDC                GDI32$CreateCompatibleDC
#define GetObjectW                        GDI32$GetObjectW
#define GetCurrentObject                  GDI32$GetCurrentObject

// ==================== WSMSVC MACROS ====================
#define WSManInitialize                   WSMSVC$WSManInitialize
#define WSManCreateSession                WSMSVC$WSManCreateSession
#define WSManCreateShell                  WSMSVC$WSManCreateShell
#define WSManRunShellCommand              WSMSVC$WSManRunShellCommand
#define WSManReceiveShellOutput           WSMSVC$WSManReceiveShellOutput
#define WSManCloseOperation               WSMSVC$WSManCloseOperation
#define WSManCloseCommand                 WSMSVC$WSManCloseCommand
#define WSManCloseShell                   WSMSVC$WSManCloseShell
#define WSManCloseSession                 WSMSVC$WSManCloseSession
#define WSManDeinitialize                 WSMSVC$WSManDeinitialize

#endif // EXTERNS_H