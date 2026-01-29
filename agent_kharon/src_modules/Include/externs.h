#ifndef EXTERNS_H
#define EXTERNS_H

#include <win32.h>

#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#define DFR(module, function) DECLSPEC_IMPORT decltype(function) module##$##function;

extern "C" {
    DFR(KERNEL32, VirtualAlloc)
    DFR(KERNEL32, VirtualAllocEx)
    DFR(KERNEL32, VirtualProtect)
    DFR(KERNEL32, VirtualProtectEx)
    DFR(KERNEL32, WriteProcessMemory)

    DFR(KERNEL32, OpenProcess)
    DFR(KERNEL32, CreateProcessW)
    DFR(KERNEL32, CreateProcessWithLogonW)
    DFR(KERNEL32, CreateProcessWithTokenW) 
    DFR(KERNEL32, GetExitCodeProcess)
    DFR(KERNEL32, TerminateProcess)
    DFR(KERNEL32, GetProcessId)

    DFR(KERNEL32, EnumProcessModules)
    DFR(KERNEL32, GetModuleFileNameW)
    DFR(KERNEL32, K32GetModuleFileNameExA)

    DFR(KERNEL32, CreateThread)
    DFR(KERNEL32, CreateRemoteThread)

    DFR(KERNEL32, InitializeProcThreadAttributeList)
    DFR(KERNEL32, UpdateProcThreadAttribute)
    DFR(KERNEL32, DeleteProcThreadAttributeList)
    
    DFR(NTDLL, NtQuerySystemInformation)
    DFR(NTDLL, NtSetInformationProcess)
    DFR(NTDLL, NtQueryInformationToken)
    DFR(NTDLL, NtQueryInformationProcess)

    DFR(KERNEL32, GetProcessHeap)
    DFR(KERNEL32, GetProcessHeaps)
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, HeapReAlloc)
    DFR(KERNEL32, HeapFree)

    DFR(ADVAPI32, OpenProcessToken)
    DFR(ADVAPI32, LookupAccountSidW)

    DFR(KERNEL32, FileTimeToSystemTime)
    DFR(KERNEL32, CreatePipe)
    DFR(KERNEL32, DuplicateHandle)
    DFR(KERNEL32, CreateFileW)
    DFR(KERNEL32, CreateFileA)
    DFR(KERNEL32, GetFullPathNameW)
    DFR(KERNEL32, CreateDirectoryW)
    DFR(KERNEL32, SetCurrentDirectoryW)
    DFR(KERNEL32, GetFileAttributesW)
    DFR(KERNEL32, GetCurrentDirectoryW)
    DFR(KERNEL32, GetFileSize)
    DFR(KERNEL32, SetStdHandle)
    DFR(KERNEL32, GetStdHandle)
    DFR(KERNEL32, ReadFile)
    DFR(KERNEL32, CopyFileW)
    DFR(KERNEL32, MoveFileW)
    DFR(KERNEL32, DeleteFileW)
    DFR(KERNEL32, FindFirstFileW)
    DFR(KERNEL32, FindNextFileW)
    DFR(KERNEL32, FindClose)

    DFR(KERNEL32, IsWow64Process)
    DFR(KERNEL32, WaitForSingleObject)

    DFR(NTDLL, DbgPrint)
    DFR(KERNEL32, CloseHandle)
    DFR(KERNEL32, GetLastError)
    DFR(KERNEL32, FormatMessageW)

    DFR(MSVCRT, malloc)
    DFR(MSVCRT, free)
    DFR(MSVCRT, wcslen)
    DFR(MSVCRT, strlen)
    DFR(MSVCRT, sprintf)
    DFR(MSVCRT, _swprintf)
}

#define VirtualAlloc        KERNEL32$VirtualAlloc
#define VirtualAllocEx      KERNEL32$VirtualAllocEx
#define VirtualProtect      KERNEL32$VirtualProtect
#define VirtualProtectEx    KERNEL32$VirtualProtectEx
#define WriteProcessMemory  KERNEL32$WriteProcessMemory

#define OpenProcess             KERNEL32$OpenProcess
#define CreateProcessW          KERNEL32$CreateProcessW
#define CreateProcessWithLogonW KERNEL32$CreateProcessWithLogonW
#define CreateProcessWithTokenW KERNEL32$CreateProcessWithTokenW
#define GetExitCodeProcess      KERNEL32$GetExitCodeProcess
#define TerminateProcess        KERNEL32$TerminateProcess
#define GetProcessId            KERNEL32$GetProcessId

#define EnumProcessModules  KERNEL32$EnumProcessModules
#define GetModuleFileNameW  KERNEL32$GetModuleFileNameW

#define CreateThread          KERNEL32$CreateThread
#define CreateRemoteThread    KERNEL32$CreateRemoteThread

#define InitializeProcThreadAttributeList KERNEL32$InitializeProcThreadAttributeList
#define UpdateProcThreadAttribute         KERNEL32$UpdateProcThreadAttribute
#define DeleteProcThreadAttributeList     KERNEL32$DeleteProcThreadAttributeList

#define RtlStringCchPrintfW NTDLL$RtlStringCchPrintfW

#define NtQuerySystemInformation  NTDLL$NtQuerySystemInformation
#define NtSetInformationProcess   NTDLL$NtSetInformationProcess
#define NtQueryInformationToken   NTDLL$NtQueryInformationToken
#define NtQueryInformationProcess NTDLL$NtQueryInformationProcess

#define OpenProcessToken  ADVAPI32$OpenProcessToken
#define LookupAccountSidW ADVAPI32$LookupAccountSidW

#define GetProcessHeap      KERNEL32$GetProcessHeap
#define GetProcessHeaps     KERNEL32$GetProcessHeaps
#define HeapAlloc           KERNEL32$HeapAlloc
#define HeapReAlloc         KERNEL32$HeapReAlloc
#define HeapFree            KERNEL32$HeapFree

#define FileTimeToSystemTime KERNEL32$FileTimeToSystemTime
#define CreatePipe          KERNEL32$CreatePipe
#define DuplicateHandle     KERNEL32$DuplicateHandle
#define CreateFileW         KERNEL32$CreateFileW   
#define SetCurrentDirectoryW KERNEL32$SetCurrentDirectoryW  
#define CreateFileA         KERNEL32$CreateFileA
#define GetFileAttributesW  KERNEL32$GetFileAttributesW
#define GetCurrentDirectoryW KERNEL32$GetCurrentDirectoryW
#define GetFileSize         KERNEL32$GetFileSize
#define CopyFileW          KERNEL32$CopyFileW
#define SetStdHandle        KERNEL32$SetStdHandle
#define GetStdHandle        KERNEL32$GetStdHandle
#define ReadFile            KERNEL32$ReadFile
#define MoveFileW           KERNEL32$MoveFileW
#define DeleteFileW         KERNEL32$DeleteFileW
#define CreateDirectoryW    KERNEL32$CreateDirectoryW
#define GetFullPathNameW    KERNEL32$GetFullPathNameW
#define FindFirstFileW     KERNEL32$FindFirstFileW
#define FindNextFileW      KERNEL32$FindNextFileW
#define FindClose          KERNEL32$FindClose

#define IsWow64Process      KERNEL32$IsWow64Process
#define WaitForSingleObject KERNEL32$WaitForSingleObject

#define DbgPrint           NTDLL$DbgPrint
#define CloseHandle         KERNEL32$CloseHandle
#define GetLastError        KERNEL32$GetLastError
#define FormatMessageW      KERNEL32$FormatMessageW

#define malloc    MSVCRT$malloc
#define wcslen    MSVCRT$wcslen
#define strlen    MSVCRT$strlen
#define free      MSVCRT$free
#define _swprintf MSVCRT$_swprintf
#define sprintf   MSVCRT$sprintf
 
#endif // EXTERNS_H