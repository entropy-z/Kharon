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

    DFR(KERNEL32, CreateThread)
    DFR(KERNEL32, CreateRemoteThread)

    DFR(KERNEL32, InitializeProcThreadAttributeList)
    DFR(KERNEL32, UpdateProcThreadAttribute)
    DFR(KERNEL32, DeleteProcThreadAttributeList)
    
    DFR(NTDLL, NtSetInformationProcess)
    DFR(NTDLL, NtQueryInformationProcess)

    DFR(KERNEL32, GetProcessHeap)
    DFR(KERNEL32, GetProcessHeaps)
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, HeapReAlloc)
    DFR(KERNEL32, HeapFree)

    DFR(KERNEL32, CreatePipe)
    DFR(KERNEL32, DuplicateHandle)
    DFR(KERNEL32, CreateFileW)
    DFR(KERNEL32, CreateFileA)
    DFR(KERNEL32, GetFileSize)
    DFR(KERNEL32, ReadFile)
    DFR(KERNEL32, CopyFileW)
    DFR(KERNEL32, MoveFileW)
    DFR(KERNEL32, DeleteFileW)

    DFR(KERNEL32, WaitForSingleObject)

    DFR(KERNEL32, CloseHandle)
    DFR(KERNEL32, GetLastError)
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

#define NtSetInformationProcess   NTDLL$NtSetInformationProcess
#define NtQueryInformationProcess NTDLL$NtQueryInformationProcess

#define GetProcessHeap      KERNEL32$GetProcessHeap
#define GetProcessHeaps     KERNEL32$GetProcessHeaps
#define HeapAlloc           KERNEL32$HeapAlloc
#define HeapReAlloc         KERNEL32$HeapReAlloc
#define HeapFree            KERNEL32$HeapFree

#define CreatePipe          KERNEL32$CreatePipe
#define DuplicateHandle     KERNEL32$DuplicateHandle
#define CreateFileW         KERNEL32$CreateFileW   
#define CreateFileA         KERNEL32$CreateFileA
#define GetFileSize         KERNEL32$GetFileSize
#define ReadFile            KERNEL32$ReadFile

#define WaitForSingleObject KERNEL32$WaitForSingleObject

#define CloseHandle         KERNEL32$CloseHandle
#define GetLastError        KERNEL32$GetLastError
 
#endif // EXTERNS_H