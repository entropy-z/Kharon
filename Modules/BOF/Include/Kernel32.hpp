#ifndef KERNEL32_HPP
#define KERNEL32_HPP

#include <Common.hpp>

EXTERN_C {
    DFR( KERNEL32, CreateFileA )
    DFR( KERNEL32, GetFileSize )
    DFR( KERNEL32, ReadFile )
    DFR( KERNEL32, VirtualAlloc )
    DFR( KERNEL32, LoadLibraryW )
    DFR( KERNEL32, VirtualProtect )
    DFR( KERNEL32, GetEnvironmentStringsW )
    DFR( KERNEL32, FreeEnvironmentStringsW )
    DFR( KERNEL32, GetLastError )
    DFR( KERNEL32, GetProcessHeap )
    DFR( KERNEL32, HeapAlloc )
    DFR( KERNEL32, HeapFree )
    DFR( KERNEL32, WideCharToMultiByte )
    DFR( KERNEL32, GetModuleHandleA )
}

#define CreateFileA             KERNEL32$CreateFileA
#define GetFileSize             KERNEL32$GetFileSize
#define ReadFile                KERNEL32$ReadFile
#define VirtualProtect          KERNEL32$VirtualProtect
#define LoadLibraryW            KERNEL32$LoadLibraryW
#define VirtualAlloc            KERNEL32$VirtualAlloc
#define GetEnvironmentStringsW  KERNEL32$GetEnvironmentStringsW
#define FreeEnvironmentStringsW KERNEL32$FreeEnvironmentStringsW         
#define GetLastError            KERNEL32$GetLastError
#define GetProcessHeap          KERNEL32$GetProcessHeap 
#define HeapAlloc               KERNEL32$HeapAlloc 
#define HeapFree                KERNEL32$HeapFree
#define WideCharToMultiByte     KERNEL32$WideCharToMultiByte
#define GetModuleHandleA        KERNEL32$GetModuleHandleA

#endif