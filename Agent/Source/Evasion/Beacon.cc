#include <Kharon.h>

auto Coff::Output( 
    INT  type, 
    PCCH data, 
    INT  len
) -> VOID {
    return Self->Pkg->Bytes( Pkg, (PUCHAR)data, len );
}

auto Coff::DataExtract(
    PDATAP parser, 
    PINT   size
) -> PCHAR {
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (PULONG)size );
}

auto Coff::DataInt(
    PDATAP parser
)->INT {
    return Self->Psr->Int32( (PPARSER)parser );
}

auto Coff::DataShort(
    PDATAP parser
) -> SHORT {
    return Self->Psr->Int16( (PPARSER)parser );
}

auto Coff::DataLength(
    PDATAP parser
) -> INT {
    return parser->length;
}

auto Coff::OpenProcess(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD processId
) -> HANDLE {
    return Self->Ps->Open( desiredAccess, inheritHandle, processId );
}

auto Coff::VirtualAlloc(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    return Self->Mm->Alloc( NULL, Address, Size, AllocType, Protect );
}

auto Coff::VirtualAllocEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    return Self->Mm->Alloc( Handle, Address, Size, AllocType, Protect );
}

auto Coff::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    return Self->Mm->Protect( NULL, Address, Size, NewProtect, OldProtect );
}

auto Coff::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    return Self->Mm->Protect( Handle, Address, Size, NewProtect, OldProtect );
}

auto Coff::OpenThread(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD threadId
) -> HANDLE {
    return Self->Td->Open( desiredAccess, inheritHandle, threadId );
}

auto Coff::LoadLibraryA(
    _In_ PCHAR LibraryName
) -> HMODULE {
    return (HMODULE)Self->Lib->Load( LibraryName );
}
