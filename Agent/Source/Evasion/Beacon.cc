#include <Kharon.h>

auto Coff::DataParse(
    PDATAP parser, 
    PCHAR  buffer, 
    INT    size
) -> VOID {
    G_KHARON

    if (parser == NULL) {
        return;
    }

    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer   += 4;
}

auto Coff::Output( 
    INT  type, 
    PCCH data, 
    INT  len
) -> VOID {
    G_KHARON

    VOID* MemRange  = __builtin_return_address( 0 );
    ULONG CommandID = 0;
    CHAR* UUID      = nullptr;

    CommandID = Self->Cf->GetCmdID( MemRange );
    UUID      = Self->Cf->GetTask( MemRange );
    
    Self->Pkg->SendOut( UUID, CommandID, (BYTE*)data, len, type );
}

auto Coff::Printf(
    INT  type,
    PCCH fmt,
    ...
) -> VOID {
    G_KHARON

    va_list VaList = { 0 };
    va_start( VaList, fmt );

    VOID* MemRange = __builtin_return_address( 0 );
    CHAR* UUID     = nullptr;
    ULONG MsgSize  = 0;
    CHAR* MsgBuff  = nullptr;
    
    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, fmt, VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "failed get the formated message size" ); goto _KH_END;
    }

    MsgBuff = (CHAR*)Self->Hp->Alloc( MsgSize +1 );

    if ( Self->Msvcrt.vsnprintf( MsgBuff, MsgSize, fmt, VaList ) < 0 ) {
        KhDbg( "failed formating string" ); goto _KH_END;
    }

    UUID = Self->Cf->GetTask( MemRange );

    KhDbg( "Message to send to the task id %s: %s [%d bytes]", UUID, MsgBuff, MsgSize );

    Self->Pkg->SendMsg( UUID, MsgBuff, type );

_KH_END:
    if ( VaList  ) va_end( VaList );
    if ( MsgBuff ) Self->Hp->Free( MsgBuff );
}

auto Coff::DataExtract(
    PDATAP parser, 
    PINT   size
) -> PCHAR {
    G_KHARON
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (ULONG*)size );
}

auto Coff::DataInt(
    PDATAP parser
)->INT {
    G_KHARON

    return Self->Psr->Int32( (PPARSER)parser );
}

auto Coff::DataShort(
    PDATAP parser
) -> SHORT {
    G_KHARON
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
    G_KHARON
    return Self->Ps->Open( desiredAccess, inheritHandle, processId );
}

auto Coff::VirtualAlloc(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( NULL, Address, Size, AllocType, Protect );
}

auto Coff::VirtualAllocEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Handle, Address, Size, AllocType, Protect );
}

auto Coff::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON

    return Self->Mm->Protect( NULL, Address, Size, NewProtect, OldProtect );
}

auto Coff::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Handle, Address, Size, NewProtect, OldProtect );
}

auto Coff::OpenThread(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD threadId
) -> HANDLE {
    G_KHARON
    return Self->Td->Open( desiredAccess, inheritHandle, threadId );
}

auto Coff::LoadLibraryA(
    _In_ PCHAR LibraryName
) -> HMODULE {
    G_KHARON
    return (HMODULE)Self->Lib->Load( LibraryName );
}
