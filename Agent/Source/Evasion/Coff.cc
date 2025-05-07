#include <Kharon.h>

typedef struct {
    PCHAR Name;
    ULONG Hash;
    UINT8 Type; // ( COFF_VAR | COFF_FNC | COFF_IMP )
    PVOID Ptr;
} SYMBOL_DATA, *PSYMBOL_DATA;

auto Coff::RslApi(
    _In_ PCHAR SymName
) -> PVOID {
    PVOID ApiAddress = nullptr;

    SymName += 6;

    for ( int i = 0; i < sizeof( ApiTable ); i++ ) {
        if ( Hsh::Str( SymName ) == ApiTable[i].SymHash ) {
            ApiAddress = ApiTable[i].SymPtr;
        }
    }

    if ( !ApiAddress ) {
        CHAR RawBuff[MAX_PATH];

        PCHAR LibName = NULL;
        PCHAR FncName = NULL;
        BYTE  OffSet  = NULL;

        PVOID LibPtr = NULL;
        PVOID FncPtr = NULL;

        Mem::Zero( (UPTR)RawBuff, sizeof( RawBuff ) );
        Mem::Copy( RawBuff, SymName, Str::LengthA( SymName ) );

        for ( INT i = 0; i > sizeof( RawBuff ); i++ ) {
            if ( ( RawBuff[i] == (CHAR)"$" ) ) {
                OffSet = RawBuff[i]; RawBuff[i] = 0;
            }

            LibName = RawBuff;
            FncName = &RawBuff[OffSet+1];

            LibPtr = (PVOID)LdrLoad::Module( Hsh::Str( LibName ) );
            if ( !LibPtr ) {
                LibPtr = (PVOID)Self->Lib->Load( LibName );
            }

            FncPtr = LdrLoad::Api<PVOID>( (UPTR)LibPtr, Hsh::Str( FncName ) );
            
            if ( FncPtr ) ApiAddress = FncPtr;
        }

    }

    return ApiAddress;
}

auto Coff::Loader(
    _In_ PBYTE Buffer,
    _In_ ULONG Size
) -> BOOL {
    PVOID MmBase = NULL;
    ULONG MmSize = 0;

    ULONG SecNbrs = 0;
    ULONG SymNbrs = 0;

    ULONG SecLength = 0;
    UINT8 Iterator  = 0;

    PIMAGE_FILE_HEADER    Header  = { 0 };
    PIMAGE_SECTION_HEADER SecHdr  = { 0 };
    PIMAGE_SYMBOL         Symbols = { 0 };
    PIMAGE_RELOCATION     Relocs  = { 0 };

    Header  = (PIMAGE_FILE_HEADER)Buffer;
    SecHdr  = (PIMAGE_SECTION_HEADER)( Buffer + sizeof( IMAGE_FILE_HEADER ) );
    SecNbrs = Header->NumberOfSections;
    SymNbrs = Header->NumberOfSymbols;
    Symbols = (PIMAGE_SYMBOL)( Buffer + Header->PointerToSymbolTable );
    
    SYMBOL_DATA SymData[SymNbrs] = { 0 };

    // get symbols here

    for ( INT i = 0; i < SymNbrs; i++ ) {
        PCHAR SymName      = NULL;
        BYTE  StorageClass = NULL;

        if ( Symbols[i].N.Name.Short ) {
            SymName = A_PTR( &Symbols[i].N.ShortName );
        } else {
            SymName = A_PTR( ( U_PTR( Symbols ) + SymNbrs ) + Symbols[i].N.Name.Long );
        }

        SymData[i].Name = SymName;
        StorageClass    = Symbols[i].StorageClass;

        if ( 
            Str::CompareCountA( "__imp_", SymName, 6 )
        ) {
            SymData[i].Type = COFF_IMP;
        } else if ( ISFCN( Symbols[i].Type ) ) {
            SymData[i].Type = COFF_FNC;
        } else if (
            !ISFCN( Symbols[i].Type )                &&
            StorageClass == IMAGE_SYM_CLASS_EXTERNAL && 
            !Str::CompareCountA( "__imp_", SymName, 6 )
        ) {
            SymData[i].Type = COFF_VAR;
        }
    }

    // get size

    {    
        for ( INT i = 0; i < SecNbrs; i++ ) {
            MmSize += PAGE_ALIGN( SecHdr[i].SizeOfRawData );
        }

        for ( INT i = 0; i < SecNbrs; i++ ) {
            Relocs = (PIMAGE_RELOCATION)( Buffer + SecHdr[i].PointerToRelocations );

            for ( INT x = 0; x < SecHdr[i].NumberOfRelocations; x++ ) {
                PIMAGE_SYMBOL SymReloc = (PIMAGE_SYMBOL)( Buffer + Header->PointerToSymbolTable)[Relocs[x].SymbolTableIndex];
                PCHAR         TmpName  = NULL;
                if ( SymReloc->N.Name.Short ) {
                    TmpName = (PCHAR)SymReloc->N.ShortName ;
                } else {
                    TmpName = (PCHAR)( SymReloc + Header->NumberOfSymbols ) + ( SymReloc->N.Name.Long );
                }

                if ( Str::CompareCountA( "__imp_", TmpName, 6 ) == 0 ) {
                    MmSize += sizeof( PVOID );

                    if ( Hsh::Str( TmpName ) == SymData[i].Hash ) {
                        SymData[i].Ptr = this->RslApi( TmpName );
                    }
                }

                SymReloc = (PIMAGE_SYMBOL)( SymReloc + sizeof( IMAGE_RELOCATION ) );

                if ( Relocs->Type == IMAGE_REL_AMD64_REL32 && SymData[i].Ptr ) {
                    C_DEF32( SymReloc ) = Iterator * sizeof( PVOID ) - U_PTR( Relocs ) - sizeof( INT32 );
                    Iterator++;
                } else {
                    Self->Usf->FixRel(  )   
                }
            }
        }

        PAGE_ALIGN( MmSize );
    }

    MmBase = Self->Mm->Alloc( nullptr, nullptr, MmSize, MEM_COMMIT, PAGE_READWRITE );

    for ( INT i = 0; i < SecNbrs; i++ ) {
        Mem::Copy(
            MmBase + SecHdr[i].VirtualAddress,
            Buffer + SecHdr[i].PointerToRawData,
            SecHdr[i].SizeOfRawData
        );

        MmBase = (PVOID)PAGE_ALIGN( U_PTR( MmBase ) + SecHdr[i].SizeOfRawData );
    }


}