#include <Kharon.h>

typedef struct {
    PCHAR Name;
    UINT8 Type; // ( COFF_VAR | COFF_FNC | COFF_IMP )
    ULONG Size;
} SYMBOL_DATA, *PSYMBOL_DATA;

auto Coff::GetSize(
    _In_ PIMAGE_SECTION_HEADER SecHdr
    _In_ ULONG SecNbrs,

) -> ULONG {

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

    PIMAGE_FILE_HEADER    Header  = { 0 };
    PIMAGE_SECTION_HEADER SecHdr  = { 0 };
    PIMAGE_SYMBOL         Symbols = { 0 };

    Header  = (PIMAGE_FILE_HEADER)Buffer;
    SecHdr  = (PIMAGE_SECTION_HEADER)( Buffer + sizeof( IMAGE_FILE_HEADER ) );
    SecNbrs = Header->NumberOfSections;
    SymNbrs = Header->NumberOfSymbols;
    Symbols = (PIMAGE_SYMBOL)( Buffer + Header->PointerToSymbolTable );
    
    SYMBOL_DATA SymData[SymNbrs] = { 0 };

    for ( INT i = 0; i < SecNbrs; i++ ) {
        MmSize += PAGE_ALIGN( SecHdr[i].SizeOfRawData );
    }

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

    MmBase = Self->Mm->Alloc( nullptr, nullptr, MmSize, MEM_COMMIT, PAGE_READWRITE );

    for ( INT i = 0; i < SecNbrs; i++ ) {
        Mem::Copy(
            MmBase + SecHdr[i].VirtualAddress,
            Buffer + SecHdr[i].PointerToRawData,
            SecHdr[i].SizeOfRawData
        );
    }
}