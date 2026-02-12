#include <general.h>

auto declfn setup_instance( 
    _In_ ULONG id 
) -> INSTANCE* {
    PEB* peb = NtCurrentPeb();

    auto AllocHeap = (PVOID (*)( PVOID, ULONG, SIZE_T ))load_api( 
        load_module( hashstr<CHAR>( "ntdll.dll" ) ), 
        hashstr<CHAR>( "RtlAllocateHeap" ) 
    );

    auto RtlCreateHeap = (PVOID(*)(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID))load_api(
        load_module( hashstr<CHAR>("ntdll.dll")), 
        hashstr<CHAR>("RtlCreateHeap")
    );
    
    PVOID CustomHeap = RtlCreateHeap(
        HEAP_GROWABLE | HEAP_ZERO_MEMORY,
        nullptr, 0x100000, 0, nullptr, nullptr
    );

    INSTANCE* self = (INSTANCE*)AllocHeap( CustomHeap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) );

    if ( peb->NumberOfHeaps >= peb->MaximumNumberOfHeaps ) {
        ULONG newMax = peb->MaximumNumberOfHeaps * 2;
        
        PVOID* newHeaps = (PVOID*)AllocHeap(
            peb->ProcessHeap, 
            HEAP_ZERO_MEMORY, 
            newMax * sizeof(PVOID)
        );

        mm::copy( newHeaps, peb->ProcessHeaps, peb->NumberOfHeaps * sizeof(PVOID) );
        
        peb->ProcessHeaps = newHeaps;
        peb->MaximumNumberOfHeaps = newMax;
    }

    peb->ProcessHeaps[peb->NumberOfHeaps] = self;
    peb->NumberOfHeaps++;

    return self;
}

auto declfn initialization( 
    _In_  PVOID       argbuff,
    _Out_ POSTEX_CTX* postex,
    _Out_ PARSER*     psr
) -> INSTANCE* {
    INSTANCE* self = nullptr;

    parser::header( argbuff, postex );

    self = setup_instance( postex->id );

    parser::create( psr, postex->args, postex->argc );

    self->postex = *postex;

    return self;
}

auto declfn dispatcher() -> ULONG {
    g_instance

    UINT32 cmd       = 0;
    BOOL   running   = TRUE;
    BOOL   suspended = FALSE;

    pipe::send( MSG_READY, STATE_RUNNING, 0, FALSE, nullptr, 0 );

    while ( running ) {
        if ( pipe::check_cmd( &cmd ) == ERROR_SUCCESS && cmd != 0 ) {
            switch ( cmd ) {
                case CMD_SUSPEND:
                    suspended = TRUE;
                    pipe::send( MSG_STATE, STATE_SUSPENDED, 0, FALSE, nullptr, 0 );
                    break;

                case CMD_RESUME:
                    suspended = FALSE;
                    pipe::send( MSG_STATE, STATE_RUNNING, 0, FALSE, nullptr, 0 );
                    break;

                case CMD_KILL:
                    running = FALSE;
                    break;

                case CMD_OUTPUT:
                    break;
            }
        }

        if ( ! suspended ) {
            CHAR* buffer = "hello from postex module";

            pipe::send( MSG_OUTPUT, STATE_RUNNING, 0, FALSE, (PBYTE)buffer, self->msvcrt.strlen( buffer ) );
        }

        self->kernel32.WaitForSingleObject( NtCurrentProcess(), 100 );
    }

    return ERROR_SUCCESS;
}

extern "C" auto declfn entry( PVOID parameter ) -> VOID {
    INSTANCE*  self    = nullptr;
    PVOID      start   = startptr();
    ULONG      size    = (UPTR)endptr() - (UPTR)start;
    PVOID      argbuff = endptr();
    PARSER     psr     = {};
    POSTEX_CTX postex  = {};

    self = initialization( argbuff, &postex, &psr );

    self->ctx.start = start;
    self->ctx.size  = size;
    self->ctx.heap  = NtCurrentPeb()->ProcessHeap;

    self->ntdll.DbgPrint( "id: %llX\n", self->postex.id );
    self->ntdll.DbgPrint( "pipename: %ls\n", self->postex.pipename );

    if ( pipe::create_server() != ERROR_SUCCESS ) {
        self->ntdll.DbgPrint( "failed to create pipe\n" );
        return;
    }

    self->ntdll.DbgPrint( "waiting for client...\n" );

    if ( pipe::wait_connection() != ERROR_SUCCESS ) {
        self->ntdll.DbgPrint( "connection failed\n" );
        pipe::cleanup();
        return;
    }

    self->ntdll.DbgPrint( "connected, starting dispatcher\n" );

    ULONG exit_code = dispatcher();

    pipe::send( MSG_END, STATE_COMPLETED, exit_code, TRUE, nullptr, 0 );

    pipe::cleanup();
}