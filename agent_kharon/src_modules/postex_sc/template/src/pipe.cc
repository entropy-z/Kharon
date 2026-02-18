#include <general.h>

#define PIPE_BUFFER_SIZE 0x10000

auto declfn pipe::create_server() -> ULONG {
    g_instance

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    self->pipe.handle = self->kernel32.CreateNamedPipeW(
        self->postex.pipename,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        &sa
    );

    if ( self->pipe.handle == INVALID_HANDLE_VALUE || ! self->pipe.handle ) {
        return last_error();
    }

    return ERROR_SUCCESS;
}

auto declfn pipe::wait_connection() -> ULONG {
    g_instance

    if ( ! self->kernel32.ConnectNamedPipe( self->pipe.handle, nullptr ) ) {
        ULONG err = last_error();
        if ( err != ERROR_PIPE_CONNECTED ) {
            return err;
        }
    }

    return ERROR_SUCCESS;
}

auto declfn pipe::check_cmd(
    _Out_ UINT32* cmd
) -> ULONG {
    g_instance

    PIPE_CMD pipe_cmd   = {};
    DWORD    bytes_read = 0;

    *cmd = 0;

    DWORD available = 0;
    if ( ! self->kernel32.PeekNamedPipe( self->pipe.handle, nullptr, 0, nullptr, &available, nullptr ) ) {
        return last_error();
    }

    if ( available == 0 ) {
        return ERROR_SUCCESS;
    }

    if ( ! self->kernel32.ReadFile( self->pipe.handle, &pipe_cmd, sizeof(pipe_cmd), &bytes_read, nullptr ) ) {
        return last_error();
    }

    if ( bytes_read == sizeof(PIPE_CMD) && pipe_cmd.magic == self->postex.id ) {
        *cmd = pipe_cmd.cmd;
    }

    return ERROR_SUCCESS;
}

auto declfn pipe::send(
    _In_     ULONG msg_type,
    _In_     ULONG state,
    _In_     ULONG exit_code,
    _In_     BOOL  need_free,
    _In_opt_ PBYTE buffer,
    _In_opt_ ULONG size
) -> ULONG {
    g_instance

    PIPE_MSG msg   = {};
    msg.magic      = self->postex.id;
    msg.type       = msg_type;
    msg.state      = state & 0xF;
    msg.free       = need_free ? 1 : 0;
    msg.exit_code  = exit_code;

    DWORD written = 0;
    ULONG total_size = sizeof(PIPE_MSG) + size;

    PBYTE send_buffer = (PBYTE)mm::alloc<PBYTE>( total_size );
    if ( ! send_buffer ) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    mm::copy( send_buffer, &msg, sizeof(PIPE_MSG) );

    if ( buffer && size > 0 ) {
        mm::copy( send_buffer + sizeof(PIPE_MSG), buffer, size );
    }

    BOOL success = self->kernel32.WriteFile( 
        self->pipe.handle, 
        send_buffer, 
        total_size, 
        &written, 
        nullptr 
    );

    mm::free( send_buffer );

    return success ? ERROR_SUCCESS : last_error();
}

auto declfn pipe::cleanup() -> void {
    g_instance

    if ( self->pipe.handle && self->pipe.handle != INVALID_HANDLE_VALUE ) {
        self->kernel32.DisconnectNamedPipe( self->pipe.handle );
        self->ntdll.NtClose( self->pipe.handle );
        self->pipe.handle = nullptr;
    }
}