#include <general.h>

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    INT32  process_id       = BeaconDataInt( &data_parser );
    INT32  process_exitcode = BeaconDataInt( &data_parser );

    HANDLE process_handle = OpenProcess( PROCESS_TERMINATE, FALSE, process_id );
    if ( ! process_handle || process_handle == INVALID_HANDLE_VALUE ) {
        BeaconPrintf( CALLBACK_ERROR, "Error to open handle: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    if ( TerminateProcess( process_handle, process_exitcode ) ) {
        BeaconPrintf( CALLBACK_ERROR, "Error to terminate process with error: (%d) %s\n", GetLastError(), fmt_error( GetLastError() ) );
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Process killed!");

    return;
}