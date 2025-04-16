from Translator.Utils import *

import ipaddress

def CheckinImp( uuid ):
    RespChkDbg( "------------------------" );

    Data = uuid.encode();

    RespChkDbg( f"data: {Data}" );

    RespChkDbg( "------------------------" );

    return Data;

def RespTasking( Tasks ) -> bytes:

    RespTaskDbg( "------------------------" );

    Pkg = Packer();

    JobID       = Jobs["get_tasking"]["hex_code"];
    TaskLength  = len( Tasks );

    RespTaskDbg( f"job id    : {JobID}" );
    RespTaskDbg( f"task qtt  : {TaskLength}" );

    Pkg.Int8( JobID );
    Pkg.Int32( TaskLength );

    for Task in Tasks:
        Command    = Task["command"];
        TaskUUID   = Task["id"].encode( );
        Parameters = json.loads( Task["parameters"] );        

        if "action" in Parameters:
            main_cmd = Command;
            sub_cmd  = Parameters["action"];

            print( f"full param: {Parameters}" );
            print( f"action    : {sub_cmd}" );
            
            if main_cmd in Commands and 'subcommands' in Commands[main_cmd]:
                TaskID = Commands[main_cmd]['hex_code'];
                
                if sub_cmd in Commands[main_cmd]['subcommands']:
                    SubID = Commands[main_cmd]['subcommands'][sub_cmd]['sub'];
                else:
                    RespTaskDbg( f"Unknown subcommand: {sub_cmd}" );
                    continue;
            else:
                RespTaskDbg( f"Command doesn't support subcommands: {main_cmd}" );
                continue;
        else:
            if Command in Commands:
                TaskID = Commands[Command]['hex_code'];
                SubID = 0;
            else:
                RespTaskDbg( f"Unknown command: {Command}" );
                continue;

        Pkg.Int16( int( TaskID ) );
        Pkg.Bytes( TaskUUID );
        
        if SubID != 0:
            Pkg.Int8( SubID );

        RespTaskDbg( f"command   : {Command}" );
        RespTaskDbg( f"task uuid : {TaskUUID}" );
        RespTaskDbg( f"task id   : {TaskID}" );
        if SubID != 0:
            RespTaskDbg( f"sub id    : {SubID}" );
        RespTaskDbg( f"parameters: {Parameters}" );

        for Key, Val in Parameters.items():
            if Key != "action":
                if isinstance( Val, int ) or ( isinstance( Val, str ) and Val.isdigit() ):
                    RespTaskDbg( f"parameter: {Val} [type: int]" );
                    Pkg.Int32( int( Val ) );
                elif isinstance( Val, str ):
                    RespTaskDbg( f"parameter: {Val} [type: str]" );
                    Pkg.Bytes( str( Val ).encode() );
                elif isinstance( Val, bool ):
                    RespTaskDbg( f"parameter: {Val} [type: bool]" );
                    Pkg.Int32( int( Val ) );
                elif isinstance( Val, bytes ):
                    RespTaskDbg( f"parameter: {Val} [type: bytes]" );
                    Pkg.Bytes( Val );
    
    RespTaskDbg( "------------------------" );
    
    return Pkg.buffer;

def RespPosting( Responses ):
    RespPostDbg( "------------------------" );

    RespPostDbg( f"responses: {Responses}" );

    Data = len( Responses ).to_bytes( 4, "big" );

    Pkg = Packer();

    for Response in Responses:
        if Response["status"] == "success":
            Data += b"\x01";
        else: 
            Data += b"\x00";
    
    RespPostDbg( f"status: {Response["status"]}" );

    for Response in Responses:
        FileID = Response

        TotalChunks = Response.get( "total_chunks" );
        if TotalChunks:
            Pkg.Int32( TotalChunks );
            RespPostDbg( f"total chunks: {TotalChunks}" );

        ChunkNbr = Response.get( "chunk_num" );
        if ChunkNbr:
            Pkg.Int32( ChunkNbr );
            RespPostDbg( f"chunk number: {ChunkNbr}" );
        
        ChunkData = Response.get( "chunk_data" );
        if ChunkData:
            Pkg.Bytes( base64.b64decode( ChunkData ) );
            RespPostDbg( f"Chunk Data: {len(ChunkData)} bytes" );
            Data = Pkg.buffer;

    RespPostDbg( "------------------------" );
    
    return Data
