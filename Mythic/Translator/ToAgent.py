from Translator.Utils import *

import ipaddress

def CheckinImp( uuid ):
    RespChkDbg( "------------------------" );

    Data = uuid.encode();

    RespChkDbg( f"data: {Data}" );

    RespChkDbg( "------------------------" );

    return Data;

def RespTasking( Tasks, Socks ) -> bytes:
    RespTaskDbg("------------------------")

    Pkg     = Packer()
    JobID   = Jobs["get_tasking"]["hex_code"]
    SockPkg = Packer()
    TaskLength = len(Tasks)

    for Sock in Socks:
        TaskLength += 1
        SrvId = Sock["server_id"]
        Data  = Sock["data"]
        Ext   = Sock["exit"]

        if Ext is False:
            Ext = 0
        else:
            Ext = 1

        TaskUUIDSck = "55555555-5555-5555-555-555555555555"

        RespTaskDbg( f"socks exit: {Ext}" )
        RespTaskDbg( f"socks id: {SrvId}" )

        if Data is not None:
            RespTaskDbg( f"socks data: {Data} [{len( Data )} bytes]" )
        
        SockPkg.Int16( T_SOCKS )
        SockPkg.Int32( Ext )
        SockPkg.Int32( SrvId )

        if Data is not None:
            SockPkg.Bytes( Data.encode() )    

        RespTaskDbg( f"socks all buffer: {SockPkg.buffer} [{SockPkg.length} bytes]" )

    Pkg.Int8( JobID )
    Pkg.Int32( TaskLength )

    for Sock in Socks:
        Pkg.Bytes( TaskUUIDSck.encode() )
        Pkg.Bytes( SockPkg.buffer )

    for Task in Tasks:
        Command = Task["command"]
        TaskUUID = Task["id"].encode()

        Parameters = {}
        if Task["parameters"] is None or Task["parameters"] == "":
            Parameters = {}
        else:
            try:
                if isinstance(Task["parameters"], str):
                    Parameters = json.loads(Task["parameters"])
                elif isinstance(Task["parameters"], dict):
                    Parameters = Task["parameters"]
                else:
                    Parameters = {}
            except (json.JSONDecodeError, TypeError):
                Parameters = {}

        Pkg.Bytes(TaskUUID)
        TaskPkg = Packer()

        if "action" in Parameters:
            main_cmd = Command
            sub_cmd = Parameters["action"]

            if main_cmd in Commands and 'subcommands' in Commands[main_cmd]:
                CommandID = Commands[main_cmd]['hex_code']
                
                if sub_cmd in Commands[main_cmd]['subcommands']:
                    SubCommandID = Commands[main_cmd]['subcommands'][sub_cmd]['sub']
                else:
                    RespTaskDbg(f"Unknown subcommand: {sub_cmd}")
                    continue
            else:
                RespTaskDbg(f"Command doesn't support subcommands: {main_cmd}")
                continue
        else:
            if Command in Commands:
                CommandID = Commands[Command]['hex_code']
                SubCommandID = 0
            else:
                RespTaskDbg(f"Unknown command: {Command}")
                continue

        TaskPkg.Int16(int(CommandID))
        RespTaskDbg( f"command id: {CommandID}" )
        
        if SubCommandID != 0:
            TaskPkg.Int8(SubCommandID)
            RespTaskDbg( f"sub id: {SubCommandID}" )

        for Key, Val in Parameters.items():
            if Key != "action":
                try:
                    hex_bytes = bytes.fromhex(Val)
                    RespTaskDbg(f"key: {Key} parameter with len: {len(hex_bytes)} [type: hex:bytes]")
                    TaskPkg.Pad(hex_bytes)
                except (ValueError, AttributeError, TypeError):
                    if isinstance(Val, str):
                        RespTaskDbg(f"key: {Key} parameter: {Val} [type: str]")
                        TaskPkg.Bytes(str(Val).encode())
                    elif isinstance(Val, int):
                        RespTaskDbg(f"key: {Key} parameter: {int(Val)} [type: int]")
                        TaskPkg.Int32(int(Val))
                    elif isinstance(Val, bool):
                        RespTaskDbg(f"key: {Key} parameter: {int(Val)} [type: bool]")
                        TaskPkg.Int32(int(Val))
                    elif isinstance(Val, bytes):
                        RespTaskDbg(f"key: {Key} parameter: {len(Val)} [type: bytes]")
                        TaskPkg.Pad(Val)
            
        if SockPkg.buffer:
            sock_data = SockPkg.buffer
            Pkg.Bytes( sock_data )

        task_data = TaskPkg.buffer

        RespTaskDbg(f"task uuid: {TaskUUID} with data [{len(task_data)} bytes]")
        Pkg.Bytes(task_data)

    RespTaskDbg("------------------------")
    return Pkg.buffer

def RespPosting( Responses ):
    RespPostDbg( "------------------------" );

    if not Responses:
        RespPostDbg("No responses to post.")
        return b""

    RespPostDbg( f"responses: {Responses}" );

    Data = len( Responses ).to_bytes( 4, "big" );

    Pkg = Packer();

    for Response in Responses:
        if Response["status"] == "success":
            Data += b"\x01";
        else: 
            Data += b"\x00";
    
    RespPostDbg( f"status: {Response["status"]}" );

    if Response["status"] == "success":
        Pkg.Int32( 1 );
    else: 
        Pkg.Int32( 0 );
    
    for Response in Responses:
        FileID = Response.get( "file_id" )
        if FileID:
            Pkg.Bytes( FileID.encode( "utf-8" ) );
            RespPostDbg( f"file id: {FileID}" );

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
            RespPostDbg( f"Chunk Data: {len( base64.b64decode( ChunkData ) )} bytes" );
            Data = Pkg.buffer;

    RespPostDbg( "------------------------" );
    
    return Data
