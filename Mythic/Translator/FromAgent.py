from Translator.Utils import *

import ipaddress

def CheckinC2( Data ) -> dict:
    Psr = Parser( Data, len( Data ) );

    UUID   = Psr.Pad( 36 );

    OsName = "Windows";
    OsArch = Psr.Pad( 1 );

    if OsArch == 0x64:
        OsArch = "x64";
    elif OsArch == 0x86:
        OsArch = "0x86";

    UserName  = Psr.Str();
    HostName  = Psr.Str();
    Netbios   = Psr.Str();
    ProcessID = Psr.Int32();
    ImagePath = Psr.Str();
    ExternIp  = Psr.Str();

    InternIp = ["0.0.0.0"];

    JsonData = {
        "action": "checkin",
        "ips": InternIp,
        "os": OsName,
        "user": UserName,
        "host": HostName,
        "domain": Netbios,
        "process_name":ImagePath,
        "pid": ProcessID,
        "uuid": UUID.decode('cp850'),
        "architecture": OsArch.decode('cp850'),
        "externalIP": ExternIp,
    };

    GetChkDbg( f"checkin json: {JsonData}" );

    return JsonData;

def GetTaskingC2( Data ):
    GetTaskDbg( "------------------------" );

    numTasks = int.from_bytes( Data[0:4] );
    JsonData = { "action": "get_tasking", "tasking_size": numTasks };

    GetTaskDbg( f"quantity: {numTasks}" );

    GetTaskDbg( "------------------------" );

    return JsonData

def PostC2( Data ):

    RespPostDbg( "------------------------" );

    RespTsk = [];

    Psr = Parser( Data, len( Data ) );
    
    TaskUUID = Psr.Bytes().replace(b'\x00', b'')
    try:
        TaskUUID = TaskUUID.decode('utf-8')
    except UnicodeDecodeError:
        TaskUUID = TaskUUID.hex() 
    
    CommandID = Psr.Pad( 2 );
    CommandID = int.from_bytes( CommandID, byteorder="big" );

    UserOut  = "";
    RawBytes = b'';

    try:
        RawBytes = Psr.All();
        UserOut  = RawBytes.hex();
    except Exception as e:
        RespPostDbg( f"failed get raw argument from agent: {e}" );

    RespPostDbg( f"command id : {CommandID}" );
    RespPostDbg( f"task uuid  : {TaskUUID}" );
    RespPostDbg( f"user output: {UserOut}" );

    JsonTsk = {
        "task_id": TaskUUID,  
        "process_response": UserOut,
        # "user_output": UserOut,
        "completed": True
    };

    RespTsk.append( JsonTsk );
    
    JsonData = {
        "action": "post_response",
        "responses": RespTsk
    };

    RespPostDbg( f"json data: {JsonData}" );
    RespPostDbg( f"json task: {JsonTsk}" );

    RespPostDbg( "------------------------" );

    return JsonData;