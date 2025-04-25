from Translator.Utils import *

import ipaddress

def CheckinC2( Data ) -> dict:
    Psr = Parser( Data, len( Data ) );

    UUID   = Psr.Pad( 36 );

    OsName = "Windows";
    OsArch = Psr.Pad( 1 );
    OscArc = ""

    if isinstance(OsArch, bytes):
        OsArch = int.from_bytes(OsArch, byteorder='big', signed=False)

    if OsArch == 0x64:
        OscArc = "x64";
    elif OsArch == 0x86:
        OscArc = "0x86";

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
        "architecture": OscArc,
        "externalIP": ExternIp,
    };

    GetChkDbg( f"checkin json: {JsonData} arch {OsArch}" );

    return JsonData;

def GetTaskingC2( Data ):
    GetTaskDbg( "------------------------" );

    JsonData = { "action": "get_tasking", "tasking_size": -1 };

    GetTaskDbg( f"getting all tasks" );

    GetTaskDbg( "------------------------" );

    return JsonData

def PostC2(Data):
    RespPostDbg("------------------------")
    RespTsk = [] 
    RespSck = []

    Psr = Parser(Data, len(Data))
    Tasks = Psr.Int32()
    RespPostDbg(f"Task quantity: {Tasks}")

    for Task in range(Tasks):
        TaskLength = Psr.Int32()
        TaskData = Psr.Pad(TaskLength)
        TaskPsr = Parser(TaskData, TaskLength)
        
        TaskUUID = TaskPsr.Bytes().replace(b'\x00', b'')
        try:
            TaskUUID = TaskUUID.decode('utf-8')
        except UnicodeDecodeError:
            TaskUUID = TaskUUID.hex()
        
        CommandID = TaskPsr.Pad(2)
        CommandID = int.from_bytes(CommandID, byteorder="big")

        if CommandID == T_SOCKS:
            Ext = TaskPsr.Int32()
            Srv = TaskPsr.Int32()
            
            if TaskPsr.buffer is not None:
                Data = TaskPsr.Bytes()
                Data = base64.b64encode( Data ).decode( "utf-8" )
            else:
                Data = ""
            
            SocksData = {
                "exit": bool(Ext),
                "server_id": Srv,
                "data": Data 
            }
            RespSck.append(SocksData)
        else:
            JsonTsk = process_normal_task(TaskUUID, CommandID, TaskPsr)
            RespTsk.append(JsonTsk)

    JsonData = {
        "action": "post_response",
        "responses": RespTsk,
    }

    if RespSck:
        JsonData["socks"] = RespSck

    RespPostDbg(f"JSON data: {JsonData}")
    RespPostDbg("------------------------")
    return JsonData

def process_normal_task(TaskUUID, CommandID, TaskPsr):
    if CommandID == T_DOWNLOAD:
        return {"task_id": TaskUUID, "download": {...}}
    elif CommandID == T_UPLOAD:
        return {"task_id": TaskUUID, "upload": {...}}
    elif CommandID == JOB_ERROR:
        ErrorCode = TaskPsr.Int32()
        ErrorMsg  = TaskPsr.Bytes().decode("utf-8")  

        if ErrorCode < 0:
            hex_code = f"{ErrorCode & 0xFFFFFFFF:X}" 
            Output   = f"({hex_code}) {ErrorMsg}"
        else:
            Output = f"({ErrorCode}) {ErrorMsg}"
        return {"task_id": TaskUUID, "user_output": Output, "completed": True}
    else:
        try:
            RawBytes = TaskPsr.All()
            Output   = RawBytes.hex()
        except Exception as e:
            RespPostDbg( f"failed get raw argument from agent: {e}" )
        return {"task_id": TaskUUID, "process_response": Output, "completed": True}