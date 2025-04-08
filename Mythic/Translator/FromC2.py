from Translator.Utils import *

def Checkin( data:bytes ) -> dict:

    RespChkDbg( "------------------------" );

    ParserMg = Parser( data, len( data ) );
    UUID     = ParserMg.ParseBytes();
    OsName   = ParserMg.ParseBytes();
    OsArch   = ParserMg.ParsePad( 1 );

    if   OsArch == 0x64:
         OsArch = "x64"
    elif OsArch == 0x86:
         OsArch = "x86"

    UserName    = ParserMg.ParseBytes();
    HostName    = ParserMg.ParseBytes();
    ProcessID   = ParserMg.ParseInt();
    ProcessName = ParserMg.parse_str();
    ExternalIP  = ParserMg.parse_str();
    IpTableLen  = ParserMg.parse_int();

    Idx     = 0;
    IpArray = [];
    while IpTableLen < Idx:
        IpA  = ParserMg.parse_int();
        Addr = str( ipaddress.ip_address( IpA ) );
        IpArray.append( Addr );
        Idx  += 1;
    
    JsonData = {
        "action": "checkin",
        "ips": IpArray,
        "os": OsName,
        "user": UserName,
        "host": HostName,
        "domain": HostName,
        "process_name":ProcessName,
        "pid": ProcessID,
        "uuid": UUID.decode('cp850'),
        "architecture": OsArch,
        "externalIP": ExternalIP,
    }

    RespChkDbg( f"showing json\n {JsonData}" );
    RespChkDbg( "------------------------\n" );

    return JsonData

def GetTasking( data ):
    print( "" );
    print( "[GET_TASKING]" );
    numTasks = int.from_bytes( data[0:4] );
    JsonData = { "action": "get_tasking", "tasking_size": numTasks };
    print( f"showing json {JsonData}" );
    return JsonData

def PostResponse( Data ):
    
    RespPostDbg( "------------------------" );

    RespTsk = [];

    TskParser = Parser( Data, len( Data ) );
    TaskUUID  = TskParser.ParseBytes();
    CommandID = TskParser.ParsePad( 1 );
    CommandID = int.from_bytes( CommandID, byteorder="big" );
    UserOut   = "";

    RespPostDbg( f"command id : {CommandID}" );
    RespPostDbg( f"task uuid  : {TaskUUID}" );
    RespPostDbg( f"task uuid decoded: {TaskUUID.decode('cp850')}" );
    RespPostDbg( f"user output: {UserOut}" );

    JsonTsk = {
        "task_id"    : TaskUUID.decode('cp850'),
        "user_output": UserOut,
    }

    JsonTsk["completed"] = True;
    RespTsk.append( JsonTsk );
    
    JsonData = {
        "action": "post_response",
        "responses": RespTsk
    };

    RespPostDbg( f"json data: {JsonData}" );
    RespPostDbg( f"json task: {JsonTsk}"  );

    RespPostDbg( "------------------------\n" );

    return JsonData


def RespCheckin( uuid ):
    RespChkDbg( "------------------------" );
    Data = Commands["checkin"]["hex_code"].to_bytes( 1, "big" ) + uuid.encode() + b"\x01";
    RespChkDbg( f"Data: {Data}" );
    RespChkDbg( "------------------------\n" );

    return Data;

def RespPosting( Responses ):
    RespPostDbg( "------------------------" );
    Data = len( Responses ).to_bytes( 4, "big" );
    for Response in Responses:
        if Response["status"] == "success":
            Data += b"\x01";
        else: 
            Data += b"\x00";
    RespPostDbg( f"Status: {Response["status"]}" );
    RespPostDbg( f"Data  : {Data}" );
    RespPostDbg( "------------------------\n" );
    
    return Data
