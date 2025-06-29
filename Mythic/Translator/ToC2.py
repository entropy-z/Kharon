from Translator.Utils import *
from mythic_container.MythicRPC import *
import ipaddress

async def CheckinC2(Data, Key) -> dict:
    Psr = Parser(Data, len(Data))

    UUID = Psr.Pad(36)
    StorageData = Psr.buffer + Key

    OsName  = "Windows"
    OsArch  = Psr.Pad(1)
    OscArc  = ""

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

    # Injection
    alloc_method = Psr.Int32()
    write_method = Psr.Int32()

    # Evasion
    syscall_enabled = Psr.Int32()
    stack_spoof_enabled = Psr.Int32()
    bof_hook_api_enabled = Psr.Int32()
    bypass_enabled = Psr.Int32()
    patchexit = Psr.Int32()
    
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

    encryption_key = Key

    print(f"\n[*] System Resources:")
    print(f"    Processor: {processor_name}")
    print(f"    Total RAM: {total_ram}MB")
    print(f"    Available RAM: {aval_ram}MB")
    print(f"    Used RAM: {used_ram}MB")
    print(f"    RAM Usage: {percent_ram}%")
    print(f"    Processor Count: {processors_nbr}")

    print( f"encryption_key: {encryption_key}" )

    await SendMythicRPCAgentStorageCreate(MythicRPCAgentstorageCreateMessage(
        UUID.decode("utf-8"), StorageData
    ))

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

def QuickOut( Data ):
    Psr       = Parser( Data, len(Data) )
    UUID      = Psr.Pad(36) 
    CommandID = Psr.Int32()

    JsonData = {
        "action": "post_response",
        "responses": []
    }

    logging.info(f"id {CommandID}")

    if CommandID == 0:
        CallbackType = Psr.Int32()
        CallbackOut  = Psr.Bytes().decode("utf-8", errors="ignore")  

        message_types = {
            KH_CALLBACK_OUTPUT: ("[+] Received Output", "user_output"),
            KH_CALLBACK_ERROR: ("[x] Received Error", "user_output"),
        }

        prefix, response_key = message_types.get(CallbackType, ("[?] Received Unknown Callback", "user_output"))
        Message = f"{prefix}:\n{CallbackOut}"

        logging.info(f"command id 0 and message {Message}")

        Response = {
            "task_id": UUID.decode("utf-8", errors="ignore"),
            response_key: Message
        }
    else:
        CallbackType = Psr.Int32()
        logging.info(f"type {CallbackType}")
        ProcessOut   = Psr.Bytes()
        logging.info(f"output length: {len(ProcessOut)}")
        if callable(ProcessOut):
            ProcessOut = ProcessOut()
        
        if isinstance(ProcessOut, bytes):
            ProcessOut = ProcessOut.hex()

        Response = {
            "task_id": UUID.decode("utf-8", errors="ignore"),
            "process_response": ProcessOut,
            "completed": False
        }

    JsonData["responses"].append(Response)
    return JsonData
    

def QuickMsg( Data ):
    Psr = Parser( Data, len( Data ) )
    UUID         = Psr.Pad( 36 )
    CallbackType = Psr.Int32()
    CallbackMsg  = Psr.Str()

    FinalMsg = ""
    
    if CallbackType == KH_CALLBACK_ERROR:
        FinalMsg = f"[x] Received Error:\n{CallbackMsg}"
    elif CallbackType == KH_CALLBACK_OUTPUT:
        FinalMsg = f"[+] Received Output:\n{CallbackMsg}"
    elif CallbackType == KH_CALLBACK_NO_PRE_MSG:
        FinalMsg = f"{CallbackMsg}"
    else:
        FinalMsg = f"[?] Callback type not recognized... (just can be used [CALLBACK_OUTPUT|CALLBACK_ERROR])\n"

    logging.info(f"MSG => {FinalMsg} with task uuid: {UUID} and callback type: {CallbackType}")

    JsonData = {
        "action": "post_response",
        "responses": [
            {
                "task_id": UUID.decode("utf-8"),
                "user_output": FinalMsg,
                "completed": False
            }
        ],
    }
 
    logging.info(f":MSG => JSON data: {JsonData}")

    return JsonData

def PostC2(Data):
    Dbg2("------------------------")
    RespTsk = [] 
    RespSck = []

    Dbg3(f"buffer: {Data} [{len(Data)}]")

    try:
        Psr = Parser(Data, len(Data))
        Tasks = Psr.Int32()
        Dbg2(f"Task quantity: {Tasks}")

        Index = 0
        for Task in range(Tasks):
            Index += 1
            try:
                Profile = Psr.Int32()
                TaskLength = Psr.Int32()
                if TaskLength <= 0:
                    Dbg2(f"Invalid task length: {TaskLength}")
                    continue
                
                Dbg2(f"profile c2 task: {Profile}")
                Dbg2(f"task #{Index} len:{TaskLength}")
                TaskData = Psr.Pad(TaskLength)
                if len(TaskData) < TaskLength:
                    Dbg2(f"Incomplete task data, expected {TaskLength} got {len(TaskData)}")
                    continue
                    
                TaskPsr = Parser(TaskData, TaskLength)
                
                try:
                    TaskUUID = TaskPsr.Bytes().replace(b'\x00', b'')
                    TaskUUID = TaskUUID.decode('utf-8') if TaskUUID else "unknown"
                except UnicodeDecodeError:
                    TaskUUID = TaskUUID.hex() if TaskUUID else "unknown"
                
                try:
                    CommandID = TaskPsr.Pad(2)
                    CommandID = int.from_bytes(CommandID, byteorder="big") if len(CommandID) == 2 else 0

                    Dbg2(f"Process command id: {CommandID}")
                except Exception as e:
                    CommandID = 0
                    Dbg2(f"Failed to read CommandID: {str(e)}")

                if CommandID == T_SOCKS:
                    try:
                        Ext = TaskPsr.Int32()
                        Srv = TaskPsr.Int32()
                        Data = ""
                        
                        Dbg2(f"exit {bool(Ext)}")
                        Dbg2(f"id {Srv}")

                        Dbg2( f"{TaskPsr.length}" )

                        if not bool( Ext ) and TaskPsr.length > 0:
                            try:
                                Data = TaskPsr.Bytes().decode("utf-8")
                                Dbg2(f"sending socks encoded: {Data[:30]}... [{len(Data)} bytes]")
                                # Data = base64.b64encode(Data).decode("utf-8")
                                # Dbg2(f"sending socks encoded: {Data[:30]}... [{len(Data)} bytes]")
                            except Exception as e:
                                Dbg2(f"Failed to encode socks data: {str(e)}")
                                Data = ""
                        
                        SocksData = {
                            "exit": bool(Ext),
                            "server_id": Srv,
                            "data": Data 
                        }
                        RespSck.append(SocksData)
                    except Exception as e:
                        Dbg2(f"Failed to process socks task: {str(e)}")
                else:
                    try:
                        JsonTsk = process_normal_task(TaskUUID, CommandID, TaskPsr)
                        RespTsk.append(JsonTsk)
                    except Exception as e:
                        Dbg2(f"Failed to process normal task {TaskUUID}: {str(e)}")

            except Exception as e:
                Dbg2(f"Error processing task {Task}: {str(e)}")
                continue

    except Exception as e:
        Dbg2(f"Fatal error in PostC2: {str(e)}")
        return {"action": "post_response", "responses": [], "error": str(e)}

    JsonData = {
        "action": "post_response",
        "responses": RespTsk,
    }

    if RespSck:
        JsonData["socks"] = RespSck

    Dbg2(f"Processed {len(RespTsk)} tasks and {len(RespSck)} socks")
    Dbg2("------------------------")
    return JsonData

def process_delegates(TaskUUID, Message, Psr:Parser):

    delegates_list = []

    delegates = Psr.Int32()

    for delegate in delegates:
        uuid         = Psr.Str()
        profile_name = Psr.Int32()
        message      = Psr.Bytes()

        delegate_data = {
            "uuid": uuid,
            "message": message,
            "c2_profile": profile_name            
        }

        delegates_list.append( delegate_data )

    return {"delegates": delegates_list}

def process_normal_task(TaskUUID, CommandID, TaskPsr:Parser):
    if   CommandID == T_DOWNLOAD:
        return {"task_id": TaskUUID, "download": {...}}
    elif CommandID == T_UPLOAD:
        return {"task_id": TaskUUID, "upload": {...}}
    elif CommandID == JOB_ERROR:
        ErrorCode = TaskPsr.Int32()
        ErrorMsg  = TaskPsr.Bytes().decode("utf-8")  

        Dbg2(f"[{ErrorCode}] {ErrorMsg}")

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
    
    