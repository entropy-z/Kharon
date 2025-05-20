import struct
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

SB_CFG_JITTER   = 14;
SB_CFG_SLEEP    = 15;
SB_CFG_MASK     = 16;
SB_CFG_SC       = 17;
SB_CFG_PE       = 18;
SB_CFG_PPID     = 19;
SB_CFG_BLOCK    = 20;
SB_CFG_CURDIR   = 21;
SB_CFG_ARG      = 22;
SB_CFG_KILLDATE = 23;
SB_CFG_WORKTIME = 24;

mask_id = {
    "timer": 1,
    "none": 3
}

shellcode_id = {
    "classic": 0,
    "stomp": 1
}

pe_id = {
    "reflection": 0
}

config_id = {
    "jitter": SB_CFG_JITTER,
    "sleep":  SB_CFG_SLEEP,
    "mask":   SB_CFG_MASK,
    "injection-sc": SB_CFG_SC,
    "injection-pe":  SB_CFG_PE,
    "ppid":   SB_CFG_PPID,
    "block":  SB_CFG_BLOCK,
    "curdir": SB_CFG_CURDIR,
    "arg": SB_CFG_ARG,
    "killdate": SB_CFG_KILLDATE,
    "worktime": SB_CFG_WORKTIME
}

SB_FS_LS    = 30;
SB_FS_CAT   = 31;
SB_FS_PWD   = 32;
SB_FS_CD    = 33;
SB_FS_MV    = 34;
SB_FS_CP    = 35;
SB_FS_DEL   = 36;
SB_FS_MKDIR = 37;

SB_PS_LIST   = 20;
SB_PS_CREATE = 21;
SB_PS_KILL   = 22;

class Parser:
    buffer: bytes = b'';
    length: int   = 0;

    def __init__( self, buffer, length ):

        self.buffer = buffer;
        self.length = length;

        return;

    def Int16( self ):

        val = struct.unpack( ">h", self.buffer[ :2 ] );
        self.buffer = self.buffer[ 2: ];

        return val[ 0 ];

    def Int32( self ) -> int:

        val = struct.unpack( ">i", self.buffer[ :4 ] );
        self.buffer = self.buffer[ 4: ];

        return val[ 0 ];

    def Int64( self ):

        val = struct.unpack( ">q", self.buffer[ :8 ] );
        self.buffer = self.buffer[ 8: ];

        return val[ 0 ];

    def Bytes( self ) -> bytes:

        length      = self.Int32();

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Pad( self, length: int ) -> bytes:

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Str( self ) -> str:
        return self.Bytes().decode('utf-8', errors="replace");
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining
    

def StorageExtract(Data):
    """Extract and organize all agent storage data efficiently"""
    
    Psr = Parser(Data, len(Data))
    
    # Architecture detection
    OsArch = Psr.Pad(1)
    OscArc = "unknown"
    if isinstance(OsArch, bytes):
        OsArch = int.from_bytes(OsArch, byteorder='big', signed=False)
    OscArc = "x64" if OsArch == 0x64 else "x86" if OsArch == 0x86 else OscArc

    # Basic Info
    username = Psr.Str()
    hostname = Psr.Str()
    netbios = Psr.Str()
    process_id = Psr.Int32()
    image_path = Psr.Str()
    internal_ip = ["0.0.0.0"]  # Default value
    architecture = OscArc

    # Evasion
    syscall_enabled = bool(Psr.Int32())
    stack_spoof_enabled = bool(Psr.Int32())
    bof_hook_api_enabled = bool(Psr.Int32())
    bypass_dotnet = Psr.Int32()

    if bypass_dotnet == 0x100:
        bypass_dotnet = "amsi and etw"
    elif bypass_dotnet == 0x400:
        bypass_dotnet = "amsi"
    elif bypass_dotnet == 0x700:
        bypass_dotnet = "etw"
    else:
        bypass_dotnet = "none"

    # Killdate
    killdate_enabled = bool(Psr.Int32())
    exit_method = Psr.Int32()
    self_delete = bool(Psr.Int32())
    killdate_year = Psr.Int16()
    killdate_month = Psr.Int16()
    killdate_day = Psr.Int16()
    killdate_date = f"{killdate_year}-{killdate_month:02d}-{killdate_day:02d}"

    # Process Info
    command_line = Psr.Str()
    heap_address = f"0x{Psr.Int32():08X}"
    elevated = bool(Psr.Int32())
    jitter = f"{Psr.Int32()}%"
    sleep_time = f"{Psr.Int32()}ms"
    parent_id = Psr.Int32()
    process_arch = Psr.Int32()
    kharon_base = f"0x{Psr.Int64():016X}"
    kharon_len = Psr.Int32()
    thread_id = Psr.Int32()

    # Mask Info
    jmp_gadget = f"0x{Psr.Int64():016X}"
    ntcontinue_gadget = f"0x{Psr.Int64():016X}"
    technique_id = Psr.Int32()

    # Process Context
    parent = Psr.Int32()
    pipe = Psr.Int32()
    current_dir = Psr.Str()
    block_dlls = bool(Psr.Int32())

    # System Resources
    processor_name = Psr.Str()
    total_ram = f"{Psr.Int32()}MB"
    available_ram = f"{Psr.Int32()}MB"
    used_ram = f"{Psr.Int32()}MB"
    ram_usage = f"{Psr.Int32()}%"
    processor_count = Psr.Int32()

    # Build the JSON structure
    data = {
        "basic_info": {
            "username": username,
            "hostname": hostname,
            "netbios": netbios,
            "process_id": process_id,
            "image_path": image_path,
            "internal_ip": internal_ip,
            "architecture": architecture
        },
        "evasion": {
            "syscall_enabled": syscall_enabled,
            "stack_spoof_enabled": stack_spoof_enabled,
            "bof_hook_api_enabled": bof_hook_api_enabled,
            "bypass_dotnet": bypass_dotnet
        },
        "killdate": {
            "enabled": killdate_enabled,
            "exit_method": exit_method,
            "self_delete": self_delete,
            "date": killdate_date
        },
        "process_info": {
            "command_line": command_line,
            "heap_address": heap_address,
            "elevated": elevated,
            "jitter": jitter,
            "sleep_time": sleep_time,
            "parent_id": parent_id,
            "process_arch": process_arch,
            "kharon_base": kharon_base,
            "kharon_len": kharon_len,
            "thread_id": thread_id
        },
        "mask_info": {
            "jmp_gadget": jmp_gadget,
            "ntcontinue_gadget": ntcontinue_gadget,
            "technique_id": technique_id
        },
        "process_context": {
            "parent": parent,
            "pipe": pipe,
            "current_dir": current_dir,
            "block_dlls": block_dlls
        },
        "system_resources": {
            "processor_name": processor_name,
            "total_ram": total_ram,
            "available_ram": available_ram,
            "used_ram": used_ram,
            "ram_usage": ram_usage,
            "processor_count": processor_count
        }
    }

    return data


async def default_completion_callback(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    out = ""
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=completionMsg.SubtaskData.Task.ID))
    responses
    for output in responses.Responses:
        out += str(output.Response)
            
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=completionMsg.TaskData.Task.ID,
        Response=f"{out}"
    ))
    return response

class CallbackCommandBase(CommandBase):
    completion_functions = {"completion_callback": default_completion_callback}