from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from .Utils.u import *

import json
import os
import random
import string
import shlex

class DotnetInlineArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.String,
                description="Name or UUID of existing .NET assembly to execute",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="upload",
                cli_name="upload",
                type=ParameterType.File,
                description="Upload new .NET assembly (use @path/to/file)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                type=ParameterType.String,
                description="Arguments to pass to the assembly",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=3
                    )
                ]
            ),
            CommandParameter(
                name="appdomain",
                cli_name="appdomain",
                type=ParameterType.String,
                description="AppDomain name to use (random if not specified)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=4
                    )
                ]
            ),
            CommandParameter(
                name="keep",
                cli_name="keep",
                type=ParameterType.Number,
                description="Keep the AppDomain loaded after execution",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=5
                    )
                ]
            ),
            CommandParameter(
                name="version",
                cli_name="version",
                type=ParameterType.String,
                description=".NET version to use (default: v4.0.30319)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=5
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New File",
                        ui_position=6
                    )
                ]
            )
        ]

    async def parse_dictionary(self, dictionary: dict) -> None:
        if not isinstance(dictionary, dict):
            raise ValueError("Input must be a dictionary")
        
    async def parse_dictionary(self, dictionary: dict) -> None:
        if not isinstance(dictionary, dict):
            raise ValueError("Input must be a dictionary")
        
        self.add_arg("action", "inline")

        if not any(key in dictionary for key in ["file", "upload"]):
            raise ValueError("Either 'file' or 'upload' must be specified")

        if "file" in dictionary and "upload" in dictionary:
            raise ValueError("Cannot specify both 'file' and 'upload'")

        if "file" in dictionary:
            if not isinstance(dictionary["file"], str):
                raise ValueError("'file' must be a string (name or UUID)")
            self.add_arg("file", dictionary["file"])

        if "upload" in dictionary:
            if not isinstance(dictionary["upload"], str):
                raise ValueError("'upload' must be a string path")
            if dictionary["upload"].startswith("@"):
                self.add_arg("upload", dictionary["upload"][1:])
            else:
                self.add_arg("upload", dictionary["upload"])

        # Configuração do AppDomain
        if "appdomain" in dictionary:
            if not isinstance(dictionary["appdomain"], str):
                raise ValueError("'appdomain' must be a string")
            self.add_arg("appdomain", dictionary["appdomain"])
        else:
            self.add_arg("appdomain", ''.join(random.choice(string.ascii_letters) for _ in range(8)))

        if "keep" in dictionary:
            self.add_arg("keep", 1)
        else:
            self.add_arg("keep", 0)

        if "version" in dictionary:
            self.add_arg("version", dictionary.get("version", dictionary["version"]))
        else:
            self.add_arg("version", dictionary.get("version", "v0.0.00000"))
        

        args = dictionary.get("args", "")
        if isinstance(args, list):
            args = " ".join(args)
        elif not isinstance(args, str):
            args = str(args)
        
        if len(args) >= 2 and args[0] == args[-1] and args[0] in ('"', "'"):
            args = args[1:-1]
        
        self.add_arg("args", args)

        if "upload" in dictionary and not os.path.exists(dictionary["upload"]):
            raise ValueError(f"File not found: {dictionary['upload']}")

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply command line arguments")
        
        if self.command_line[0] == "{":
            try:
                dictionary = json.loads(self.command_line)
                await self.parse_dictionary(dictionary)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format")
        else:
            try:
                # Manual command line parsing
                argv = shlex.split(self.command_line)
                args_dict = {}
                i = 0
                
                while i < len(argv):
                    arg = argv[i]
                    if arg == "--file":
                        if i+1 >= len(argv):
                            raise ValueError("Missing value for --file")
                        args_dict["file"] = argv[i+1]
                        i += 2
                    elif arg == "--upload":
                        if i+1 >= len(argv):
                            raise ValueError("Missing value for --upload")
                        args_dict["upload"] = argv[i+1]
                        i += 2
                    elif arg == "--args":
                        if i+1 >= len(argv):
                            raise ValueError("Missing value for --args")
                        args_dict["args"] = argv[i+1]
                        i += 2
                    elif arg == "--appdomain":
                        if i+1 >= len(argv):
                            raise ValueError("Missing value for --appdomain")
                        args_dict["appdomain"] = argv[i+1]
                        i += 2
                    elif arg == "--keep":
                        args_dict["keep"] = True
                        i += 1
                    elif arg == "--version":
                        if i+1 >= len(argv):
                            raise ValueError("Missing value for --version")
                        args_dict["version"] = argv[i+1]
                        i += 2
                    else:
                        raise ValueError(f"Unknown argument: {arg}")
                
                await self.parse_dictionary(args_dict)
                
            except Exception as e:
                raise ValueError(f"Error parsing command line: {str(e)}")


class DotnetInlineCommand(CommandBase):
    cmd = "dotnet-inline"
    needs_admin = False
    help_cmd = """
    Execute a .NET assembly in the current process

    Usage with existing file:
    dotnet-inline --file <name_or_uuid> [--args "<arguments>"] [--appdomain <name>] [--keep] [--version <version>]

    Usage with new file upload:
    dotnet-inline --upload @<path_to_file> [--args "<arguments>"] [--appdomain <name>] [--keep] [--version <version>]

    Options:
    -file       Name or UUID of existing .NET assembly
    -upload     Upload new assembly (prefix path with @)
    -args       Arguments to pass to assembly (use quotes for complex args)
    -appdomain  AppDomain name (random if not specified)
    -keep       Keep AppDomain loaded after execution
    -version    .NET version (default: v4.0.30319)

    Examples:
    dotnet-inline -file Rubeus.exe -args "triage"
    dotnet-inline -file cf2bde20-d03e-461a-a3dd-a8a5a2693bf0 -args "-group=user"
    dotnet-inline -upload @/tmp/Seatbelt.exe -args "--group=user --computername=DC01"
    """
    description = "Execute a .NET assembly in the current process with support for file uploads and complex arguments"
    version = 2
    author = "@ Oblivion"
    attackmapping = ["T1055", "T1059", "T1027"]
    argument_class = DotnetInlineArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        file_name = None
        file_id = None
        file_contents = None

        if task.args.get_arg("upload"):
            try:
                file_path = task.args.get_arg("upload")
                if not os.path.exists(file_path):
                    raise Exception(f"File not found: {file_path}")
                
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                create_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                    TaskID=task.Task.ID,
                    FileContents=file_content,
                    Filename=os.path.basename(file_path),
                    DeleteAfterFetch=False
                ))
                
                if not create_resp.Success:
                    raise Exception(f"Failed to upload file: {create_resp.Error}")
                
                file_id = create_resp.AgentFileId
                file_name = create_resp.Filename
                file_contents = create_resp.FileContents
                
            except Exception as e:
                raise Exception(f"Error uploading file: {str(e)}")
        
        elif task.args.get_arg("file"):
            file_identifier = task.args.get_arg("file")
            
            if len(file_identifier) == 36 and '-' in file_identifier:
                file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=task.Task.ID,
                    AgentFileID=file_identifier,
                    LimitByCallback=True,
                    MaxResults=1
                ))
            else:
                file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=task.Task.ID,
                    Filename=file_identifier,
                    LimitByCallback=True,
                    MaxResults=1
                ))
            
            if not file_search.Success or len(file_search.Files) == 0:
                raise Exception(f"File '{file_identifier}' not found in Mythic")
            
            file_id = file_search.Files[0].AgentFileId
            file_name = file_search.Files[0].Filename
            
            file_contents = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id
            ))
            
            if not file_contents.Success:
                raise Exception(f"Failed to get contents of file '{file_name}'")
        
        else:
            raise Exception("Either --file or --upload must be specified")

        display_params = []
        
        if task.args.get_arg("upload"):
            display_params.append(f"-upload @{task.args.get_arg('upload')}")
        else:
            display_params.append(f"-file {file_name}")
        
        display_params.append(f"-appdomain {task.args.get_arg('appdomain')}")
        
        task.args.remove_arg("file")

        if task.args.get_arg("keep"):
            display_params.append("-keep")
        
        if task.args.get_arg('version') != "v0.0.00000":
            display_params.append(f"-version {task.args.get_arg('version')}")

        if task.args.get_arg("args"):
            display_params.append(f"-args \"{task.args.get_arg('args')}\"")
        else:
            task.args.set_arg("args", " ");

        task.args.add_arg("file_contents", file_contents.Content.hex() )

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=" ".join(display_params),
            CommandName="dotnet",
            Params=json.dumps(task.args.to_json()),
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        response = bytes.fromhex(response);
        Psr = Parser( response, len( response ) );
        bResp = ""
        bResp = Psr.Bytes()


        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=bResp
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )