from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from collections import OrderedDict
import re

from .Utils.u import *

class FsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                type=ParameterType.ChooseOne,
                description="Action to execute",
                choices=["ls", "cat", "pwd", "cd", "mv", "cp", "rm", "mkdir"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="Path for directory operations",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.String,
                description="File to read/remove",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name="source",
                cli_name="source",
                type=ParameterType.String,
                description="Source file/directory",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name="destination",
                cli_name="destination",
                type=ParameterType.String,
                description="Destination file/directory",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=3
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
            return
            
        # Handle CLI parsing with explicit flags
        try:
            # Split while preserving quoted strings
            parts = []
            current = ""
            in_quote = False
            for char in self.command_line:
                if char == '"':
                    in_quote = not in_quote
                elif char == ' ' and not in_quote:
                    if current:
                        parts.append(current)
                        current = ""
                    continue
                current += char
            if current:
                parts.append(current)
            
            # First part should be the action
            if not parts:
                raise ValueError("Must specify an action")
                
            action = parts[0].lower()
            if action not in ["ls", "cat", "pwd", "cd", "mv", "cp", "rm", "mkdir"]:
                raise ValueError(f"Invalid action: {action}")
            self.add_arg("action", action)
            
            # Remove action from parts
            parts = parts[1:]
            
            # Parse based on action
            if action == "pwd":
                if parts:
                    raise ValueError("pwd action takes no arguments")
                return
                
            elif action in ["ls", "cd", "mkdir"]:
                path = None
                
                # Check for explicit -path flag
                for i, part in enumerate(parts):
                    if part == "-path" and i < len(parts)-1:
                        path = parts[i+1].strip('"')
                        break
                
                # If no flag, take the first argument as path
                if path is None and parts:
                    path = parts[0].strip('"')
                
                if path:
                    self.add_arg("path", path)
                
                # For cd, path can be empty (means go to home)
                if action in ["ls", "mkdir"] and not path:
                    if action == "mkdir":
                        raise ValueError("mkdir requires a path")
                    # For ls, default to current directory
                    self.add_arg("path", ".")
                
            elif action in ["cat", "rm"]:
                file = None
                
                # Check for explicit -file flag
                for i, part in enumerate(parts):
                    if part == "-file" and i < len(parts)-1:
                        file = parts[i+1].strip('"')
                        break
                
                # If no flag, take the first argument as file
                if file is None and parts:
                    file = parts[0].strip('"')
                
                if not file:
                    raise ValueError(f"{action} requires a file parameter")
                
                self.add_arg("file", file)
                
            elif action in ["mv", "cp"]:
                source = None
                destination = None
                next_is_source = False
                next_is_dest = False
                
                for i, part in enumerate(parts):
                    if part == "-source" or part == "-src":
                        next_is_source = True
                    elif part == "-destination" or part == "-dest" or part == "-dst":
                        next_is_dest = True
                    elif next_is_source:
                        source = part.strip('"')
                        next_is_source = False
                    elif next_is_dest:
                        destination = part.strip('"')
                        next_is_dest = False
                
                if source is None and destination is None and len(parts) >= 2:
                    source = parts[0].strip('"')
                    destination = parts[1].strip('"')
                
                if not source or not destination:
                    raise ValueError(f"{action} requires both source and destination parameters")
                
                self.add_arg("source", source)
                self.add_arg("destination", destination)
                
        except Exception as e:
            raise ValueError(f"Error parsing command line: {str(e)}")

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)
        
        action = dictionary.get("action")
        if not action:
            raise ValueError("Action parameter is required")
            
        action = action.lower()
        if action not in ["ls", "cat", "pwd", "cd", "mv", "cp", "rm", "mkdir"]:
            raise ValueError(f"Invalid action: {action}")
        
        if action == "pwd":
            if any(k for k in dictionary.keys() if k not in ["action", "task_id"]):
                raise ValueError("pwd action takes no additional parameters")
                
        elif action in ["ls", "cd", "mkdir"]:
            path = dictionary.get("path")
            if action == "mkdir" and not path:
                raise ValueError("mkdir requires a path parameter")
            
        elif action in ["cat", "rm"]:
            if not dictionary.get("file"):
                raise ValueError(f"{action} requires a file parameter")
                
        elif action in ["mv", "cp"]:
            if not dictionary.get("source"):
                raise ValueError(f"{action} requires a source parameter")
            if not dictionary.get("destination"):
                raise ValueError(f"{action} requires a destination parameter")

class FsCommand(CommandBase):
    cmd         = "exec"
    needs_admin = False
    help_cmd    = \
    """
    File System Operations

    Usage:
    fs -action <action> [parameters]

    Actions and Parameters:
    - ls [-path <path>]       - List directory contents (default: current directory)
    - cat -file <file>        - Display file contents
    - pwd                     - Print working directory
    - cd [-path <path>]       - Change directory (default: home directory)
    - mv -source <src> -destination <dst>  - Move/rename file or directory
    - cp -source <src> -destination <dst>  - Copy file or directory
    - rm -file <path>         - Remove file or directory
    - mkdir -path <path>      - Create directory

    Examples:
    fs -action ls -path /tmp
    fs -action cat -file /etc/passwd
    fs -action pwd
    fs -action mv -source old.txt -destination new.txt
    fs -action cp -source file.txt -destination /backups/
    fs -action rm -file /tmp/junk
    fs -action mkdir -path /new/folder
    """
    description = "File system operations command with multiple actions"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1083", "T1106", "T1570"]
    browser_script = BrowserScript("ls_new", "@Oblivion", for_new_ui=True)
    argument_class = FsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        action = task.args.get_arg("action").lower()
        display_params = f"-action {action}"
        
        if action == "pwd":
            pass  # No additional parameters
            
        elif action in ["ls", "cd", "mkdir"]:
            path = task.args.get_arg("path")
            if path:
                display_params += f" -path \"{path}\""
                if action == "ls":
                    task.args.add_arg("path", path + "\\*" if path != "." else ".\\*")
                else:
                    task.args.add_arg("path", path)
            elif action == "ls":
                if path is None:
                    path = "."
                    task.args.add_arg("path", path + "\\*" if path != "." else ".\\*")
            elif action == "mkdir":
                raise ValueError("mkdir requires a path parameter")
                
        elif action in ["cat", "rm"]:
            file = task.args.get_arg("file")
            if not file:
                raise ValueError(f"{action} requires a file parameter")
            display_params += f" -file \"{file}\""
            task.args.add_arg("file", file)
            
        elif action in ["mv", "cp"]:
            source = task.args.get_arg("source")
            destination = task.args.get_arg("destination")
            if not source or not destination:
                raise ValueError(f"{action} requires both source and destination parameters")
            display_params += f" -source \"{source}\" -destination \"{destination}\""
            task.args.add_arg("source", source)
            task.args.add_arg("destination", destination)
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=display_params,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True
                )
                
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            output_data = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            if sub_id == SB_FS_LS:
                file_list = []
                
                while Psr.buffer:
                    try:
                        file_info = OrderedDict()
                        
                        file_info['Name'] = Psr.Str()
                        FileSize = Psr.Int32()
                        Attribute = Psr.Int32()
                        
                        if FileSize == -1:
                            file_info['Type'] = "DIR"
                            file_info['Size'] = None
                        else:
                            file_info['Type'] = "FILE"
                            file_info['Size'] = f"{FileSize}" 
                        
                        def TimePsr():
                            Day = Psr.Int16()
                            Month = Psr.Int16()
                            Year = Psr.Int16()
                            Hour = Psr.Int16()
                            Minute = Psr.Int16()
                            Second = Psr.Int16()
                            return f"{Year:04d}-{Month:02d}-{Day:02d} {Hour:02d}:{Minute:02d}:{Second:02d}"
                        
                        file_info['Created'] = TimePsr()
                        file_info['Accessed'] = TimePsr()
                        file_info['Modified'] = TimePsr()
                        
                        AttrMap = {
                            0x1: "R", 0x2: "H", 0x4: "S",
                            0x10: "D", 0x20: "A", 0x40: "N", 0x80: "T"
                        }
                        file_info['Attributes'] = "".join(v for k, v in AttrMap.items() if Attribute & k) or "?"
                        
                        file_list.append(file_info)
                        
                    except struct.error:
                        break
                
                output_data = {
                    "DirectoryListing": file_list,
                    "Count": len(file_list)
                }
                
                Output = json.dumps(output_data, indent=4)

                Remaining = len(Psr.All())
                if Remaining > 0:
                    Output += f"\nWarning: {Remaining} unparsed bytes remaining\n"

            elif sub_id == SB_FS_CAT or sub_id == SB_FS_PWD:
                Output = Psr.Str()
            
            else:
                BooleanTask = Psr.Int32()

                if BooleanTask == 1:
                    Output = "Task Executed with Success"
                else:
                    Output = "Task Failed"
                

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=Output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )