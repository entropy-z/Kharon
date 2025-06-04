from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetSessionArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Target Host",
                type=ParameterType.String,
                description="Target host to enumerate sessions (default: localhost)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                if self.command_line.strip():
                    self.add_arg("hostname", self.command_line.strip())

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetSessionCommand(CommandBase):
    cmd = "net-session"
    needs_admin = False
    help_cmd = "net-session [hostname]"
    description = """
    Enumerate active sessions on the specified host using NetSessionEnum.
    
    Without arguments, enumerates sessions on localhost.
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = NetSessionArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("get-netsession.x64.o", task.Task.ID)

        hostname = task.args.get_arg("hostname") or "localhost"

        display_params = ""
        
        if hostname:
            display_params = f"-hostname \\\\{hostname}"

        bof_args = [
            {"type": "char", "value": hostname}
        ]

        task.args.remove_arg("hostname")
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp