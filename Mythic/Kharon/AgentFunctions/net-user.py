from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetUserArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username to query (leave empty for all users)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain to query (default: current domain)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    self.add_arg("username", args[0])
                if len(args) >= 2:
                    self.add_arg("domain", args[1])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetUserCommand(CommandBase):
    cmd = "net-user"
    needs_admin = False
    help_cmd = "net-user -username [username] -domain [domain]"
    description = """
    Query user information from the domain or local system.
    
    Without arguments, lists all users.
    With username, shows detailed information about specific user.
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = NetUserArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_netuser.x64.o", task.Task.ID)

        username = task.args.get_arg("username") or ""
        domain = task.args.get_arg("domain") or ""

        display_params = ""
        if username:
            display_params += f" {username}"
        if domain:
            display_params += f" @{domain}"
        if not display_params:
            display_params = " (all users)"

        bof_args = [
            {"type": "char", "value": username},
            {"type": "char", "value": domain}
        ]

        task.args.remove_arg("username")
        task.args.remove_arg("domain")
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params.strip()
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp