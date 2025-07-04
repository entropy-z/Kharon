from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class ScstopArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                cli_name="service_name",
                display_name="Service Name",
                type=ParameterType.String,
                description="Target service name to query",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Hostname",
                type=ParameterType.String,
                description="Target host to query (default: localhost)",
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
                    self.add_arg("hostname", args[0])
                if len(args) >= 2:
                    self.add_arg("service_name", args[1])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class ScstopCommand(CommandBase):
    cmd = "sc-stop"
    needs_admin = False
    help_cmd = "sc-stop -hostname [hostname] -service [service_name]"
    description = \
    """
    Stop the specified service
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ScstopArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_sc_stop.x64.o", task.Task.ID)

        hostname = task.args.get_arg("hostname") or 'localhost'
        service_name = task.args.get_arg("service_name") or '' 
        display_params = ""

        if hostname :
            display_params += f" -hostname {hostname}"
        
        if service_name:
            display_params += f" -service {service_name}"

        bof_args = [
            {"type": "char", "value": hostname},
            {"type": "char", "value": service_name}
        ]

        task.args.remove_arg("hostname")
        task.args.remove_arg("service_name")
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
