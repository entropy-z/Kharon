from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class ScqueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="service_name",
                cli_name="service_name",
                display_name="Service Name",
                type=ParameterType.String,
                description="Target service name to query",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Hostname",
                type=ParameterType.String,
                description="Target host to query (default: localhost)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Binary Path",
                type=ParameterType.String,
                description="Binary path for the service",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="display_name",
                cli_name="display_name",
                display_name="Display Name",
                type=ParameterType.String,
                description="Display name for the service",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="description",
                cli_name="description",
                display_name="Description",
                type=ParameterType.String,
                description="Service description",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ignore_mode",
                cli_name="ignore_mode",
                display_name="Ignore Mode",
                type=ParameterType.Number,
                description="Whether to ignore service mode (0 or 1)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="start_mode",
                cli_name="start_mode",
                display_name="Start Mode",
                type=ParameterType.Number,
                description="Service start mode (0-4)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="service_type",
                cli_name="service_type",
                display_name="Service Type",
                type=ParameterType.Number,
                description="Service type (1=Kernel, 2=FileSystem, 3=Adapter, 4=Recognizer)",
                default_value=0,
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
                if len(args) >= 3:
                    self.add_arg("path", args[2])
                if len(args) >= 4:
                    self.add_arg("display_name", args[3])
                if len(args) >= 5:
                    self.add_arg("description", args[4])
                if len(args) >= 6:
                    self.add_arg("ignore_mode", int(args[5]))
                if len(args) >= 7:
                    self.add_arg("start_mode", int(args[6]))
                if len(args) >= 8:
                    self.add_arg("service_type", int(args[7]))

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class ScStartCommand(CommandBase):
    cmd = "sc-query"
    needs_admin = False
    help_cmd = "sc-query -hostname [hostname] -service_name [service_name] -path [path] -display_name [name] -description [desc] -ignore_mode [0|1] -start_mode [0-4] -service_type [1-4]"
    description = \
    """
    Enumerates status for active services and drivers.
    Query can be performed against a specific service or all services if none specified.
    
    Service Types:
      1 = Kernel Driver
      2 = File System Driver
      3 = Adapter
      4 = Recognizer Driver
    
    Start Modes:
      0 = Boot
      1 = System
      2 = Automatic
      3 = Manual
      4 = Disabled
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ScqueryArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_sc_create.x64.o", task.Task.ID)

        hostname = task.args.get_arg("hostname") or ""
        service_name = task.args.get_arg("service_name") or ""
        bin_path = task.args.get_arg("path") or ""
        disp_name = task.args.get_arg("display_name") or ""
        desc = task.args.get_arg("description") or ""
        ignore_mode = task.args.get_arg("ignore_mode") or 0
        start_mode = task.args.get_arg("start_mode") or 0
        service_type = task.args.get_arg("service_type") or 0

        display_params = ""
        if hostname:
            display_params += f" -hostname {hostname}"
        if service_name:
            display_params += f" -service_name {service_name}"
        if bin_path:
            display_params += f" -path {bin_path}"
        if disp_name:
            display_params += f" -display_name {disp_name}"
        if desc:
            display_params += f" -description {desc}"
        if ignore_mode:
            display_params += f" -ignore_mode {ignore_mode}"
        if start_mode:
            display_params += f" -start_mode {start_mode}"
        if service_type:
            display_params += f" -service_type {service_type}"

        bof_args = [
            {"type": "char", "value": hostname},
            {"type": "char", "value": service_name},
            {"type": "char", "value": bin_path},
            {"type": "char", "value": disp_name},
            {"type": "char", "value": desc},
            {"type": "short", "value": ignore_mode},
            {"type": "short", "value": start_mode},
            {"type": "short", "value": service_type}
        ]

        task.args.remove_arg("hostname")
        task.args.remove_arg("service_name")
        task.args.remove_arg("path")
        task.args.remove_arg("display_name")
        task.args.remove_arg("description")
        task.args.remove_arg("ignore_mode")
        task.args.remove_arg("start_mode")
        task.args.remove_arg("service_type")
        
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