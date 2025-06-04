from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class WmiQueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="query",
                cli_name="query",
                display_name="WMI Query",
                type=ParameterType.String,
                description="The WMI query to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="system",
                cli_name="system",
                display_name="Target System",
                type=ParameterType.String,
                description="Target system (default: localhost)",
                default_value=".",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="namespace",
                cli_name="namespace",
                display_name="WMI Namespace",
                type=ParameterType.String,
                description="WMI namespace (default: root\\cimv2)",
                default_value="root\\cimv2",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split(" ", 3)  # Split into max 4 parts
                if len(args) >= 1:
                    self.add_arg("query", args[0])
                if len(args) >= 2:
                    self.add_arg("system", args[1])
                if len(args) >= 3:
                    self.add_arg("namespace", args[2])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class WmiQueryCommand(CommandBase):
    cmd = "wmi-query"
    needs_admin = False
    help_cmd = "wmi-query -query <query> -system [system] -namespace [namespace:opt]"
    description = """
    Executes a WMI query against the specified system and namespace.
    Defaults to local system (.) and root\\cimv2 namespace if not specified.
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = WmiQueryArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("wmi_query.x64.o", task.Task.ID)

        query = task.args.get_arg("query")
        system = task.args.get_arg("system") or "."
        namespace = task.args.get_arg("namespace") or "root\\cimv2"
        resource = f"\\\\{system}\\{namespace}"

        display_params = f"'{query}'"
        if system != ".":
            display_params += f" on \\\\{system}"
        if namespace != "root\\cimv2":
            display_params += f" (namespace: {namespace})"

        bof_args = [
            {"type": "char", "value": system},
            {"type": "char", "value": namespace},
            {"type": "char", "value": query},
            {"type": "char", "value": resource}
        ]

        task.args.remove_arg("query")
        task.args.remove_arg("system")
        task.args.remove_arg("namespace")
        
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