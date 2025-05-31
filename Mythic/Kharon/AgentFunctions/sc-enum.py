from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging

from .Utils.u import *

class ScenumArguments( TaskArguments ):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [            
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
        pass

class ScenumCommand( CommandBase ):
    cmd         = "sc-enum"
    needs_admin = False
    help_cmd    = "sc-enum [hostname:opt]"
    description = \
    """
    Enumerate services for qc, query, qfailure, and qtriggers info.

    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ScenumArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    
        content:bytes = await get_content_by_name( "kh_sc_enum.x64.o", task.Task.ID )

        hostname = task.args.get_arg("hostname") or 'localhost'
        display_params = ""
        
        if hostname :
            display_params += f" -hostname {hostname}"

        bof_args = [
            {"type": "char", "value": hostname},
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
