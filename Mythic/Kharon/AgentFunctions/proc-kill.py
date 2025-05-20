from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class ProcKillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to kill",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply PID to kill")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            try:
                pid = int(self.command_line)
                self.add_arg("pid", pid)
            except ValueError:
                raise ValueError("PID must be a number")
        self.add_arg("action", "kill")

class ProcKillCommand(CommandBase):
    cmd = "proc-kill"
    needs_admin = False
    help_cmd = 'proc-kill [pid]'
    description = "Kill a process by ID"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1057"]
    argument_class = ProcKillArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        pid = task.args.get_arg("pid")
        task.args.add_arg("action", "kill")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-pid {pid}",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )