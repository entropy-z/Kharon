from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class ScDescArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="pid",
                type=ParameterType.String,
                description="Target Process ID to enumerate handles",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    self.add_arg("pid", args[0])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class ProcHandlesCommand(CommandBase):
    cmd = "proc-handles"
    needs_admin = False
    help_cmd = "proc-handles -pid [pid]"
    description = \
    """
    List handles for target process
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ScDescArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_pslist_handles.x64.o", task.Task.ID)

        proc_id = task.args.get_arg("pid")
        display_params = ""

        if proc_id :
            display_params += f" -pid {proc_id}"

        bof_args = [
            {"type": "int32", "value": int(proc_id)},
        ]

        task.args.remove_arg("proc_id")

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
