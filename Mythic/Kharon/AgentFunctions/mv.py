from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class MvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                cli_name="source",
                type=ParameterType.String,
                description="Source file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="destination",
                cli_name="destination",
                type=ParameterType.String,
                description="Destination file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) != 2:
                    raise ValueError("Usage: mv <source> <destination>")
                self.add_arg("source", parts[0])
                self.add_arg("destination", parts[1])

class MvCommand(CommandBase):
    cmd = "mv"
    needs_admin = False
    help_cmd = "mv <source> <destination>"
    description = \
    """
    Move or rename files/directories" \
    Category: Native
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1564", "T1070"]
    argument_class = MvArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "mv")
        source = task.args.get_arg("source")
        destination = task.args.get_arg("destination")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-source {source} -destination {destination}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            success = Psr.Int32()
            
            if success:
                output = "File moved successfully"
            else:
                output = "Failed to move file"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )