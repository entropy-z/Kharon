from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class CdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="Path to change to (default: home directory)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", self.command_line.strip())

class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd [path]"
    description = "Change current working directory"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1083"]
    argument_class = CdArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        path = task.args.get_arg("path")
        task.args.add_arg("action", "cd")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="fs",
            DisplayParams=f"-path {path}"
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
            output = Psr.Int32()

            if output:
                output = "directory changed with success"

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