from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class CpArguments(TaskArguments):
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
                    raise ValueError("Usage: cp <source> <destination>")
                self.add_arg("source", parts[0])
                self.add_arg("destination", parts[1])

class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp <source> <destination>"
    description = "Copy files/directories"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1564", "T1070"]
    argument_class = CpArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "cp")
        source = task.args.get_arg("source")
        destination = task.args.get_arg("destination")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-source {source} to -destination {destination}",
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
                output = "File copied successfully"
            else:
                output = "Failed to copy file"
            
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