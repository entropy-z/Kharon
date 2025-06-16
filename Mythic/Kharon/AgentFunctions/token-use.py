from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *

class TokenUseArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="id",
                cli_name="id",
                type=ParameterType.Number,
                description="Token from Mythic table to use",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("id", int(self.command_line.strip()))

class TokenUseCommand(CommandBase):
    cmd = "token-use"
    needs_admin = False
    help_cmd = "token-use [id]"
    description = "Usa um token da tabela do Mythic no agente atual"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1134.001"]
    argument_class = TokenUseArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "use")
        task.args.add_arg("token_id", task.args.get_arg("id"))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"id: {task.args.get_arg('id')}",
            CommandName="token"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error="Not response from agent",
                    Completed=True
                )
            
            # A resposta deve ser apenas um booleano (true/false)
            success = bool(response)
            
            message = "Token impersonated" if success else "Failure to impersonate token"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=message.encode()
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=success,
                Completed=True
            )

        except Exception as e:
            error_msg = f"Error to process response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )