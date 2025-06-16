from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *

class TokenRemoveArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="id",
                cli_name="id",
                type=ParameterType.Number,
                description="ID of the token to remove from Mythic table",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("id", int(self.command_line.strip()))

class TokenRemoveCommand(CommandBase):
    cmd = "token-rm"
    needs_admin = False
    help_cmd = "token-rm -id [id]"
    description = "Remove token from store"
    version = 1
    author = "@Oblivion"
    attackmapping = []
    argument_class = TokenRemoveArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.display_params = f"id: {task.args.get_arg('id')}"
        task.args.add_arg("action", "rm")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=task.display_params,
            CommandName="token"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error="No response from agent",
                    Completed=True
                )
            
            agent_success = bool(response)
            token_id = task.args.get_arg("id")
            token_list = Token( TokenID=token_id )

            if agent_success:
                remove_response = await SendMythicRPCTokenRemove(MythicRPCTokenRemoveMessage(
                    TaskID=task.Task.ID,
                    Tokens=token_list
                ))
                
                if remove_response.Success:
                    message = f"Successfully removed token {token_id}"
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=message.encode()
                    ))
                    return PTTaskProcessResponseMessageResponse(
                        TaskID=task.Task.ID,
                        Success=True,
                        Completed=True
                    )
                else:
                    error_msg = f"Agent removed token but failed to remove from Mythic table: {remove_response.Error}"
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
            else:
                error_msg = "Agent failed to remove token locally"
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

        except Exception as e:
            error_msg = f"Error processing response: {str(e)}"
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