from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class TokenUUIDArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenUUIDCommand(CommandBase):
    cmd = "token-getuuid"
    needs_admin = False
    help_cmd = "token-getuuid"
    description = "Steal an access token from a specified process and optionally use it"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1070", "T1485", "T1134"]
    argument_class = TokenUUIDArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"",
            CommandName="token"
        )
        
        task.args.add_arg("action", "getuuid")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            token_uuid = psr.Bytes()

            token_message =  f"{token_uuid[1:].decode('utf-8', 'ignore')}"

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )