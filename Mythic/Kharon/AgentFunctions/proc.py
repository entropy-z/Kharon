from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import re

class ProcArguments( TaskArguments ):
    def __init__( self, command_line, **kwargs ):
        super().__init__( command_line, **kwargs )
        self.args = [
            CommandParameter(
                name        = "action",
                type        = ParameterType.ChooseOne,
                description = "Action to perform",
                choices     = ["run", "pwsh", "kill", "list"],
                parameter_group_info = [
                        ParameterGroupInfo (
                        required=True,
                        group_name="Default"
                    )
                ]
            ),
            CommandParameter(
                name          = "args",
                type          = ParameterType.String,
                description   = "Arguments for the process",
                default_value = "",
                parameter_group_info = [
                        ParameterGroupInfo (
                        required   = False,
                        group_name = "Default"
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError( "Must supply arguments. Usage: proc [run|pwsh|kill|list] [options]" );
        
        if self.command_line[0] == "{":
            self.load_args_from_json_string( self.command_line );
            return;
        
        parts = self.command_line.split( " ", 1 );
        self.add_arg( "action", parts[0].lower() );
        
        if len(parts) > 1:
            self.add_arg( "args", parts[1] );
        

class ProcCommand(CommandBase):
    cmd         = "proc"
    needs_admin = False
    help_cmd    = \
    """
    proc <action> [options]
        
    Actions:
    run  <command>  - Run a process
    pwsh <command>  - Run PowerShell command
    kill <pid>      - Kill process by ID
    list            - List running processes

    Examples:
    proc run  -command notepad.exe
    proc pwsh -command "Get-Process | Where-Object { $_.CPU -gt 100 }"
    proc kill -pid 1234
    proc list
    """
    description = "Process management utility with subcommands for running, listing, and killing processes"
    version     = 1
    author      = "@ Oblivion"
    attackmapping  = ["T1059", "T1059.001", "T1059.003", "T1106", "T1057"]
    argument_class = ProcArguments
    attributes     = CommandAttributes(
        supported_os      = [SupportedOS.Windows],
        suggested_command = True,
        load_only         = False,
        builtin           = True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        action   = task.args.get_arg( "action" );
        args     = task.args.get_arg( "args" );

        if action == "pwsh":
            args = f"powershell.exe -c {args}";
        elif action == "cmd":
            args = f"cmd.exe /c {args}";
        elif action == "run":
            args = f"{args}";
        
        task.args.set_arg( "args", args );

        display_params  = f"{action}";
        display_params += f" {args}";
        
        response = PTTaskCreateTaskingMessageResponse(
            TaskID        = task.Task.ID,
            Success       = True,
            DisplayParams = display_params
        );
        
        return response;

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        );
        
        if response:
            try:
                if isinstance( response, bytes ):
                    response = response.decode( 'utf-8', errors='replace' );
                
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response.encode() if isinstance(response, str) else response
                ));
            except Exception as e:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=f"Error processing response: {str(e)}".encode()
                ));
        
        return resp;