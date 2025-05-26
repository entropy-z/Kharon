from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *
import datetime
import re
import json

class ConfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="mask",
                type=ParameterType.ChooseOne,
                choices=["timer", "none"],
                description="Change the sleep mask technique",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="bypass",
                type=ParameterType.ChooseOne,
                choices=["all", "amsi", "etw"],
                description="Set bypass for AMSI and/or ETW",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="injection-sc",
                type=ParameterType.ChooseOne,
                choices=["classic", "stomp"],
                description="Change shellcode injection technique",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="arg",
                type=ParameterType.String,
                description="Argument to spoof process creation",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="sleep",
                type=ParameterType.Number,
                description="Change sleep time in seconds (positive integer)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="jitter",
                type=ParameterType.Number,
                description="Change jitter percentage (0-100)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="self-delete",
                type=ParameterType.Boolean,
                description="Set the self deletion in the killdate routine",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="exit",
                type=ParameterType.ChooseOne, 
                choices = ["thread", "process"],
                description="choice for exit in the killdate routine",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="killdate",
                type=ParameterType.String,
                description="Set kill date (YYYY-MM-DD)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
            ),
            CommandParameter(
                name="ppid",
                type=ParameterType.Number,
                description="Set parent process ID (positive integer)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Default"
                )]
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
        
        # Try to parse as dictionary first
        try:
            cmd_line = self.command_line.strip().strip('"').strip("'")
            if cmd_line.startswith("{") and cmd_line.endswith("}"):
                data = json.loads(cmd_line)
                self.parse_dictionary(data)
                return
        except json.JSONDecodeError:
            pass
        
        # Process command line arguments
        parts = re.findall(r'(-[a-zA-Z\-]+)\s+([^-]+)(?=\s+-|$)', self.command_line.strip())
        if not parts:
            raise ValueError("Invalid command format. Use '-option value' pairs.")
        
        args_dict = {}
        for option, value in parts:
            option = option.lstrip('-')
            value = value.strip()
            
            if option not in [param.name for param in self.args]:
                raise ValueError(f"Invalid option '{option}'. Use 'help config' for valid options.")
            
            args_dict[option] = value
        
        self.parse_dictionary(args_dict)
    
    def parse_dictionary(self, dictionary):
        for key, value in dictionary.items():
            if key not in [param.name for param in self.args]:
                continue
            
            if key in ["sleep", "jitter", "ppid"]:
                try:
                    value = int(value)
                except (ValueError, TypeError):
                    raise ValueError(f"{key} must be a numeric value")
            
            self.add_arg(key, value)


class ConfigCommand( CommandBase ):
    cmd = "config"
    needs_admin = False
    help_cmd = \
    """
    Configure agent settings. Options can be combined:
    
    config -mask [timer|none] -bypass [all|amsi|etw] -injection-sc [classic|stomp] -sleep [seconds] -bof-hook [true|false]
           -jitter [percentage] -killdate [YYYY-MM-DD] -ppid [pid] -arg [arg] -exit [thread|process] -self-delete [true|false]
    
    Examples:
        config -mask timer -bypass all
        config -sleep 5 -jitter 10
        config -killdate 2040-01-01 -ppid 1234 -injection-sc stomp
    """
    description = "Configure agent settings"
    version = 3
    author = "@Oblivion"
    attackmapping = ["T1059", "T1059.001", "T1059.003"]
    argument_class = ConfigArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        suggested_command=True,
        load_only=False,
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        validation_errors = []
        config_params = []
        display_params = ""
        param_count = 0
        param_str = ""

        for param_name in config_id:
            if task.args.get_arg(param_name) is not None:
                param_count += 1

        for param_name, param_id in config_id.items():
            param_value = task.args.get_arg(param_name)
            
            if param_value is None:
                continue

            try:
                if param_name in ["sleep", "jitter", "ppid"]:
                    param_value = int(param_value)
                elif param_name == "killdate":
                    datetime.datetime.strptime(str(param_value), "%Y-%m-%d")  # Just validate format
            except ValueError as e:
                validation_errors.append(f"Invalid value for {param_name}: {str(e)}")
                continue

            if param_name == "mask":
                if str(param_value).lower() not in ["timer", "none"]:
                    validation_errors.append("Invalid mask value. Must be timer, apc, or none")
            elif param_name == "bypass":
                if str(param_value).lower() not in ["all", "amsi", "etw"]:
                    validation_errors.append("Invalid bypass value. Must be all, amsi, or etw")
            elif param_name == "injection-sc":
                if str(param_value).lower() not in ["classic", "stomp"]:
                    validation_errors.append("Invalid injection-sc value. Must be classic or stomp")
            elif param_name == "sleep":
                if param_value < 0:
                    validation_errors.append("Sleep value must be a positive integer")
            elif param_name == "jitter":
                if param_value < 0 or param_value > 100:
                    validation_errors.append("Jitter must be between 0 and 100")
            elif param_name == "arg":
                if not param_value:
                    validation_errors.append("Arg need be the value")
            elif param_name == "ppid":
                if param_value < 0:
                    validation_errors.append("PPID must be a positive integer")

            if validation_errors:
                continue

            config_params.append({
                "id": int( param_id ), 
                "name": param_name,
                "value": param_value
            })

            display_params += f"-{param_name} {param_value} "

        if validation_errors:
            raise ValueError("\n".join(validation_errors))

        task.args.remove_arg("param_count")
        for param_name in config_id.keys():
            task.args.remove_arg(param_name)
        while task.args.has_arg("config_id"):
            task.args.remove_arg("config_id")

        task.args.add_arg("param_count", int( param_count ), ParameterType.Number)
        
        param_index = 0;
        param_type = None;
        for param in config_params:
            param_index += 1;
            task.args.add_arg(f"config_id_{param_index}", int( param["id"] ), ParameterType.Number)
            if param["name"] in ["sleep", "jitter", "mask", "injection-sc", "injection-pe", "bypass"]:
                task.args.add_arg(param["name"], int( param["value"]), ParameterType.Number)
            elif param["name"] in ["arg"]:
                task.args.add_arg(param["name"], param["value"], ParameterType.String)
            elif param["name"] in ["killdate"]:
                date_parts = param["value"].split('-')
                year  = int(date_parts[0])
                month = int(date_parts[1])
                day   = int(date_parts[2])
                task.args.add_arg("year", year, ParameterType.Number)
                task.args.add_arg("month", month, ParameterType.Number)
                task.args.add_arg("day", day, ParameterType.Number)

        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=display_params.strip()
        )
        
        return response
    
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )
        
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response="Configuration updated successfully"
        ))
         
        return resp