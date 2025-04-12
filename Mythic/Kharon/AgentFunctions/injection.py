from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import struct

class FsArguments( TaskArguments ):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        
        self.args = [
            CommandParameter(
                name        = "action",
                type        = ParameterType.ChooseOne,
                description = "Action to execute",
                choices     = ["ls", "cat", "pwd", "cd", "mv", "cp", "rm", "mkdir"],
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = True,
                        group_name  = "Default",
                        ui_position = 1
                    )
                ]
            ),
            CommandParameter(
                name        = "path",
                type        = ParameterType.String,
                description = "Path for directory operations",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="path",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name        = "file",
                type        = ParameterType.String,
                description = "File to read",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 2
                    ),
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "file",
                        ui_position = 2
                    )
                ]
            ),
            CommandParameter(
                name        = "source",
                type        = ParameterType.String,
                description = "Source file/directory",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="src",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name        = "destination",
                type        = ParameterType.String,
                description = "Destination file/directory",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 3
                    ),
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "dst",
                        ui_position = 3
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            # Handle command line parsing for non-JSON input
            parts = self.command_line.split()
            if not parts:
                raise ValueError("Must supply arguments")
                
            action = parts[0]
            self.add_arg("action", action)
            
            if action == "pwd":
                return
                
            if action in ["ls", "cd", "rm", "mkdir"]:
                if len(parts) > 1:
                    self.add_arg("path", " ".join(parts[1:]))
                    
            elif action == "cat":
                if len(parts) > 1:
                    self.add_arg("file", " ".join(parts[1:]))
                else:
                    raise ValueError("File parameter is required for cat action")
                    
            elif action in ["mv", "cp"]:
                if len(parts) > 2:
                    self.add_arg("source", parts[1])
                    self.add_arg("destination", " ".join(parts[2:]))
                else:
                    raise ValueError("Both source and destination parameters are required")

    async def parse_dictionary(self, dictionary):
        if "action" not in dictionary:
            self.load_args_from_dictionary (dictionary );
            return
            
        action = dictionary["action"]
        self.add_arg("action", action)
        
        if action == "pwd":
            return
        
        if "-path" in dictionary:
            self.add_arg("path", dictionary["-path"])
        elif "path" in dictionary:
            self.add_arg("path", dictionary["path"])
        
        if "-file" in dictionary:
            self.add_arg("file", dictionary["-file"])
        elif "file" in dictionary:
            self.add_arg("file", dictionary["file"])
        
        if action in ["mv", "cp"]:
            if "-source" in dictionary:
                self.add_arg("source", dictionary["-source"])
            elif "-src" in dictionary:
                self.add_arg("source", dictionary["-src"])
            elif "source" in dictionary:
                self.add_arg("source", dictionary["source"])
            elif "src" in dictionary:
                self.add_arg("source", dictionary["src"])
            
            if "-destination" in dictionary:
                self.add_arg("destination", dictionary["-destination"])
            elif "-dst" in dictionary:
                self.add_arg("destination", dictionary["-dst"])
            elif "destination" in dictionary:
                self.add_arg("destination", dictionary["destination"])
            elif "dst" in dictionary:
                self.add_arg("destination", dictionary["dst"])

class FsCommand( CommandBase ):
    cmd         = "injection"
    needs_admin = False
    help_cmd    = \
    """
    Injection Command

    Usage:
    injection <type> [arguments]

    Actions:
    injection -sc <shellcode_file> -pid <process_id> = Execute shellcode in process memory
    injection -pe <pe_id>                            = Execute PE in the process memory
    """
    description = "Injection PE or Shellcode in memory";
    version     = 1;
    author      = "@ Oblivion";
    attackmapping  = ["T1083", "T1106", "T1570"];
    argument_class = FsArguments;
    attributes     = CommandAttributes(
        spawn_and_injectable = True,
        supported_os         = [SupportedOS.Windows],
        builtin              = True
    );