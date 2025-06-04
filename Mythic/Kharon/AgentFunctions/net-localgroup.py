from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetLocalGroupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                description="Action to perform",
                choices=["list_groups", "list_members"],
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="group",
                cli_name="group",
                display_name="Group Name",
                type=ParameterType.String,
                description="Group name (required for list_members action)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="list_groups"),
                    ParameterGroupInfo(
                        required=True,
                        group_name="list_members")
                ]
            ),
            CommandParameter(
                name="server",
                cli_name="server",
                display_name="Target Server",
                type=ParameterType.String,
                description="Target server (default: localhost)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    action = args[0].lower()
                    if action in ["list_groups", "list_members"]:
                        self.add_arg("action", action)
                    else:
                        raise ValueError("Invalid action. Use 'list_groups' or 'list_members'")
                    
                    if len(args) >= 2:
                        if action == "list_members":
                            self.add_arg("group", args[1])
                            if len(args) >= 3:
                                self.add_arg("server", args[2])
                        else:
                            self.add_arg("server", args[1])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetLocalGroupCommand(CommandBase):
    cmd = "net-localgroup"
    needs_admin = False
    help_cmd = """
    net-localgroup list_groups [server]
    net-localgroup list_members <group> [server]
    """
    description = """
    Enumerate local groups or group members on a target system.
    
    Actions:
    list_groups   - List all local groups
    list_members  - List members of specified group
    
    MITRE ATT&CK Technique:
    T1069.001 - Permission Groups Discovery: Local Groups
    
    Category: Discovery
    """
    version = 1
    author = "@Oblivion"
    argument_class = NetLocalGroupArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_netlocalgroup.x64.o", task.Task.ID)

        action = task.args.get_arg("action")
        group = task.args.get_arg("group") or ""
        server = task.args.get_arg("server") or ""
        
        # Convert action to numeric type
        action_type = 0 if action == "list_groups" else 1

        display_params = f"{action}"
        if action == "list_members":
            display_params += f" {group}"
        if server:
            display_params += f" on \\\\{server}"

        bof_args = [
            {"type": "short", "value": action_type},  # 0=list groups, 1=list members
            {"type": "char", "value": server},
            {"type": "char", "value": group}
        ]

        task.args.remove_arg("action")
        task.args.remove_arg("group")
        task.args.remove_arg("server")
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp