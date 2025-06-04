from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class LdapSearchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="query",
                cli_name="query",
                display_name="LDAP Query",
                type=ParameterType.String,
                description="The LDAP search query to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="attributes",
                cli_name="attributes",
                display_name="Attributes",
                type=ParameterType.String,
                description="Comma-separated list of attributes to return (default: *)",
                default_value="*",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="count",
                cli_name="count",
                display_name="Result Limit",
                type=ParameterType.Number,
                description="Maximum number of results to return (0 = no limit)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="scope",
                cli_name="scope",
                display_name="Search Scope",
                type=ParameterType.Number,
                description="Search scope (1=Base, 2=OneLevel, 3=Subtree)",
                default_value=3,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="LDAP Host",
                type=ParameterType.String,
                description="LDAP server hostname (default: domain controller)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dn",
                cli_name="dn",
                display_name="Base DN",
                type=ParameterType.String,
                description="Base distinguished name for the search",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ldaps",
                cli_name="ldaps",
                display_name="Use LDAPS",
                type=ParameterType.Boolean,
                description="Use LDAPS (SSL) instead of LDAP",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                # Parse command line arguments in format:
                # query --attributes value --count value --scope value --hostname value --dn value --ldaps
                parts = self.command_line.split(" --")
                if len(parts) > 0:
                    self.add_arg("query", parts[0].strip())
                
                for part in parts[1:]:
                    if not part:
                        continue
                    
                    option_value = part.split(" ", 1)
                    option = option_value[0].lower()
                    value = option_value[1].strip() if len(option_value) > 1 else ""
                    
                    if option == "attributes":
                        self.add_arg("attributes", value)
                    elif option == "count":
                        self.add_arg("count", int(value))
                    elif option == "scope":
                        self.add_arg("scope", int(value))
                    elif option == "hostname":
                        self.add_arg("hostname", value)
                    elif option == "dn":
                        self.add_arg("dn", value)
                    elif option == "ldaps":
                        self.add_arg("ldaps", True)
                    else:
                        raise ValueError(f"Unknown argument: --{option}")

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class LdapSearchCommand(CommandBase):
    cmd = "ldap-query"
    needs_admin = False
    help_cmd = "ldap-query -query <query> [--attributes <attrs>] [--count <limit>] [--scope <1-3>] [--hostname <host>] [--dn <base_dn>] [--ldaps]"
    description = """
    Executes an LDAP query against a domain controller.
    
    Search Scopes:
    1 = Base (only the base object)
    2 = OneLevel (immediate children of base object)
    3 = Subtree (base object and all descendants)
    
    MITRE ATT&CK Techniques:
    T1018 - Remote System Discovery
    T1069.002 - Permission Groups Discovery: Domain Groups
    T1087 - Account Discovery
    T1482 - Domain Trust Discovery
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = LdapSearchArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("ldapsearch.x64.o", task.Task.ID)

        query = task.args.get_arg("query")
        attributes = task.args.get_arg("attributes") or "*"
        count = task.args.get_arg("count") or 0
        scope = task.args.get_arg("scope") or 3
        hostname = task.args.get_arg("hostname") or ""
        dn = task.args.get_arg("dn") or ""
        ldaps = task.args.get_arg("ldaps") or False

        # Build display parameters
        display_params = f"'{query}'"
        if attributes != "*":
            display_params += f" (attrs: {attributes})"
        if count > 0:
            display_params += f" [limit: {count}]"
        if scope != 3:
            display_params += f" [scope: {scope}]"
        if hostname:
            display_params += f" [host: {hostname}]"
        if dn:
            display_params += f" [base DN: {dn}]"
        if ldaps:
            display_params += " [LDAPS]"

        bof_args = [
            {"type": "char", "value": query},
            {"type": "char", "value": attributes},
            {"type": "int", "value": count},
            {"type": "int", "value": scope},
            {"type": "char", "value": hostname},
            {"type": "char", "value": dn},
            {"type": "int", "value": 1 if ldaps else 0}
        ]

        for arg in ["query", "attributes", "count", "scope", "hostname", "dn", "ldaps"]:
            task.args.remove_arg(arg)
        
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