from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NslookupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.record_mapping = {
            "A": 1,
            "NS": 2,
            "CNAME": 5,
            "SOA": 6,
            "PTR": 12,
            "MX": 15,
            "TXT": 16,
            "AAAA": 28,
            "SRV": 33
        }
        
        self.args = [
            CommandParameter(
                name="lookup",
                cli_name="lookup",
                display_name="Hostname/IP",
                type=ParameterType.String,
                description="Hostname or IP address to lookup",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="server",
                cli_name="server",
                display_name="DNS Server",
                type=ParameterType.String,
                description="DNS server to query (default: system configured)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="type",
                cli_name="type",
                display_name="Record Type",
                type=ParameterType.ChooseOne,
                description="DNS record type to query",
                choices=["A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "SRV"],
                default_value="A",
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
                    self.add_arg("lookup", args[0])
                if len(args) >= 2:
                    self.add_arg("server", args[1])
                if len(args) >= 3:
                    record_type = args[2].upper()
                    if record_type in self.record_mapping:
                        self.add_arg("type", record_type)
                    else:
                        raise ValueError(f"Invalid record type: {record_type}")

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NslookupCommand(CommandBase):
    cmd = "nslookup"
    needs_admin = False
    help_cmd = "nslookup <hostname/ip> [server] [type]"
    description = """
    Performs DNS lookups using the system resolver or specified DNS server.
    
    Supported Record Types:
    A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV
    
    MITRE ATT&CK Technique:
    T1018 - Remote System Discovery
    
    Note: x86 beacons don't support custom DNS servers (will use system default)
    """
    version = 1
    author = "@Oblivion"
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = NslookupArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("nslookup.x64.o", task.Task.ID)

        lookup = task.args.get_arg("lookup")
        server = task.args.get_arg("server") or ""
        record_type = task.args.get_arg("type") or "A"
        
        record_mapping = task.args.record_mapping
        type_value = record_mapping.get(record_type.upper(), record_mapping["A"])

        if server == "127.0.0.1":
            raise Exception("Localhost DNS queries have potential to crash, refusing")
        
        if task.Callback.Architecture == "x86" and server:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response="x86 beacons do not support custom DNS nameservers, overriding to default"
            ))
            server = ""

        display_params = f"'{lookup}'"
        if server:
            display_params += f" using server {server}"
        if record_type != "A":
            display_params += f" (type: {record_type})"

        bof_args = [
            {"type": "char", "value": lookup},
            {"type": "char", "value": server},
            {"type": "short", "value": type_value}
        ]

        # Clean up original arguments
        task.args.remove_arg("lookup")
        task.args.remove_arg("server")
        task.args.remove_arg("type")
        
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