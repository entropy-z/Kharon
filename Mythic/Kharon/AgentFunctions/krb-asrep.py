from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class KrbAsrepCommand( CommandBase ):
    cmd         = "krb-asrep"
    needs_admin = False
    help_cmd    = "krb-asrep"
    description = \
    """
    Perform AS-REP Roasting attack

    Category: Beacon Object File

    Example:
        krb-asrep
    """
    version = 1
    author = "@Oblivion"
    #attackmapping = ["T1055", "T1064"]
    #argument_class = 
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )