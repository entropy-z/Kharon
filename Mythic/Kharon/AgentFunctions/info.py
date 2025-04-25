from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from collections import OrderedDict
import re

from .Utils.u import *

class InfoArguments( TaskArguments ):
    def __init__( self, command_line, **kwargs ):
        super().__init__( command_line, **kwargs );
        self.args = [];

    async def parse_arguments(self):
        if len( self.command_line.strip() ) > 0:
            raise Exception("pwd takes no command line arguments.")
        pass

class InfoCommand( CommandBase ):
    cmd         = "info"
    needs_admin = False
    help_cmd    = \
    """
    Get information from agent, configs, session and machine.
    """
    description = "Get several information"
    version     = 1
    author      = "@Oblivion"
    attackmapping  = ["T1083", "T1106", "T1570"]
    browser_script = BrowserScript("info_new", "@Oblivion", for_new_ui=True)
    argument_class = InfoArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=task.args.command_line,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True
                )
                
            RawResponse = bytes.fromhex( response )
            Psr         = Parser( RawResponse, len( RawResponse ) );
            output_data = [];
            Output = "";

            AgentID = Psr.Str();
            MmStart = Psr.Int64();
            MmEnd   = Psr.Int32();
            ImgPath = Psr.Str();
            ImgName = ImgPath.split("\\")[-1] if ImgPath else "";
            CmdLine = Psr.Str();
            ProcID  = Psr.Int32();
            TdID    = Psr.Int32();
            ParID   = Psr.Int32();
            HHeap   = Psr.Int32();
            SleepT  = Psr.Int32();
            ProcAch = Psr.Int32();
            Elevate = Psr.Pad( 1 );

            MaskID  = Psr.Pad( 1 );
            MaskHp  = Psr.Pad( 1 );
            JmpGdt  = Psr.Int64();
            NtCntGd = Psr.Int64();

            UsrN  = Psr.Str();
            CmpN  = Psr.Str();
            DomN  = Psr.Str();
            NetB  = Psr.Str();
            OsAc  = Psr.Int32();
            OsMj  = Psr.Int32();
            OsMn  = Psr.Int32();
            OsBd  = Psr.Int32();
            PTyp  = Psr.Int32();
            TotRm = Psr.Int32();
            AvlRm = Psr.Int32();
            UsdRm = Psr.Int32();
            PctRm = Psr.Int32();
            PcNm  = Psr.Str();
            PcNbr = Psr.Int32();

            Elevate = "true" if Elevate and Elevate != b'\x00' else "false"
            MaskHp = "true" if MaskHp and MaskHp != b'\x00' else "false"

            MaskID = int.from_bytes(MaskID, byteorder='big', signed=False) if isinstance(MaskID, bytes) else MaskID
            if MaskID == 0:
                MaskID = "None"
            elif MaskID == 1:
                MaskID = "timer"
            elif MaskID == 2:
                MaskID = "apc"
            else:
                MaskID = str(MaskID)  #

            data = {
                "Agent ID": AgentID,
                "Memory Base": hex( MmStart ),
                "Memory Size": MmEnd,
                "Image Name": ImgName,
                "Image Path": ImgPath,
                "Command Line": CmdLine,
                "Process ID": ProcID,
                "Thread ID": TdID,
                "Parent ID": ParID,
                "Heap Address using": hex( HHeap ),
                "Sleep Time": SleepT % 1000,
                "Process Arch": ProcAch,
                "Elevate": Elevate.hex() if isinstance(Elevate, bytes) else Elevate,
                "Mask Technique": MaskID.hex() if isinstance(MaskID, bytes) else MaskID,
                "Mask Heap": MaskHp.hex() if isinstance(MaskHp, bytes) else MaskHp,
                "Jump Gadget": hex( JmpGdt ),
                "NtContinue Gadget": hex( NtCntGd ),
                "User Name": UsrN,
                "Computer Name": CmpN,
                "Domain Name": DomN,
                "Net Bios": NetB,
                "OS Arch": OsAc,
                "Version": f"{OsMj}.{OsMn}.{OsBd}",
                "Product Type": PTyp,
                "Total RAM": TotRm,
                "Avalilable RAM": AvlRm,
                "Used RAM": f"{UsdRm} ({PctRm}%)",
                "Processor Name": PcNm,
                "Processors Numbers": PcNbr
            }

            Output = json.dumps(data, indent=4)

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=Output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )