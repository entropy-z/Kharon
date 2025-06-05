from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

from collections import OrderedDict
import json
import logging
import struct

logging.basicConfig( level=logging.INFO );

class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="Path to list (default: current directory)",
                default_value=".",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", self.command_line.strip())

class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List directory contents"
    version = 1
    author = "@ Oblivion"
    attackmapping = ["T1083"]
    browser_script = BrowserScript( script_name="ls_new", author="@ Oblivion", for_new_ui=True )
    supported_ui_features = ["file_browser:list"]
    argument_class = LsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "ls")
        path = task.args.get_arg("path")
        task.args.add_arg("path", path + "\\*" if path != "." else ".\\*")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-path {path}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True
                )
                
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            output_data = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            if sub_id == SB_FS_LS:
                parent_dir = MythicRPCFileBrowserData(
                    IsFile=False,
                    Permissions="",
                    AccessTime="",
                    ModifyTime="",
                    Size=0,
                    UpdateDeleted=True,
                    Files=[]
                )
                
                file_list = []
                
                while Psr.buffer:
                    try:
                        file_info = OrderedDict()
                        file_info['Name'] = Psr.Str()
                        FileSize = Psr.Int32()
                        Attribute = Psr.Int32()
                        
                        if FileSize == -1:
                            file_info['Type'] = "<DIR>"
                            file_info['Size'] = None
                        else:
                            file_info['Type'] = "<FILE>"
                            file_info['Size'] = f"{FileSize}" 
                        
                        def TimePsr():
                            Day = Psr.Int16()
                            Month = Psr.Int16()
                            Year = Psr.Int16()
                            Hour = Psr.Int16()
                            Minute = Psr.Int16()
                            Second = Psr.Int16()
                            return f"{Year:04d}-{Month:02d}-{Day:02d} {Hour:02d}:{Minute:02d}:{Second:02d}"
                        
                        file_info['Created'] = TimePsr()
                        file_info['Accessed'] = TimePsr()
                        file_info['Modified'] = TimePsr()
                        
                        AttrMap = {
                            0x1: "R", 0x2: "H", 0x4: "S",
                            0x10: "D", 0x20: "A", 0x40: "N", 0x80: "T"
                        }
                        file_info['Attributes'] = "".join(v for k, v in AttrMap.items() if Attribute & k) or "?"
                        
                        child_entry = MythicRPCFileBrowserDataChildren(
                            Name=file_info['Name'],
                            IsFile=file_info['Type'] == "<FILE>",
                            Permissions=file_info['Attributes'],
                            AccessTime=file_info['Accessed'],
                            ModifyTime=file_info['Modified'],
                            Size=FileSize if file_info['Type'] == "<FILE>" else 0,
                        )
                        
                        parent_dir.Files.append(child_entry)
                        file_list.append(file_info)
                    
                    except struct.error:
                        break
                
                output_data = {
                    "DirectoryListing": file_list,
                    "Count": len(file_list)
                }

                await SendMythicRPCFileBrowserCreate(MythicRPCFileBrowserCreateMessage(
                    TaskID=task.Task.ID,
                    FileBrowser=parent_dir
                ))
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=json.dumps(output_data, indent=4).encode('utf-8')
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