from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
from .Utils.u import *

class ProcListArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise ValueError("proc-list takes no arguments")
        self.add_arg("action", "list")

class ProcListCommand(CommandBase):
    cmd = "proc-list"
    needs_admin = False
    help_cmd = "proc-list"
    description = \
    """"
    List running processes with informations like:
        - Image Name
        - Image Path
        - Process ID
        - Parent ID
        - Handle Count
        - Session ID
        - User Token
        - Threads Quantity
        - Architecture
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1057"]
    argument_class = ProcListArguments
    supported_ui_features = ["process_browser:list"]
    browser_script = BrowserScript(script_name="ps_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "list")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams="",
            CommandName="proc"
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
            process_list = []
            mythic_process_list = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            if sub_id == SB_PS_LIST:
                try:
                    while Psr.buffer and len(Psr.buffer) > 0:
                        process_info = {}
                        try:
                            ImagePath = Psr.Str()
                            ImageName = Psr.Wstr()
                            CommandLn = Psr.Wstr()
                            ProcessID = Psr.Int32()
                            ParentID  = Psr.Int32()
                            HandleCnt = Psr.Int32()
                            SessionID = Psr.Int32()
                            ThreadNbr = Psr.Int32()
                            TokenUser = Psr.Str()
                            Isx64     = Psr.Int32()

                            # Create process info for the response
                            process_info = {
                                "Image Name": ImageName,
                                "Image Path": ImagePath,
                                "Command Line": CommandLn,
                                "Process ID": ProcessID,
                                "Parent ID": ParentID,
                                "Handle Count": HandleCnt,
                                "Session ID": SessionID,
                                "User Token": TokenUser,
                                "Threads Quantity": ThreadNbr,
                                "Architecture": "x86" if Isx64 else "x64"
                            }
                            process_list.append(process_info)

                            mythic_process = MythicRPCProcessCreateData(
                                Host=task.Callback.Host,  
                                ProcessID=ProcessID,
                                ParentProcessID=ParentID,
                                Architecture="x86" if Isx64 else "x64",
                                Name=ImageName,
                                BinPath=ImagePath,
                                CommandLine=CommandLn,
                                User=TokenUser,
                                IntegrityLevel=SessionID
                            )
                            mythic_process_list.append(mythic_process)
                        except Exception as e:
                            continue

                    await SendMythicRPCProcessCreate(MythicRPCProcessesCreateMessage(
                        TaskID=task.Task.ID,
                        Processes=mythic_process_list
                    ))

                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=json.dumps(process_list, indent=2, ensure_ascii=False).encode('utf-8')
                    ))
                except Exception as e:
                    raise ValueError(f"Error parsing process list: {str(e)}")
            else:
                RawData = Psr.Str()
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=RawData.encode('utf-8')
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