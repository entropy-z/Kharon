# from mythic_container.MythicCommandBase import *
# from mythic_container.MythicRPC import *
# import logging

# class IpconfigArguments( TaskArguments ):
#     def __init__(self, command_line, **kwargs):
#         super().__init__(command_line, **kwargs)
#         self.args = []

#     async def parse_arguments(self):
#         pass

# class IpconfigCommand( CommandBase ):
#     cmd         = "ipconfig"
#     needs_admin = False
#     help_cmd    = "ipconfig"
#     description = \
#     """
#     Display detailed IP configuration and network adapter information

#     Category: Beacon Object File
#     """
#     version = 1
#     author = "@Oblivion"
#     #attackmapping = ["T1055", "T1064"]
#     argument_class = IpconfigArguments
#     browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
#     attributes = CommandAttributes(
#         supported_os=[SupportedOS.Windows],
#     )

#     async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    
#         file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
#             TaskID=task.Task.ID,
#             Filename="ipconfig.o",    
#             LimitByCallback=False,
#             MaxResults=1
#         ))

#         if file_resp.Error and len(file_resp.Files) < 0:
#             return PTTaskCreateTaskingMessageResponse(
#                 TaskID=task.Task.ID,
#                 Success=False
#             )    

#         file_contents = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
#             AgentFileId=file_resp.Files[0].AgentFileId
#         ))

#         task.args.add_arg("bof_file", file_contents.Content.hex())

#         return PTTaskCreateTaskingMessageResponse(
#             TaskID=task.Task.ID,
#             CommandName="exec-bof",
#             TokenID=task.Task.TokenID
#         )
  
#     async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
#         resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
#         return resp
