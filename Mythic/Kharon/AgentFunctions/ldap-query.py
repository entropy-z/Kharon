# from mythic_container.MythicCommandBase import *
# from mythic_container.MythicRPC import *
# import logging

# from .Utils.u import *

# class LdapsearchArguments( TaskArguments ):
#     def __init__(self, command_line, **kwargs):
#         super().__init__(command_line, **kwargs)
#         self.args = [
#             CommandParameter(
#                 name="filter",
#                 cli_name="filter",
#                 type=ParameterType.String,
#                 description="",
#                 parameter_group_info=[ParameterGroupInfo(required=True)]
#             ),
#             CommandParameter(
#                 name="attributes",
#                 cli_name="attributes",
#                 type=ParameterType.String,
#                 description="",
#                 parameter_group_info=[ParameterGroupInfo(required=True)]
#             )
#             CommandParameter(
#                 name="count",
#                 cli_name="count",
#                 type=ParameterType.String,
#                 description="",
#                 parameter_group_info=[ParameterGroupInfo(required=True)]
#             )
#             CommandParameter(
#                 name="hostname",
#                 cli_name="hostname",
#                 type=ParameterType.String,
#                 description="",
#                 parameter_group_info=[ParameterGroupInfo(required=True)]
#             )
#         ]
# class LdapsearchCommand( CommandBase ):
#     cmd         = "ldap-query"
#     needs_admin = False
#     help_cmd    = "ldap-query"
#     description = \
#     """
#     Execute LDAP searches (NOTE: specify *,ntsecuritydescriptor as attribute parameter if
#     you want all attributes + base64 encoded ACL of the objects, 
#     this can then be resolved using BOFHound. Could possibly break pagination, although everything seemed fine during testing.)

#     Category: Beacon Object File
#     """
#     version = 1
#     author = "@Oblivion"
#     argument_class = LdapsearchArguments
#     browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
#     attributes = CommandAttributes(
#         supported_os=[SupportedOS.Windows],
#     )

#     async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    
#         content:bytes = await get_content_by_name( "kh_ldapsearch.x64.o", task.Task.ID )

#         task.args.add_arg("bof_file", content.hex())

#         return PTTaskCreateTaskingMessageResponse(
#             TaskID=task.Task.ID,
#             CommandName="exec-bof",
#             TokenID=task.Task.TokenID
#         )
  
#     async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
#         resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
#         return resp
