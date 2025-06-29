from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from .Utils.u import *

import logging
import json
import os
import random
import string
import shlex

class DotnetVerArguments( TaskArguments ):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

class DotnetVerCommand( CommandBase ):
    cmd = "dotnet-verlist"
    needs_admin = False
    help_cmd = \
    """
    dotnet-verlist
    """
    description = "List available versions"
    version = 2
    author = "@ Oblivion"
    attackmapping = ["T1055", "T1059", "T1027"]
    argument_class = DotnetVerArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        bof_args = []

        content:bytes = await get_content_by_name( "dotnet_listvers.x64.o", task.Task.ID )

        display_params = ""
        display_msg    = "[+] Listing the .NET versions availables\n"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=display_msg
        ))

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
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )