from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import logging, sys

logging.basicConfig(level=logging.INFO)

class InlineExecuteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_name",
                cli_name="file",
                display_name="file",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Already existing BOF to execute (e.g. whoami.x64.o)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]),
            CommandParameter(
                name="bof_file",
                display_name="new",
                type=ParameterType.File,
                description="A new BOF to execute. After uploading once, you can just supply the bof_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True, 
                        group_name="New", 
                        ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="bof_arguments",
                cli_name="args",
                display_name="args",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int16", "int32", "string", "wchar", "base64"],
                description=\
                """
                Arguments to pass to the BOF via the following way:
                -s:123 or int16:123
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or base64:abc==
                """,
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New",
                        ui_position=4
                    ),
                ]),
        ]
        
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        raise ValueError("Must supply named arguments or use the modal")

    async def parse_dictionary(self, dictionary_arguments):
        expected_args = {"bof_arguments", "bof_file", "bof_name"}

        invalid_keys = set(dictionary_arguments.keys()) - expected_args
        if invalid_keys:
            raise ValueError(f"Invalid arguments provided: {', '.join(invalid_keys)}")
        
        filtered_arguments = {k: v for k, v in dictionary_arguments.items() if k in expected_args}
        self.load_args_from_dictionary(filtered_arguments)   

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)
        bof_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s" or argType == "s":
                bof_arguments.append(["int16", int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i":
                bof_arguments.append(["int32", int(value)])
            elif argType == "string" or argType == "-z" or argType == "z":
                bof_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z" or argType == "Z":
                bof_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b" or argType == "b":
                bof_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=bof_arguments)
        return argumentResponse

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse()
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=callback.Callback,
            LimitByCallback=False,
            IsDownloadFromAgent=False,
            IsScreenshot=False,
            IsPayload=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".o"):
                    file_names.append(f.Filename)
            response.Success = True
            response.Choices = file_names
            return response
        else:
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                CallbackId=callback.Callback,
                Message=f"Failed to get files: {file_resp.Error}",
                MessageLevel="warning"
            ))
            response.Error = f"Failed to get files: {file_resp.Error}"
            return response


class InlineExecuteCommand(CommandBase):
    cmd = "exec-bof"
    needs_admin = False
    help_cmd = "exec-bof -file [file_id|file_name] -args [args]"
    description = \
    """
    Execute beacon object file in the current process memory
    
    Examples:
        exec-bof -file 55555555-5555-5555-555555 -args
        
    Obs:
        Some APIs can be hooked to perform configured behavior. For example, when any API is executed with indirect syscall and/or call stack spoofing, 
        if hooking is enabled, the agent will hook the imported functions and verify whether the function is in the API list to perform its routine and resolve to the internal function. 
        This can be enabled with the command \"config -hook-bof true\".
    """
    version = 1
    author = "@c0rnbread"
    attackmapping = []
    argument_class = InlineExecuteArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[ SupportedOS.Windows ],
        suggested_command=False
    )


    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        try:
            groupName = taskData.args.get_parameter_group_name()
            if groupName == "New":
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    AgentFileID=taskData.args.get_arg("bof_file")
                ))
                if file_resp.Success:
                    if len(file_resp.Files) > 0:
                        pass
                    else:
                        raise Exception("Failed to find that file")
                else:
                    raise Exception("Error from Mythic trying to get file: " + str(file_resp.Error))
            elif groupName == "Default":
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    Filename=taskData.args.get_arg("bof_name"),
                    LimitByCallback=False,
                    MaxResults=1
                ))
                if file_resp.Success:
                    if len(file_resp.Files) > 0:
                        logging.info(f"Found existing BOF file replacing with file_id: {file_resp.Files[0].AgentFileId}")
                        taskData.args.add_arg("bof_file", file_resp.Files[0].AgentFileId)
                        taskData.args.remove_arg("bof_name")  
                        
                        response.DisplayParams = "-bof_file {} -bof_arguments {}".format(
                            file_resp.Files[0].Filename,
                            taskData.args.get_arg("bof_arguments")
                        )

                    elif len(file_resp.Files) == 0:
                        raise Exception("Failed to find the named file. Have you uploaded it before? Did it get deleted?")
                else:
                    raise Exception("Error from Mythic trying to search files:\n" + str(file_resp.Error))
        except Exception as e:
            raise Exception("Error from Mythic: " + str(sys.exc_info()[-1].tb_lineno) + " : " + str(e))
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp