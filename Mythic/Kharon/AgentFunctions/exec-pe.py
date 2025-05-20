from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64

class ExecScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.File,
                description="Shellcode file ID in Mythic to inject",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to inject into (optional)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                type=ParameterType.String,
                description="Arguments for shellcode execution (optional)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Arguments required")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) < 1:
                raise ValueError("Usage: exec-sc <file_id> [pid] [args]")
            
            self.add_arg("file", parts[0])
            
            if len(parts) > 1 and parts[1].isdigit():
                self.add_arg("pid", int(parts[1]))
                if len(parts) > 2:
                    self.add_arg("args", " ".join(parts[2:]))
            elif len(parts) > 1:
                self.add_arg("args", " ".join(parts[1:]))

class ExecScCommand(CommandBase):
    cmd = "exec-sc"
    needs_admin = False
    help_cmd = "exec-sc <file_id> [pid] [args]"
    description = "Execute shellcode in memory"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1055", "T1064"]
    argument_class = ExecScArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        file_id = task.args.get_arg("file")
        args = task.args.get_arg("args")
        
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=task.Task.ID,
            AgentFileID=file_id
        ))
        
        if not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("File not found")
            
        file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=file_id
        ))
        
        if not file_content.Success:
            raise Exception("Failed to get file content")
            
        file_info = file_resp.Files[0]
        output = f"Executing shellcode file: {file_info.Filename}"
        
        if pid > 0:
            output += f" in PID: {pid}"
        if args:
            output += f" with args: {args}"
        
        task.args.remove_arg("file")
        task.args.add_arg("file_contents", file_content.Content.hex())
        task.args.add_arg("pid", pid)
        
        if args:
            task.args.add_arg("args_bytes", base64.b64encode(args.encode()).decode())
        
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response="Executing shellcode..."
        ))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-file {file_id}"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            output = "Shellcode executed successfully\n"

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output.encode('utf-8')
            ))
            
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )