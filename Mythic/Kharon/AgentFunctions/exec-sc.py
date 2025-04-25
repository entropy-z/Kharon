from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64
import binascii

class ExecScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.File,
                description="Arquivo de shellcode carregado no Mythic",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="PID do processo para injeção (opcional)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                type=ParameterType.String,
                description="Argumentos adicionais para o shellcode (opcional)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Requer argumentos")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) < 1:
                raise ValueError("Uso: exec-sc <file_id> [pid] [args]")
            
            # Primeiro argumento é sempre o file_id
            self.add_arg("file", parts[0])
            
            # Verifica se tem PID
            if len(parts) > 1 and parts[1].isdigit():
                self.add_arg("pid", int(parts[1]))
                
                # O resto são argumentos
                if len(parts) > 2:
                    self.add_arg("args", " ".join(parts[2:]))
            elif len(parts) > 1:
                # Se não for número, são argumentos
                self.add_arg("args", " ".join(parts[1:]))

class ExecScCommand(CommandBase):
    cmd = "exec-sc"
    needs_admin = False
    help_cmd = "exec-sc <file_id> [pid] [args]"
    description = "execute shellcode in memory"
    version = 1
    author = "@ Oblivion"
    attackmapping = ["T1055", "T1064"]
    argument_class = ExecScArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        file_id = task.args.get_arg("file")
        pid = task.args.get_arg("pid", 0)
        args = task.args.get_arg("args", "")
        
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            TaskID=task.Task.ID,
            AgentFileID=file_id
        ))
        
        if not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("file not found")
            
        file_info = file_resp.Files[0]
        
        display_params = f"executing shellcode file: {file_info.Filename}"
        if pid > 0:
            display_params += f" in pid: {pid}"
        if args:
            display_params += f"with args: {args}"
        
        task.args.add_arg("file_id", file_id)
        task.args.add_arg("file_name", file_info.Filename)
        task.args.add_arg("pid", pid)
        
        if args:
            task.args.add_arg("args_bytes", base64.b64encode(args.encode()).decode())
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=display_params,
            Completed=True
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            resp = json.loads(response)
            
            if "status" in resp and resp["status"] == "success":
                output = f"shellcode exexcuted with success\n"
                if "output" in resp:
                    output += f"Saída: {resp['output']}"
            else:
                output = f"error during shellcode execution\n"
                if "error" in resp:
                    output += f"Detalhes: {resp['error']}"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output.encode()
            ))
            
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Erro processando resposta: {str(e)}".encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )