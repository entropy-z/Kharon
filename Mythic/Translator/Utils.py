import base64
import os
import struct
from struct import pack, calcsize

TASK_CHECKIN = 0xf1
TASK_GET_JOB = 0
TASK_POST    = 1
TASK_NO_JOB  = 4
TASK_ERROR   = 5

TASK_SLEEPTIME  = 41
TASK_CMD        = 42
TASK_PWSH       = 43
TASK_SOCKS      = 44
TASK_SELFDEL    = 45
TASK_UPLOAD     = 46
TASK_DOWNLOAD   = 47
TASK_EXIT_T     = 48
TASK_EXIT_P     = 49
TASK_INFO       = 50

SB_PS_LIST     = 10
TASK_PS_CREATE = 11
TASK_PS_KILL   = 12
SB_PS_PPID   = 13
SB_PS_BLOCKS = 14

SB_FS_LS    = 30
SB_FS_CAT   = 31
SB_FS_PWD   = 32
SB_FS_CD    = 33
SB_FS_MV    = 34
SB_FS_CP    = 35
SB_FS_DEL   = 36
SB_FS_MKDIR = 37

Commands = {
    "get_tasking"   : { "hex_code": TASK_GET_JOB },
    "post_response" : { "hex_code": TASK_POST },
    "error"         : { "hex_code": 0x3 },

    "checkin"     : { "hex_code": TASK_CHECKIN },
    "getinfo"     : { "hex_code": TASK_INFO },
    "cmd"         : { "hex_code": TASK_CMD },
    "pwsh"        : { "hex_code": TASK_PWSH },
    "run"         : { "hex_code": TASK_PS_CREATE },
    "sleep"       : { "hex_code": TASK_SLEEPTIME },
    "blocks"      : { "hex_code": SB_PS_BLOCKS },
    "ppid"        : { "hex_code": SB_PS_PPID },
    "ps"          : { "hex_code": SB_PS_LIST },
    "self-del"    : { "hex_code": TASK_SELFDEL },
    "cat"         : { "hex_code": SB_FS_CAT },
    "ls"          : { "hex_code": SB_FS_LS },
    "mv"          : { "hex_code": SB_FS_MV },
    "cp"          : { "hex_code": SB_FS_CP },
    "cd"          : { "hex_code": SB_FS_CD },
    "del"         : { "hex_code": SB_FS_DEL },
    "pwd"         : { "hex_code": SB_FS_PWD },
    "mkdir"       : { "hex_code": SB_FS_MKDIR },
    "upload"      : { "hex_code": TASK_UPLOAD },
    "download"    : { "hex_code": TASK_DOWNLOAD },
    "exit-thread" : { "hex_code": TASK_EXIT_T },
    "exit-process": { "hex_code": TASK_EXIT_P },
};

class Packer:
    buffer: bytes = b'';
    length: int   = 0;

    def GetBuff( self ) -> bytes:
        return pack( "<L", self.length ) + self.buffer;

    def AddInt32( self, data ) -> None:

        self.buffer += pack( "<i", data );
        self.length += 4;

        return;

    def AddInt64( self, data ) -> None:

        self.buffer += pack( "<i", data );
        self.length += 8;

        return;
    
    def AddData( self, data: str ) -> None:

        if isinstance( data, str ):
            data = data.encode( "utf-8" );

        fmt = "<L{}s".format( len( data ) + 1 );

        self.buffer += pack( fmt, len( data ) + 1, data );
        self.length += calcsize( fmt );

    def Dmp( self ) -> None:

        print( f"[*] Buffer: [{ self.length }] [{ self.get_buffer() }]" );

        return;

class Parser:
    buffer: bytes = b'';
    length: int   = 0;

    def __init__( self, buffer, length ):

        self.buffer = buffer;
        self.length = length;

        return;

    def Int32( self ) -> int:

        val = struct.unpack( ">i", self.buffer[ :4 ] );
        self.buffer = self.buffer[ 4: ];

        return val[ 0 ];

    def Int64( self ):

        val = struct.unpack( ">i", self.buffer[ :8 ] );
        self.buffer = self.buffer[ 8: ];

        return val[ 0 ];

    def Bytes( self ) -> bytes:

        length      = self.parse_int();

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Pad( self, length: int ) -> bytes:

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Str( self ) -> str:
        return self.parse_bytes().decode( 'utf-8' );
    
    def Wstr( self ):
        return self.parse_bytes().decode( 'utf-16' );

def RespChkDbg( Input:str ) -> None:
    print( f"[DEBUG::RESP::CHECKIN] => {Input}" );

def RespPostDbg( Input:str ) -> None:
    print( f"[DEBUG::RESP::POST] => {Input}" );

def C2TlDbg( Input:str ) -> None:
    print( f"[DEBUG::C2::FMT] => {Input}" );

def AgTlDbg( Input:str ) -> None:
    print( f"[DEBUG::AG::FMT] => {Input}" );