import base64
import os
import json
import re
import base64
import struct
import ast
import logging
from struct import pack, calcsize

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

KH_CALLBACK_OUTPUT = 0x0
KH_CALLBACK_ERROR  = 0x0d

JOB_CHECKIN   = 0xf1;
JOB_GET_TASK  = 0;
JOB_POST      = 1;
JOB_NO_JOB    = 4;
JOB_QUICK_MSG = 5;
JOB_ERROR     = 6;
JOB_QUICK_OUT = 7;

BF_WHOAMI     = 5000;
BF_IPCONFIG   = 5001;
BF_CLIPDUMP   = 5002;
BF_SELFDEL    = 5003;
BF_SCREENSHOT = 5004;

BF_JMP_PSEXEC = 5051;
BF_JMP_WMI    = 5052;
BF_JMP_WINRM  = 5053;

BF_KRB_ASREP  = 5101;
BF_KRB_ASKTGT = 5102;
BF_KRB_ASKTGS = 5103;
BF_KRB_DUMP   = 5104;
BF_KRB_CHNGPW = 5105;
BF_KRB_KRBRST = 5106;
BF_KRB_KLIST  = 5107;
BF_KRB_PTT    = 5107;
BF_KRB_PURGE  = 5107;
BF_KRB_S4U    = 5109;
BF_KRB_RENEW  = 5110;
BF_KRB_TGTDEL = 5111;
BF_KRB_TRIAGE = 5112;
BF_KRB_DESCB  = 5113;
BF_KRB_HASH   = 5114;

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
T_EXEC_SC   = 21;
T_EXEC_PE   = 22;
T_EXEC_BOF  = 23;
T_TOKEN     = 24;

SB_TKN_UID   = 10;
SB_TKN_STEAL = 11;
SB_TKN_MAKE  = 12;
SB_TKN_PRIV  = 13;
SB_TKN_STORE = 14;
SB_TKN_USE   = 15;
SB_TKN_RM    = 16;

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
    "error":         {"hex_code": JOB_ERROR },
    "quick_msg":     {"hex_code": JOB_QUICK_MSG},
    "quick_out":     {"hex_code": JOB_QUICK_OUT}
}

Commands = {
    # Task commands
    "getinfo":   {"hex_code": T_INFO},
    "socks":     {"hex_code": T_SOCKS},
    "self-del":  {"hex_code": T_SELFDEL},
    "upload":    {"hex_code": T_UPLOAD},
    "download":  {"hex_code": T_DOWNLOAD},
    "info"    :  {"hex_code": T_INFO},
    "exec-bof":  {"hex_code": T_EXEC_BOF},
    "exec-sc" :  {"hex_code": T_EXEC_SC},
    "exec-pe" :  {"hex_code": T_EXEC_PE},

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

    "bof": {
        "whoami":     {"sub": BF_WHOAMI},
        "ipconfig":   {"sub": BF_IPCONFIG},
        "clipdump":   {"sub": BF_CLIPDUMP},
        "selfdel":    {"sub": BF_SELFDEL},
        "screenshot": {"sub": BF_SCREENSHOT},

        "psexec":     {"sub": BF_JMP_PSEXEC},
        "wmi":        {"sub": BF_JMP_WMI},
        "winrm":      {"sub": BF_JMP_WINRM},

        "krb_asrep":  {"sub": BF_KRB_ASREP},
        "krb_asktgt": {"sub": BF_KRB_ASKTGT},
        "krb_asktgs": {"sub": BF_KRB_ASKTGS},
        "krb_dump":   {"sub": BF_KRB_DUMP},
        "krb_chngpw": {"sub": BF_KRB_CHNGPW},
        "krb_krbrst": {"sub": BF_KRB_KRBRST},
        "krb_klist":  {"sub": BF_KRB_KLIST},
        "krb_ptt":    {"sub": BF_KRB_PTT},
        "krb_purge":  {"sub": BF_KRB_PURGE},
        "krb_s4u":    {"sub": BF_KRB_S4U},
        "krb_renew":  {"sub": BF_KRB_RENEW},
        "krb_tgtdel": {"sub": BF_KRB_TGTDEL},
        "krb_triage": {"sub": BF_KRB_TRIAGE},
        "krb_descb":  {"sub": BF_KRB_DESCB},
        "krb_hash":   {"sub": BF_KRB_HASH}
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

        self.buffer += pack( "<q", data );
        self.length += 8;

        return;

    def Pad( self, data:bytes ) -> None:
        self.buffer += pack("<L", len(data)) + data
        self.length += 4 + len(data)
        return
    
    def Bytes( self, data: bytes ) -> None:

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

        val = struct.unpack( ">q", self.buffer[ :8 ] );
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
        return self.Bytes().decode( 'utf-8', errors="replace" );
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining

def is_valid_base64(s: str) -> bool:
    if len(s) % 4 != 0:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except:
        return False

def Dbg1( Input:str ) -> None:
    ConcStr = f"CHECKIN => {Input}";
    logging.info(ConcStr)

def Dbg2( Input:str ) -> None:
    ConcStr = f"POST => {Input}";
    logging.info(ConcStr)

def Dbg3( Input:str ) -> None:
    ConcStr = f"TASK => {Input}";
    logging.info(ConcStr)

def Dbg4( Input:str ) -> None:
    ConcStr = f"CHECKIN => {Input}";
    logging.info(ConcStr)

def Dbg5( Input:str ) -> None:
    ConcStr = f"TASK => {Input}";
    logging.info(ConcStr)

def Dbg6( Input:str ) -> None:
    ConcStr = f"POST => {Input}";
    logging.info(ConcStr)

def Dbg7( Input:str ) -> None:
    ConcStr = f"FMT => {Input}";
    logging.info(ConcStr)

def Dbg8( Input:str ) -> None:
    ConcStr = f"FMT => {Input}";
    logging.info(ConcStr)