import json
import base64
import binascii
import os
import logging

from Translator.Utils import *
from Translator.ToAgent import*
from Translator.ToC2    import *
from mythic_container.TranslationBase import *

logging.basicConfig( level=logging.INFO );

class KharonTranslator( TranslationContainer ):
    name        = "KharonTranslator";
    description = "Translator for Kharon agent";
    author      = "@ Oblivion";

    async def translate_to_c2_format( self, InputMsg: TrMythicC2ToCustomMessageFormatMessage ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        Dbg8( "------------------------" );

        Response  = TrMythicC2ToCustomMessageFormatMessageResponse( Success=True );
        Action    = InputMsg.Message["action"];
        AgentUUID = InputMsg.UUID
        
        Dbg8( f"Action: {Action}" );
        Dbg8( f"Input Json: {InputMsg.Message}" );

        if "socks" in InputMsg.Message and InputMsg.Message["socks"]:
            SocksKey = InputMsg.Message["socks"]
        else: 
            SocksKey = []

        if Action == "checkin":
            Dbg8( f"ID: {InputMsg.Message['id']}" );
            Response.Message = await CheckinImp( InputMsg.Message["id"], InputMsg.UUID );
            AgentUUID        =  InputMsg.Message["id"]
        
        elif Action == "get_tasking":
            Dbg8( f"Tasks: {InputMsg.Message['tasks']}" );
            Response.Message = RespTasking( InputMsg.Message["tasks"], SocksKey );

        elif Action == "post_response":
            Dbg8( f"Responses: {InputMsg.Message['responses']}" );
            Response.Message = RespPosting( InputMsg.Message["responses"] );
        
        search_resp: MythicRPCAgentStorageSearchMessageResponse = await SendMythicRPCAgentStorageSearch(MythicRPCAgentStorageSearchMessage(
            AgentUUID
        ))
        StorageMsg = base64.b64decode( base64.b64decode( search_resp.AgentStorageMessages[0]["data"].encode("utf-8") ).decode("utf-8") )
        EncryptKey = StorageMsg[-16:]
        Crypter    = LokyCrypt( EncryptKey )  
        PlainTxt   = Response.Message
        CipherTxt  = Crypter.encrypt( Response.Message )

        Response.Message = CipherTxt

        Dbg8( f"UUID     {AgentUUID}" )
        Dbg8( f"Key      {EncryptKey}" )
        Dbg8( f"plain    {PlainTxt}  [{len( PlainTxt )}]" );
        Dbg8( f"cipher   {CipherTxt} [{len( CipherTxt )}]" );
        Dbg8( f"response {Response.Message} [{len( Response.Message )}]" );
        Dbg8( "-----------------------\n" );

        return Response

    async def translate_from_c2_format( self, InputMsg: TrCustomMessageToMythicC2FormatMessage ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        Dbg7( "------------------------" );

        Response     = TrCustomMessageToMythicC2FormatMessageResponse( Success=True );
        EncryptKey   = b""

        search_resp: MythicRPCAgentStorageSearchMessageResponse = await SendMythicRPCAgentStorageSearch(MythicRPCAgentStorageSearchMessage(
            InputMsg.UUID
        ))

        if search_resp.Success is True and search_resp.AgentStorageMessages:
            print( search_resp.AgentStorageMessages[0]["data"].encode("utf-8") )
            StorageMsg = base64.b64decode( base64.b64decode( search_resp.AgentStorageMessages[0]["data"].encode("utf-8") ).decode("utf-8") )
            EncryptKey   = StorageMsg[-16:]
            if not EncryptKey or len(EncryptKey) != 16:
                EncryptKey = InputMsg.Message[-16:] 
        else:
            EncryptKey = InputMsg.Message[-16:]

        AgentMsg  = InputMsg.Message;
        Crypter   = LokyCrypt( EncryptKey )  
        TextPlain = Crypter.decrypt( AgentMsg )

        Action      = TextPlain[0];
        ActionData  = TextPlain[1:];

        Dbg7( f"raw dec: {TextPlain}" )
        Dbg7( f"Action: {Action}" );
        Dbg7( f"Encrypt Key: {EncryptKey} [{len(EncryptKey)}]" );

        if Action == Jobs['checkin']['hex_code']:
            Response.Message = await CheckinC2( ActionData, EncryptKey );
        
        elif Action == Jobs['quick_out']['hex_code']:
            Response.Message = QuickOut( ActionData );

        elif Action == Jobs['quick_msg']['hex_code']:
            Response.Message = QuickMsg( ActionData );
        
        elif Action == Jobs['get_tasking']['hex_code']:
            Response.Message = GetTaskingC2( ActionData );
        
        elif Action == Jobs['post_response']['hex_code']:
            Response.Message = PostC2( ActionData );
        
        Dbg7( f"buffer: {Response.Message} length {len(Response.Message)}" );
        Dbg7( "-----------------------\n" );

        return Response