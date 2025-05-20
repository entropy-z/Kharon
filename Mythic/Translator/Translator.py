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

        Response = TrMythicC2ToCustomMessageFormatMessageResponse( Success=True );
        
        Action = InputMsg.Message["action"];
        
        Dbg8( f"Action: {Action}" );
        Dbg8( f"Input Json: {InputMsg.Message}" );

        if "socks" in InputMsg.Message and InputMsg.Message["socks"]:
            SocksKey = InputMsg.Message["socks"]
        else: 
            SocksKey = []

        if Action == "checkin":
            Dbg8( f"ID: {InputMsg.Message["id"]}" );
            Response.Message = CheckinImp( InputMsg.Message["id"] );
        
        elif Action == "get_tasking":
            Dbg8( f"Tasks: {InputMsg.Message["tasks"]}" );
            Response.Message = RespTasking( InputMsg.Message["tasks"], SocksKey );

        elif Action == "post_response":
            Dbg8( f"Responses: {InputMsg.Message["responses"]}" );
            Response.Message = RespPosting( InputMsg.Message["responses"] );
        
        Dbg8( f"buffer [{len( Response.Message )}]" );
        Dbg8( "-----------------------\n" );

        return Response


    async def translate_from_c2_format( self, InputMsg: TrCustomMessageToMythicC2FormatMessage ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        Dbg7( "------------------------" );

        Response = TrCustomMessageToMythicC2FormatMessageResponse( Success=True );
        
        AgentMsg    = InputMsg.Message;
        Action      = AgentMsg[0];
        ActionData  = AgentMsg[1:];

        Dbg7( f"raw {AgentMsg}" )
        Dbg7( f"Action: {Action}" );

        if Action == Jobs['checkin']['hex_code']:
            Response.Message = await CheckinC2( ActionData );
        
        elif Action == Jobs['get_tasking']['hex_code']:
            Response.Message = GetTaskingC2( ActionData );
        
        elif Action == Jobs['post_response']['hex_code']:
            Response.Message = PostC2( ActionData );
        
        Dbg7( f"buffer: {len(Response.Message)}" );
        Dbg7( "-----------------------\n" );

        return Response