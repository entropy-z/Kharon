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
        AgTlDbg( "------------------------" );

        Response = TrMythicC2ToCustomMessageFormatMessageResponse( Success=True );
        
        Action = InputMsg.Message["action"];
        
        AgTlDbg( f"Action: {Action}" );

        if Action == "checkin":
            AgTlDbg( f"ID: {InputMsg.Message["id"]}" );
            Response.Message = CheckinImp( InputMsg.Message["id"] );
        
        elif Action == "get_tasking":
            AgTlDbg( f"Tasks: {InputMsg.Message["tasks"]}" );
            Response.Message = RespTasking( InputMsg.Message["tasks"] );
        
        elif Action == "post_response":
            AgTlDbg( f"Responses: {InputMsg.Message["responses"]}" );
            Response.Message = RespPosting( InputMsg.Message["responses"] );
        
        AgTlDbg( f"buffer [{len( Response.Message )}]: {Response.Message}" );
        AgTlDbg( "-----------------------\n" );

        return Response


    async def translate_from_c2_format( self, InputMsg: TrCustomMessageToMythicC2FormatMessage ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        C2TlDbg( "------------------------" );

        Response = TrCustomMessageToMythicC2FormatMessageResponse( Success=True );
        
        AgentMsg    = InputMsg.Message;
        Action      = AgentMsg[0];
        ActionData  = AgentMsg[1:];

        C2TlDbg( f"Action: {Action}"     );
        C2TlDbg( f"Data  : {ActionData}" );

        if Action == Jobs['checkin']['hex_code']:
            Response.Message = CheckinC2( ActionData );
        
        elif Action == Jobs['get_tasking']['hex_code']:
            Response.Message = GetTaskingC2( ActionData );
        
        elif Action == Jobs['post_response']['hex_code']:
            Response.Message = PostC2( ActionData );
        
        C2TlDbg( f"buffer: {Response.Message}" );
        C2TlDbg( "-----------------------\n" );

        return Response