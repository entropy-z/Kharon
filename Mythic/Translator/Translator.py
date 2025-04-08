import json
import base64
import binascii
import os
import logging

from Translator.Utils import *
from Translator.FromC2 import *
from Translator.FromAgent import *
from mythic_container.TranslationBase import *

logging.basicConfig( level=logging.INFO );

class KharonTranslator( TranslationContainer ):
    name        = "KharonTranslator";
    description = "Translator for Kharon agent";
    author      = "@ Oblivion";

    async def translate_to_c2_format( self, InputMsg: TrMythicC2ToCustomMessageFormatMessage ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        AgTlDbg( "------------------------" );
        AgTlDbg( "Starting..." );

        Response = TrMythicC2ToCustomMessageFormatMessageResponse( Success=True );
        
        Action = InputMsg.Message["action"];
        
        AgTlDbg( f"Action: {Action}" );

        if Action == "checkin":
            AgTlDbg( f"ID: {InputMsg.Message["id"]}" );
            Response.Message = CheckinC2( InputMsg.Message["id"] );
        
        elif Action == "get_tasking":
            AgTlDbg( f"Tasks: {InputMsg.Message["tasks"]}" );
            Response.Message = GetTaskingC2( InputMsg.Message["tasks"] );
        
        elif Action == "post_response":
            AgTlDbg( f"Responses: {InputMsg.Message["responses"]}" );
            Response.Message = PostC2( InputMsg.Message["responses"] );
        
        AgTlDbg( "-----------------------\n" );

        return Response


    async def translate_from_c2_format( self, InputMsg: TrCustomMessageToMythicC2FormatMessage ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        C2TlDbg( "------------------------" );
        C2TlDbg( "Starting..." );

        Response = TrCustomMessageToMythicC2FormatMessageResponse( Success=True );
        
        AgentMsg    = InputMsg.Message;
        Action      = AgentMsg[0];
        ActionData  = AgentMsg[1:];

        C2TlDbg( f"Action: {Action}"     );
        C2TlDbg( f"Data  : {ActionData}" );

        if Action == "checkin":
            Response.Message = checkin_to_mythic_format( ActionData );
        
        elif Action == "get_tasking": 
            Response.Message = get_tasking_to_mythic_format( ActionData );
        
        elif Action == "post_response": 
            Response.Message = post_response_to_mythic_format( ActionData );
        
        # elif Action == MYTHIC_INIT_DOWNLOAD: 
        #     Response.Message = download_init_to_mythic_format( ActionData );
        
        # elif Action == MYTHIC_CONT_DOWNLOAD: 
        #     Response.Message = download_cont_to_mythic_format( ActionData );
        
        # elif Action == MYTHIC_UPLOAD_CHUNKED: 
        #     Response.Message = upload_to_mythic_format(Action_data);

        C2TlDbg( "-----------------------\n-" );

        return Response