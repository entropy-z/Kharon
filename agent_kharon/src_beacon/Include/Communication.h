#include <Win32.h>

#define KH_SOCKET_CLOSE 10
#define KH_SOCKET_NEW   20
#define KH_SOCKET_DATA  30

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

enum class Base64Action {
    Get_Size,
    Encode,
    Decode
};

typedef enum class OutputFmt {
    Raw,
    Base32,
    Base64,
    Base64Url
};

typedef enum _OUTPUT_TYPE {
    Output_Parameter,
    Output_Header,
    Output_Body,
    Output_Format_Count
} OUTPUT_TYPE;

typedef struct _OUTPUT_FORMAT {
    OUTPUT_TYPE Type;

    union {
        struct {
            WCHAR* ParamName; 
            BOOL   Encode;    
        } Parameter;
        
        struct {
            WCHAR* HeaderName;
        } Header;
        
        struct {
            WCHAR* ContentType;
            DWORD  Flags;
        } Body;
    } Config;
    
    WCHAR* FormatTemplate;
    DWORD  FormatFlags;
} OUTPUT_FORMAT, *POUTPUT_FORMAT;

typedef struct _HTTP_ENDPOINT {
    WCHAR*         Path;
    OUTPUT_FORMAT  Output;
    
    PBYTE          AppendData;
    SIZE_T         AppendSize;
    PBYTE          PrependData;
    SIZE_T         PrependSize;
    PBYTE          DoNothingBuff;
    
    WCHAR**        Parameters;
    ULONG          ParamCount;
    
    WCHAR**        Headers;
    ULONG          HeaderCount;
} HTTP_ENDPOINT, *PHTTP_ENDPOINT;

typedef struct _HTTP_METHOD_ENDPOINTS {
    HTTP_ENDPOINT* Endpoints;      
    ULONG          EndpointCount;  
    
    OUTPUT_FORMAT  DefaultOutput;  
    PBYTE          DefaultAppend;
    PBYTE          DefaultPrepend;
} HTTP_METHOD_ENDPOINTS, *PHTTP_METHOD_ENDPOINTS;

typedef struct _HTTP_CALLBACKS {
    WCHAR*                 Host;
    ULONG                  Port;
    WCHAR*                 BaseUrl;
    
    WCHAR*                 Headers;       // Global Headers 
    WCHAR**                Cookies;       // Global Cookies
    ULONG                  CookieCount;
    
    HTTP_METHOD_ENDPOINTS  Get;           // Endpoints GET
    HTTP_METHOD_ENDPOINTS  Post;          // Endpoints POST
} HTTP_CALLBACKS, *PHTTP_CALLBACKS;

typedef _SMB_PROFILE_DATA SMB_PROFILE_DATA;
