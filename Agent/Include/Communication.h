#include <Win32.h>

#define KH_SOCKET_CLOSE 10
#define KH_SOCKET_NEW   20
#define KH_SOCKET_DATA  30

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;
} PARSER, *PPARSER;

