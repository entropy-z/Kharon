#include <Win32.h>

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

    BOOL    Endian;
} PARSER, *PPARSER;

namespace Web {
    auto Checkin(
        VOID
    ) -> BOOL;

    auto Send(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    ) -> BOOL;
}

namespace Package {
    auto AddInt32( 
        _In_ PPACKAGE Package, 
        _In_ UINT32   dataInt
    ) -> VOID;

    auto AddInt64( 
        _In_ PPACKAGE Package, 
        _In_ UINT64   dataInt 
    ) -> VOID;

    auto AddPad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddBytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) -> VOID;

    auto AddByte( 
        _In_ PPACKAGE Package, 
        _In_ BYTE     dataInt 
    ) -> VOID;

    auto Create( 
        _In_ UINT32 CommandID 
    ) -> PPACKAGE;

    auto New( 
        VOID
    ) -> PPACKAGE;

    auto Destroy( 
        _In_ PPACKAGE Package 
    ) -> VOID;

    auto Transmit( 
        _In_  PPACKAGE Package, 
        _Out_ PVOID*   Response, 
        _Out_ PSIZE_T  Size 
    ) -> BOOL;

    auto Error(
        _In_ UINT32 ErrorCode,
        _In_ PSTR   InputString
    ) -> VOID;

    auto AddString( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) -> VOID;

    auto AddWString( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) -> VOID;
}

namespace Parser {
    auto New( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT32  size 
    ) -> VOID;

    auto Destroy(
        _In_ PPARSER Parser
    ) -> BOOL;

    auto GetByte(
        _In_ PPARSER Parser
    ) -> BYTE;

    auto GetInt16(
        _In_ PPARSER Parser
    ) -> INT16;

    auto GetInt32(
        _In_ PPARSER Parser
    ) -> INT32;

    auto GetInt64(
        _In_ PPARSER Parser
    ) -> INT64;

    auto GetBytes(
        _In_  PPARSER parser,
        _Out_ PULONG  size
    ) -> PBYTE;

    auto GetStr( 
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PCHAR;

    auto GetWstr(
        _In_ PPARSER parser, 
        _In_ PULONG  size 
    ) -> PWCHAR;

    auto Destroy(
        _In_ PPARSER Parser 
    ) -> BOOL;    
}