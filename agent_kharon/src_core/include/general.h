#ifndef GENERAL_H
#define GENERAL_H

#include <ntstatus.h>
#include <beacon.h>
#include <externs.h>

#define nt_current_process() ((HANDLE)-1)
#define PIPE_BUFFER_DEFAULT_LEN 0x10000

typedef DWORD ERROR_CODE;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          TotalNumberOfObjects;
    ULONG          TotalNumberOfHandles;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

auto inline fmt_error( _In_ int error_code ) -> WCHAR* {
    WCHAR* error_msg = nullptr;
    ULONG  flags     = FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                       FORMAT_MESSAGE_FROM_SYSTEM     | 
                       FORMAT_MESSAGE_IGNORE_INSERTS;
    
    ULONG msg_len = FormatMessageW(
        flags, nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (WCHAR*)&error_msg, 0, nullptr
    );

    return error_msg;
}

typedef union _BASICEX_PARAM {
    ULONG Flags;

    struct {
        ULONG Arch: 8;
        ULONG ParentId: 8;
        ULONG ProcessId: 8;
        ULONG Protection: 8;
    };
} BASICEX_FLAGS;

typedef enum class Create {
    Default,
    WithLogon,
    WithToken
};

struct _PS_CREATE_ARGS {
    Create method;
    ULONG  state;
    ULONG  ppid;

    BOOL pipe;
    BOOL blockdlls;

    HANDLE token;

    WCHAR* argument;
    WCHAR* spoofarg;

    WCHAR* domain;
    WCHAR* username;
    WCHAR* password;
};
typedef _PS_CREATE_ARGS PS_CREATE_ARGS;

auto kh_process_creation( 
    _In_      PS_CREATE_ARGS*      create_args,
    _Out_opt_ PROCESS_INFORMATION* ps_information,
    _Out_opt_ PBYTE*               output_ptr  = nullptr,
    _Out_opt_ ULONG*               output_len  = nullptr,
    _Out_opt_ BOOL                 spawnto     = TRUE
) -> ULONG;

#endif // GENERAL_H