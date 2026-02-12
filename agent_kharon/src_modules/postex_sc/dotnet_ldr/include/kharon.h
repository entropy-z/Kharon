#ifndef KHARON_H
#define KHARON_H

#include <windows.h>

#define PIPE_BUFFER_SIZE 0x100000

// Beacon -> Module
#define CMD_RESUME              0x01
#define CMD_SUSPEND             0x02
#define CMD_KILL                0x03
#define CMD_OUTPUT              0x05

// Module -> Beacon
#define MSG_READY               0x10
#define MSG_OUTPUT              0x11
#define MSG_STATE               0x12
#define MSG_END                 0x13

// States
#define STATE_RUNNING           0x01
#define STATE_SUSPENDED         0x02
#define STATE_COMPLETED         0x03
#define STATE_DEAD              0x04

#pragma pack(push, 1)

// Beacon -> Module
typedef struct _PIPE_CMD {
    UINT32 magic;
    UINT32 cmd;
} PIPE_CMD, *PPIPE_CMD;

// Module -> Beacon 
typedef struct _PIPE_MSG {
    UINT64 magic;
    UINT32 type;
    struct {
        UINT32 state    : 4; 
        BOOL   nfree    : 1;
        BOOL   exit     : 1;
    };

    UINT32 exit_code; 
} PIPE_MSG, *PPIPE_MSG;

#pragma pack(pop)

typedef struct _POSTEX_CTX {
    ULONG  id;
    INT16  execmethod;
    INT8   spoof;
    INT8   bypassflag;
    ULONG  pipename_len;
    WCHAR* pipename;
    ULONG  argc;
    PBYTE  args;
} POSTEX_CTX;

#endif // KHARON_H