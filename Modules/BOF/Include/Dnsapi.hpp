#ifndef DNSAPI_HPP
#define DNSAPI_HPP

#include <Common.hpp>

EXTERN_C {
    DECLSPEC_IMPORT INT WINAPI DNSAPI$DnsGetCacheDataTable(PVOID Data);
}

#define DnsGetCacheDataTable DNSAPI$DnsGetCacheDataTable

#endif