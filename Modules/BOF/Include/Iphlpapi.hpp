#ifndef IPHLPAPI_HPP
#define IPHLPAPI_HPP

#include <Macros.hpp>
#include <iphlpapi.h>

EXTERN_C {
    DFR( IPHLPAPI, GetNetworkParams )
    DFR( IPHLPAPI, GetAdaptersInfo )
}

#define GetNetworkParams IPHLPAPI$GetNetworkParams
#define GetAdaptersInfo  IPHLPAPI$GetAdaptersInfo

#endif