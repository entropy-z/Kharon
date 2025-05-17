#ifndef USER32_H
#define USER32_H

#include <Common.hpp>

EXTERN_C {
    DFR( USER32, printf );
    DFR( USER32, GetSystemMetrics );
    DFR( USER32, GetDC );
    DFR( USER32, vsnprintf );
    DFR( USER32, wcscmp );
    DFR( USER32, memcpy );
}

#define wcscmp    USER32$wcscmp
#define printf    USER32$printf
#define GetSystemMetrics   USER32$GetSystemMetrics
#define GetDC    USER32$GetDC
#define vsnprintf USER32$vsnprintf
#define memcpy    USER32$memcpy

#endif