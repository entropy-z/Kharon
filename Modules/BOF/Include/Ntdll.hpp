#ifndef NTDLL_HPP
#define NTDLL_HPP

#include <Common.hh>
#include <Native.hpp>

EXTERN_C {
    DFR( NTDLL, NtOpenSection )
    DFR( NTDLL, NtCreateSection )
    DFR( NTDLL, NtMapViewOfSection )
    DFR( NTDLL, NtUnmapViewOfSection )
}

#define NtOpenSection           NTDLL$NtOpenSection
#define NtCreateSection         NTDLL$NtCreateSection
#define NtMapViewOfSection      NTDLL$NtMapViewOfSection
#define NtUnmapViewOfSection    NTDLL$NtUnmapViewOfSection

#endif //NTDLL_HPP