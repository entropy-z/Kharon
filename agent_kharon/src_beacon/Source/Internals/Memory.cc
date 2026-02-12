#include <Kharon.h>

auto DECLFN Memory::Read(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T Reads,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS    Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return NT_SUCCESS( Self->Ntdll.NtReadVirtualMemory(
            Handle, Base, Buffer, Size, (PULONG)Reads
        ));
    }

    UPTR Address = SYS_ADDR( Sys::Read );
    UPTR ssn = SYS_SSN( Sys::Read );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Base,
        (UPTR)Buffer, (UPTR)Size, (UPTR)Reads
    );

    Self->Usf->NtStatusToError(Status);

    return NT_SUCCESS(Status);
}

auto DECLFN Memory::Alloc(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   AllocType,
    _In_  ULONG   Protect,
    _In_  HANDLE  Handle
) -> PVOID {
    UINT32 Flags = Self->Config.Syscall;

    NTSTATUS Status      = STATUS_UNSUCCESSFUL;
    PVOID    BaseAddress = Base;
    SIZE_T   RegionSize  = Size;

    if ( ! Flags ) {
        KhDbg("execute without syscall and spoof");
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
        } else {
            return Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
        }
    }

    UPTR Address = SYS_ADDR( Sys::Alloc );
    UPTR ssn = SYS_SSN( Sys::Alloc );

    KhDbg("executing indirect syscall with spoof");
    KhDbg("address: %p", Address);
    KhDbg("ssn: %x", ssn);

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&BaseAddress,
        0, (UPTR)&RegionSize, (UPTR)AllocType, (UPTR)Protect
    );
    
    Self->Usf->NtStatusToError( Status );
    
    return NT_SUCCESS( Status ) ? BaseAddress : nullptr;
}

auto DECLFN Memory::Protect(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   NewProt,
    _Out_ ULONG  *OldProt,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
        } else {
            return Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
        }
    }

    UPTR Address = SYS_ADDR( Sys::Protect );
    UPTR ssn = SYS_SSN( Sys::Protect );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&Base,
        (UPTR)&Size, (UPTR)NewProt, (UPTR)OldProt
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::Write(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  ULONG   Size,
    _Out_ SIZE_T* Written,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags   = Self->Config.Syscall;
    NTSTATUS     Status  = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return NT_SUCCESS( Self->Ntdll.NtWriteVirtualMemory(
            Handle, Base, Buffer, Size, Written
        ));
    }

    UPTR Address = SYS_ADDR( Sys::Write );
    UPTR ssn = SYS_SSN( Sys::Write );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)Base,
        (UPTR)Buffer, (UPTR)Size, (UPTR)Written
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::Free(
    _In_ PVOID  Base,
    _In_ SIZE_T Size,
    _In_ ULONG  FreeType,
    _In_ HANDLE Handle
) -> BOOL {
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return NT_SUCCESS( Self->Ntdll.NtFreeVirtualMemory(
            Handle, &Base, &Size, FreeType
        ));
    }

    UPTR Address = SYS_ADDR( Sys::Free );
    UPTR ssn = SYS_SSN( Sys::Free );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)Handle, (UPTR)&Base, (UPTR)&Size, (UPTR)FreeType
    );

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::MapView(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID*          BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           PageProtection
) -> NTSTATUS {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return Self->Ntdll.NtMapViewOfSection(
            SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
            CommitSize, SectionOffset, ViewSize, InheritDisposition,
            AllocationType, PageProtection
        );
    }

    UPTR Address = SYS_ADDR( Sys::MapView );
    UPTR ssn = SYS_SSN( Sys::MapView );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)SectionHandle, (UPTR)ProcessHandle,
        (UPTR)BaseAddress, (UPTR)ZeroBits, (UPTR)CommitSize,
        (UPTR)SectionOffset, (UPTR)ViewSize, (UPTR)InheritDisposition,
        (UPTR)AllocationType, (UPTR)PageProtection
    );

    return Status;
}

auto DECLFN Memory::CreateSection(
    _Out_    PHANDLE           SectionHandle,
    _In_     ACCESS_MASK       DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER    MaximumSize,
    _In_     ULONG             SectionPageProtection,
    _In_     ULONG             AllocationAttributes,
    _In_opt_ HANDLE            FileHandle
) -> NTSTATUS {
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ! Flags ) {
        return Self->Ntdll.NtCreateSection(
            SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes,
            FileHandle
        );
    }

    UPTR Address = SYS_ADDR( Sys::CrSectn );
    UPTR ssn = SYS_SSN( Sys::CrSectn );

    Status = Self->Spf->Call(
        Address, ssn, (UPTR)SectionHandle, (UPTR)DesiredAccess,
        (UPTR)ObjectAttributes, (UPTR)MaximumSize,
        (UPTR)SectionPageProtection, (UPTR)AllocationAttributes,
        (UPTR)FileHandle
    );

    return Status;
}