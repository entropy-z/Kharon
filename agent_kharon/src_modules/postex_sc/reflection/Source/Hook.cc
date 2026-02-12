#include <General.hpp>

namespace Hook {

//==============================================================================
// Exit Prevention Hooks
//==============================================================================

class ExitHandler {
public:
    static auto RtlExitUserProcess(LONG ExitCode) -> VOID {
        // Prevent process exit - do nothing
        return;
    }

    static auto NtTerminateProcess(HANDLE Handle, UINT ExitCode) -> BOOL {
        auto* instance = GetInstance();
        
        if (Handle == NtCurrentProcess()) {
            instance->Win32.ExitThread(ExitCode);
            return TRUE;
        }
        
        return instance->Win32.NtTerminateProcess(Handle, ExitCode);
    }

private:
    static auto GetInstance() -> INSTANCE* {
        return reinterpret_cast<INSTANCE*>(NtCurrentPeb()->TelemetryCoverageHeader);
    }
};

//==============================================================================
// Memory Management Hooks
//==============================================================================

class MemoryManager {
public:
    static auto NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T* RegionSize,
        ULONG AllocType,
        ULONG Protect
    ) -> LONG {
        return AllocVm( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocType, Protect );
    }

    static auto VirtualAlloc(
        PVOID  Address,
        SIZE_T Size,
        ULONG  AllocType,
        ULONG  Protect
    ) -> PVOID {
        auto*  instance = GetInstance();
        PVOID  addrTemp = Address;
        SIZE_T sizeTemp = Size;
        
        const LONG status = NtAllocateVirtualMemory(
            NtCurrentProcess(), &addrTemp, 0, &sizeTemp, AllocType, Protect
        );
        
        SetLastError( instance->Win32.RtlNtStatusToDosError( status ) );
        return addrTemp;
    }

    static auto VirtualAllocEx(
        HANDLE ProcessHandle,
        PVOID Address,
        SIZE_T Size,
        ULONG AllocType,
        ULONG Protect
    ) -> PVOID {
        auto* instance = GetInstance();
        PVOID addrTemp = Address;
        SIZE_T sizeTemp = Size;
        
        const LONG status = NtAllocateVirtualMemory(
            ProcessHandle,
            &addrTemp,
            0,
            &sizeTemp,
            AllocType,
            Protect
        );
        
        SetLastError(instance->Win32.RtlNtStatusToDosError(status));
        return addrTemp;
    }

    static auto NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T Size,
        SIZE_T* Written
    ) -> LONG {
        return WriteVm(ProcessHandle, BaseAddress, Buffer, Size, Written);
    }

    static auto WriteProcessMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T Size,
        SIZE_T* Written
    ) -> BOOL {
        auto* instance = GetInstance();
        
        const LONG status = NtWriteVirtualMemory(
            ProcessHandle,
            BaseAddress,
            Buffer,
            Size,
            Written
        );
        
        SetLastError(instance->Win32.RtlNtStatusToDosError(status));
        return (status == STATUS_SUCCESS);
    }

    static auto NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        SIZE_T* RegionSize,
        ULONG NewProtection,
        ULONG* OldProtection
    ) -> NTSTATUS {
        auto* instance = GetInstance();
        
        if (!instance->Ctx.IsSpoof) {
            return instance->Win32.NtProtectVirtualMemory(
                ProcessHandle,
                BaseAddress,
                RegionSize,
                NewProtection,
                OldProtection
            );
        }
        
        return static_cast<NTSTATUS>(
            Spoof::Call(
                reinterpret_cast<PVOID>(instance->Win32.NtProtectVirtualMemory),
                nullptr,
                reinterpret_cast<PVOID>(ProcessHandle),
                reinterpret_cast<PVOID>(BaseAddress),
                reinterpret_cast<PVOID>(RegionSize),
                reinterpret_cast<PVOID>(NewProtection),
                reinterpret_cast<PVOID>(OldProtection)
            )
        );
    }

    static auto VirtualProtect(
        LPVOID Address,
        SIZE_T Size,
        DWORD NewProtect,
        PDWORD OldProtect
    ) -> BOOL {
        auto* instance = GetInstance();
        PVOID addr = Address;
        SIZE_T size = Size;
        ULONG oldProt = 0;
        
        const NTSTATUS status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &addr,
            &size,
            NewProtect,
            &oldProt
        );
        
        if (OldProtect) {
            *OldProtect = oldProt;
        }
        
        SetLastError(instance->Win32.RtlNtStatusToDosError(status));
        return NT_SUCCESS(status);
    }

    static auto VirtualProtectEx(
        HANDLE ProcessHandle,
        LPVOID Address,
        SIZE_T Size,
        DWORD NewProtect,
        PDWORD OldProtect
    ) -> BOOL {
        auto* instance = GetInstance();
        PVOID addr = Address;
        SIZE_T size = Size;
        ULONG oldProt = 0;
        
        const NTSTATUS status = NtProtectVirtualMemory(
            ProcessHandle,
            &addr,
            &size,
            NewProtect,
            &oldProt
        );
        
        if (OldProtect) {
            *OldProtect = oldProt;
        }
        
        SetLastError(instance->Win32.RtlNtStatusToDosError(status));
        return NT_SUCCESS(status);
    }

private:
    static auto GetInstance() -> INSTANCE* {
        return reinterpret_cast<INSTANCE*>(NtCurrentPeb()->TelemetryCoverageHeader);
    }
    
    static auto SetLastError(DWORD error) -> VOID {
        NtCurrentTeb()->LastErrorValue = error;
    }
};

auto RtlExitUserProcess(LONG ExitCode) -> VOID {
    return ExitHandler::RtlExitUserProcess(ExitCode);
}

auto NtTerminateProcess(HANDLE Handle, UINT ExitCode) -> BOOL {
    return ExitHandler::NtTerminateProcess(Handle, ExitCode);
}

auto NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocType,
    ULONG Protect
) -> LONG {
    return MemoryManager::NtAllocateVirtualMemory(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocType, Protect
    );
}

auto VirtualAlloc(PVOID Address, SIZE_T Size, ULONG AllocType, ULONG Protect) -> PVOID {
    return MemoryManager::VirtualAlloc( Address, Size, AllocType, Protect );
}

auto VirtualAllocEx(
    HANDLE ProcessHandle,
    PVOID Address,
    SIZE_T Size,
    ULONG AllocType,
    ULONG Protect
) -> PVOID {
    return MemoryManager::VirtualAllocEx( ProcessHandle, Address, Size, AllocType, Protect );
}

auto NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    SIZE_T* Written
) -> LONG {
    return MemoryManager::NtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer, Size, Written
    );
}

auto WriteProcessMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    SIZE_T* Written
) -> BOOL {
    return MemoryManager::WriteProcessMemory(
        ProcessHandle, BaseAddress, Buffer, Size, Written
    );
}

auto VirtualProtect(
    LPVOID Address,
    SIZE_T Size,
    DWORD NewProtect,
    PDWORD OldProtect
) -> BOOL {
    return MemoryManager::VirtualProtect( Address, Size, NewProtect, OldProtect );
}

auto VirtualProtectEx(
    HANDLE ProcessHandle,
    LPVOID Address,
    SIZE_T Size,
    DWORD NewProtect,
    PDWORD OldProtect
) -> BOOL {
    return MemoryManager::VirtualProtectEx(
        ProcessHandle, Address, Size, NewProtect, OldProtect
    );
}

auto NtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    SIZE_T* RegionSize,
    ULONG   NewProtection,
    ULONG*  OldProtection
) -> NTSTATUS {
    return MemoryManager::NtProtectVirtualMemory(
        ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection
    );
}

} // namespace Hook