# Process Injection Kit
Kharon utilizes commands such as ``postex`` and ``scinject`` that uses the injection kit process for injection behavior control.
You can customize these behavior by editing the ``kit_explicit_inject.cc`` and ``kh_spawn_injecyt.cc`` files located in ``agent_kharon/src_modules/kit/``.
More details about ``postex`` and ``scinject`` clicking [Here](./Commands.md).

The process creation behavior file ``kit_process_creation.cc`` is located on the ``agent_kharon/src_modules/kit/`` directory. To utilize it, simply call the function ``KhpCreateProcess`` with the process ID as a parameter. While ``KhpSpawnProcess`` utilizes spawnto process in the creation of a new project. 

> KhpCreateProcess
```cpp
auto inline KhpCreateProcess( 
    _In_  datap*               DataParser,
    _In_  WCHAR*               SpawnProcess,
    _In_  ULONG                StateFlag,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> NTSTATUS {
#if defined(PS_INJECT_KIT)
#include <kit/process_creation.cc>
#endif

    ULONG  ParentId  = BeaconDataInt( DataParser );
    BOOL   BlockDlls = BeaconDataInt( DataParser );
    HANDLE PsToken   = (HANDLE)BeaconDataInt( DataParser );

    PS_CREATE_ARGS CreateArgs = {};

    CreateArgs.argument  = SpawnProcess;
    CreateArgs.state     = StateFlag;
    CreateArgs.ppid      = ParentId;
    CreateArgs.blockdlls = BlockDlls;

    return kh_process_creation( &CreateArgs, PsInfo );
}
```

> KhpSpawnProcess
```cpp
auto inline KhpSpawntoProcess(
    _In_  datap*               DataParser,
    _In_  ULONG                StateFlag,
    _Out_ PROCESS_INFORMATION* PsInfo
) -> NTSTATUS {
#if defined(PS_INJECT_KIT)
#include <kit/process_creation.cc>
#endif

    WCHAR* SpawntoProcess = (WCHAR*)BeaconDataExtract( DataParser, nullptr );
    ULONG  ParentId       = BeaconDataInt( DataParser );
    BOOL   BlockDlls      = BeaconDataInt( DataParser );
    HANDLE PsToken        = (HANDLE)BeaconDataInt( DataParser );

    PS_CREATE_ARGS CreateArgs = {};

    CreateArgs.argument  = SpawntoProcess;
    CreateArgs.state     = StateFlag;
    CreateArgs.ppid      = ParentId;
    CreateArgs.blockdlls = BlockDlls;

    return kh_process_creation( &CreateArgs, PsInfo );
}
```