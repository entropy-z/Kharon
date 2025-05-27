# .NET Execution
Run CLRCreateInstance with call spoof (if enabled)

# Beacon Object File 
Check if module and function loaded before try load, resolve GetModuleHandleA/W and GetProcAddress without DFR

## APIs
- BeaconDataParse
- BeaconDataInt
- BeaconDataShort
- BeaconDataLength
- BeaconOutput
- BeaconPrintf
- BeaconFormatAlloc
- BeaconFormatReset
- BeaconFormatFree
- BeaconFormatAppend
- BeaconFormatPrintf
- BeaconFormatToString
- BeaconFormatInt
- BeaconVirtualAlloc/Ex
- BeaconVirtualProtect/Ex
- BeaconOpenProcess
- BeaconOpenThread

## Hooks
Support functions
- VirtualAlloc
- VirtualProtect
- VirtualAllocEx
- VirtualProtectEx
- WriteProcessMemory
- ReadProcessMemory
- CreateThread
- LoadLibraryA
- OpenProcess
- OpenThread
- NtQueueApcThread

