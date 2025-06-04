# Kharon Agent 

![kharon img](Assets/kharon-1.png)

C2 Agent for Mythic with advanced evasion capabilities, supporting dotnet/powershell/PE/shellcode/BOF memory execution, lateral movement, pivoting, SOCKS, and more. Kharon is a fully Position-Independent Code (PIC) shellcode and llvm support. 

## Listener
- **HTTP/S**: Web-based encrypted communication
- **SMB**: Named pipe-based C2 channel

## Evasion  
- Uses hardware breakpoints to bypass AMSI/ETW.
- Sleep obfuscation via timers.  
- Heap obfuscation during sleep (XOR).  
- Indirect syscalls.  
- Call stack spoofing.

## Execution in memory 
Supports injection of dotnet assembly, PE file, shellcode, and Beacon Object File (BOF). All execution is inline with exception of the shellcode for a while.

### General  
Allows customization of injection techniques, including:  
- **Allocation**: DripAlloc or standard allocation.  
- **Writing**: WriteMemoryAPC or standard memory writing (for inline is just used custom memcpy).  
- **Execution**: Normal thread creation, thread pool execution, or direct pointer invocation (inline execution).  

### Methods
- **Dotnet**: Can inject .NET assembly and keep them in memory for later execution without reloading.  
- **Powershell**: Its using PowerPick, you can pass the script url and command for execution.
- **PE**: PE file can also be kept in memory and executed later. While idle, they are obfuscated using SystemFunction040/SystemFunction041 (also used for sleep obfuscation).   
- **Shellcode**: Standard shellcode execution for post-exploitation, similar to BOF. Includes a specific template for custom shellcode development, allowing users to code their own shellcode and use it as a new command.  
- **BOF (Beacon Object File)**: Beyond standard BOF execution, the agent provides custom APIs such as `BeaconVirtualAlloc` and `BeaconLoadLibrary`. Future updates may include more APIs. The advantage of using these APIs is that they execute in the preferred context with stack spoofing and/or indirect syscalls.  

## Lateral Movement  
Advanced movement techniques:  
- **WMI**: Windows Management Instrumentation execution  
- **SCM**: Service-based execution with custom implementation 
- **WinRM**: Windows Remote Management execution via COM without spawn powershell binary

## Process Creation
- **PPID Spoofing**: Masquerade as child of legitimate processes (explorer.exe, svchost.exe, etc.)
- **Argument Spoofing**: Forge command-line arguments to evade detection
- **BlockDLL Enforcement**: Restrict non-Microsoft DLL injection

## Misc Commands
- Registry Interaction
- SCM Interaction
- Token Manipulation
- Any Netapi32 commands
- Slack cookie dump
- ipconfig, whoami, env, arp, dns cache and uptime

Check the [References](REFERENCES.md)!