# Kharon Agent 

![kharon img](Assets/kharon-1.png)

C2 Agent for Mythic with advanced evasion capabilities, supporting dotnet/powershell/PE/shellcode/BOF memory execution, lateral movement, pivoting, SOCKS, and more. Kharon is a fully Position-Independent Code (PIC) shellcode based on [Startdust Project](https://github.com/Cracked5pider/Stardust) by [C5pider](https://x.com/C5pider) and llvm support. 

## Listener
The communication is all encrypted with AES256

### **SMB**
- Named pipe-based C2 channel
- Blends with legitimate Windows file sharing traffic

### **HTTP/S**
- Web-based encrypted communication
- Supports TLS-secured connections

## Evasion  
- Uses hardware breakpoints lib to bypass AMSI/ETW by [rad](https://x.com/rad9800).  
- Sleep obfuscation via timers.  
- Heap obfuscation during sleep (XOR).  
- Indirect syscalls (e.g., [Halo's Gate](https://github.com/boku7/AsmHalosGate)).  
- Call stack spoofing based on [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk).  

## Injection 
Supports injection of dotnet assemblies, PE files, shellcode, and Beacon Object Files (BOF). All execution is inline with exception of the shellcode for a while.

### General  
Allows customization of injection techniques, including:  
- **Allocation**: DripAlloc or standard allocation.  
- **Writing**: WriteMemoryAPC or standard memory writing (for inline is just used custom memcpy).  
- **Execution**: Normal thread creation, thread pool execution, or direct pointer invocation (inline execution).  

### Dotnet  
Can inject .NET assemblies and keep them in memory for later execution without reloading.  

### Powershell
Its using the PowerPick dotnet, you can pass the script url and command for execution.

### PE  
PE files can also be kept in memory and executed later. While idle, they are obfuscated using SystemFunction040/SystemFunction041 (also used for sleep obfuscation).  

### Shellcode  
Standard shellcode execution for post-exploitation, similar to BOF. Includes a specific template for custom shellcode development, allowing users to code their own shellcode and use it as a new command.  

### BOF (Beacon Object Files)  
Beyond standard BOF execution, the agent provides custom APIs such as `BeaconVirtualAlloc` and `BeaconLoadLibrary`. Future updates may include more APIs. The advantage of using these APIs is that they execute in the preferred context with stack spoofing and/or indirect syscalls.  

## Lateral Movement  
Advanced movement techniques:  
- **WMI** (Windows Management Instrumentation) execution  
- **SCM** (Service-based execution with custom implementation)  
- Seamless network traversal capabilities  

## File System Operations  
Core file management commands:  
| Command | Description                          | 
|---------|--------------------------------------|
| `cd`    | Change working directory             |
| `pwd`   | Print current working directory      |
| `cp`    | Copy files/directories               |
| `mv`    | Move/rename files                    |
| `ls`    | List directory contents              |
| `rm`    | Delete files/directories             |
| `cat`   | View file contents                   |

Here's an enhanced version of the Process Management section with more technical depth and better organization:

## Process Management  
Advanced process manipulation engine with defensive evasion capabilities:

### Process Creation
**Advanced Capabilities:**
- `PPID Spoofing`: Masquerade as child of legitimate processes (explorer.exe, svchost.exe, etc.)
- `Argument Spoofing`: Forge command-line arguments to evade detection
- `BlockDLL Enforcement`: Restrict non-Microsoft DLL injection
- `Suspended Process Creation`: For memory manipulation prior to execution
- `Output Redirection`: Anon pipe streaming (STDOUT/STDERR)

### Process List
Detailed enumeration of running processes with the following information:
- `Image Name`: The executable name (e.g., explorer.exe, svchost.exe)
- `Full Path`: Complete on-disk location of the process binary
- `Command Line`: Full execution command with arguments (if available)
- `Process ID (PID)`: Unique numerical identifier
- `Parent PID (PPID)`: Process that spawned the current instance
- `Session ID`: Terminal session association
- `User Context`: Security context under which the process runs
- `Handle Count`: Number of open handles (files, registry keys, etc.)
- `Thread Count`: Active execution threads

### Process Termination  
Kill the existence process.
