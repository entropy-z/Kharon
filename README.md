# Kharon Agent 

![kharon img](Assets/kharon-1jpg.jpg)

C2 Agent for Mythic with advanced evasion capabilities, supporting dotnet/PE/shellcode/BOF memory execution, lateral movement, pivoting, SOCKS, and more. Kharon is a fully Position-Independent Code (PIC) shellcode agent.  

## Evasion  
- Uses hardware breakpoints to bypass AMSI/ETW.  
- Sleep obfuscation via timers.  
- Heap obfuscation during sleep (XOR).  
- Indirect syscalls (e.g., [Halo's Gate](https://github.com/boku7/AsmHalosGate)).  
- Call stack spoofing based on [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk).  

## Injection  
Supports injection of dotnet assemblies, PE files, shellcode, and Beacon Object Files (BOF).  

### General  
Allows customization of injection techniques, including:  
- **Allocation**: DripAlloc or standard allocation.  
- **Writing**: WriteMemoryAPC or standard memory writing.  
- **Execution**: Normal thread creation, thread pool execution, or direct pointer invocation (inline execution).  

### Dotnet  
Can inject .NET assemblies and keep them in memory for later execution without reloading.  

### PE  
PE files can also be kept in memory and executed later. While idle, they are obfuscated using SystemFunction040/SystemFunction041 (also used for sleep obfuscation).  

### Shellcode  
Standard shellcode execution for post-exploitation, similar to BOF. Includes a specific template for custom shellcode development, allowing users to code their own shellcode and use it as a new command.  

### BOF (Beacon Object Files)  
Beyond standard BOF execution, the agent provides custom APIs such as `BeaconVirtualAlloc` and `BeaconLoadLibrary`. Future updates may include more APIs. The advantage of using these APIs is that they execute in the preferred context with stack spoofing and/or indirect syscalls.  

## Lateral Movement  
Kharon enables remote execution on target machines using:  
- **WMI (Windows Management Instrumentation)**  
- **Service Control Manager (SCM)** (similar to PsExec but with its own implementation).  

This allows for seamless lateral movement within a network.