# Kharon Agent 

![kharon img](Assets/kharon-1.png)

C2 Agent for Mythic with advanced evasion capabilities, supporting dotnet/powershell/shellcode/BOF memory execution, lateral movement, pivoting, and more. Kharon is a fully Position-Independent Code (PIC) shellcode. 

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

### Methods
- **Dotnet**: Can inject .NET assembly and execution in memory. 
- **Powershell**: Its using PowerPick, you can pass the script url and command for execution. 
- **Shellcode**: Standard shellcode execution in memory.
- **BOF (Beacon Object File)**: Beyond standard BOF execution, the agent provides custom APIs such as metioned in documentation. Future updates may include more APIs. The advantage of using these APIs is that they execute in the preferred context with stack spoofing and/or indirect syscalls.  

## Lateral Movement  
Advanced movement techniques:  
- **WMI**: Windows Management Instrumentation execution  
- **SCM**: Service-based execution with custom implementation 
- **WinRM**: Windows Remote Management execution via COM without spawn powershell binary

## Process Creation
- **PPID Spoofing**: Masquerade as child of legitimate processes (explorer.exe, svchost.exe, etc.)
- **Argument Spoofing**: Forge command-line arguments to evade detection
- **BlockDLL Enforcement**: Restrict non-Microsoft DLL injection

## Kerberos Interactions
Some command to kerberos interaction like klist, ptt, describe, triage, s4u and more.

## Misc Commands
- Registry Interaction
- SCM Interaction
- Token Manipulation
- Any Netapi32 commands
- Slack cookie dump
- ipconfig, whoami, env, arp, dns cache and uptime

Check the [References](REFERENCES.md)!