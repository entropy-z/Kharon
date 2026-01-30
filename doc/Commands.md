# Commands
// Currently the built-in commands are:
// - info
// Show details about target machine and session as well as beacon configuration info. Output commands example as follows:
Atualmente os built-in commands sao:

- info
Mostra diversos detalhes sobre a configuracao do beacon, session e maquina alvo. exemplo do output do comando abaixo:
```
kharon > info
[29/01 20:44:52] [*] Kharon config informations:
┌───────────────────────────┬────────────────────────────────────────────────────┐
│                                SESSION INFORMATION                             │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Agent ID                  │ 280753bb                                           │
│ Image Name                │ Kharon.x64.exe                                     │
│ Image Path                │ D:\Kharon.x64.exe                                  │
│ Command Line              │ D:\Kharon.x64.exe                                  │
│ Process ID                │ 29760                                              │
│ Thread ID                 │ 29764                                              │
│ Parent ID                 │ 29708                                              │
│ Elevated                  │ False                                              │
│ Process Arch              │ 0x64                                               │
│ Heap Handle               │ 0x00000180AE7D0000                                 │
│ Kharon in-memory base     │ 0x7ff7da741020                                     │
│ Kharon in-memory Size     │ 101360 bytes                                       │
│ Code Page (ACP)           │ 1252                                               │
│ OEM Code Page             │ 437                                                │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                               TIMING CONFIGURATION                             │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Sleep Time                │ 3000 ms                                            │
│ Jitter                    │ 0%                                                 │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                EVASION TECHNIQUES                              │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Mask Beacon               │ None                                               │
│ Heap Mask                 │ True                                               │
│ Jump Gadget               │ 0x7ffd58f85039                                     │
│ NtContinue Gadget         │ 0x7ffd00000000                                     │
│ BOF API Proxy             │ False                                              │
│ Syscall Method            │ None                                               │
│ AMSI/ETW Bypass           │ None                                               │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                 PROCESS SPAWNING                               │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Parent PID                │ 0                                                  │
│ Block DLLs                │ False                                              │
│ Spawn To                  │ C:\Windows\System32\notepad.exe                    |
│ Fork Pipe                 │ \\.\pipe\kharon_pipe                               │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                              KILLDATE CONFIGURATION                            │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Use Killdate              │ False                                              │
│ Exit Type                 │ Exit Process                                       │
│ Self Delete               │ False                                              │
│ Killdate                  │ 00/00/0000                                         │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                              WORKTIME CONFIGURATION                            │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Enable Worktime           │ False                                              │
│ Start Time                │ 00:00                                              │
│ End Time                  │ 00:00                                              │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                    GUARDRAILS                                  │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ IP Address                │                                                    │
│ Hostname                  │                                                    │
│ Username                  │                                                    │
│ Domain                    │                                                    │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                SYSTEM INFORMATION                              │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Username                  │ <user-name>                                        │
│ Computer Name             │ <machine-name>                                     │
│ NetBIOS Name              │ DESKTOP-NJFOEJD                                    │
│ Domain                    │                                                    │
│ IP Address                │ <local-ip-address>                                 │
│ OS Architecture           │ 0x64                                               │
│ OS Version                │ 10.0.26200                                         │
│ Processor Name            │ <processor-name>                                   │
│ Processor Count           │ 16                                                 │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                MEMORY INFORMATION                              │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ Total RAM                 │ 32693 MB                                           │
│ Available RAM             │ 15047 MB                                           │
│ Used RAM                  │ 17646 MB                                           │
│ RAM Usage                 │ 53%                                                │
│ Page Size                 │ 4096 bytes                                         │
│ Allocation Granularity    │ 65536 bytes                                        │
├───────────────────────────┼────────────────────────────────────────────────────┤
│                                 SECURITY FEATURES                              │
├───────────────────────────┼────────────────────────────────────────────────────┤
│ CFG Enabled               │ False                                              │
│ DSE Status                │ Disabled                                           │
│ VBS/HVCI                  │ Disabled                                           │
└───────────────────────────┴────────────────────────────────────────────────────┘
```

### config
Utiliza para mudar o behavior de algumas coisas do Kharon, este comando possui sub comandos como:
- sleep : altera o intervalo durasnte callbacks
- jitter : altera a porcentagem de jitter para randomizacao do sleep
- ppid : configura o parent process id dos processos gerados pelo kharon, em todos comandos de criacao de processo
- blockdlls : bloqueia non-microsoft dlls de carregarem em processos gerados pelo kharon, implica em todos comandos de criacao de processo
- worktime : configura o intervalo de horarios do dia em que o kharon tera atividade de callback
- killdate.date : altera a data para o kharon terminar sua execucao
- killdate.exit : o metodo de exit utilizado quando kharon parar de executar (thread/process)
- killdate.selfel : define o kharon para deletar o pe do disco no qual ele esta sendo executado
- mask.heap : configura se o kharon deve ou nao criptografar suas alocacoes na heap durante o tempo de sleep
- mask.beacon : define o metodo de masking do kharon, options disponiveis sao (timer/none)
- amsi_etw_bypass : configure AMSI/ETW bypass no 
