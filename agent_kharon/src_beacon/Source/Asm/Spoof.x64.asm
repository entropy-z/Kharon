[BITS 64]

global SpoofCall

[SECTION .text$B]
    SpoofCall:
        ; ---------------------------------------------------------------------
        ; Initial Setup
        ; ---------------------------------------------------------------------
        pop rax             ; Save the real return address in rax
        mov r10, rdi        ; Preserve original rdi (1st param) in r10
        mov r11, rsi        ; Preserve original rsi (2nd param) in r11

        mov rdi, [rsp + 40] ; Load spoofing struct pointer into rdi
        mov rsi, [rsp + 32] ; Load target function address into rsi

        ; ---------------------------------------------------------------------
        ; Save Original Register State
        ; ---------------------------------------------------------------------
        mov [rdi + 0x50], r10       ; Store original rdi in struct
        mov [rdi + 0x58], r11       ; Store original rsi in struct  
        mov [rdi + 0x60], r12       ; Store original r12 in struct
        mov [rdi + 0x68], r13       ; Store original r13 in struct
        mov [rdi + 0x70], r14       ; Store original r14 in struct
        mov [rdi + 0x78], r15       ; Store original r15 in struct

        mov r12, rax                ; Save real return address in r12

        ; ---------------------------------------------------------------------
        ; Prepare Stack Argument Handling
        ; ----------------------------------------------------------------- ----
        xor r11, r11                ; r11 = counter for processed stack args
        mov r13, [rdi + 0x80]       ; Get argument count from struct (ArgCount at 0x80)
        
        mov r14, 0x200           ; r14 will hold the offset we need to push stuff
        add r14, 8
        add r14, [rdi + 0x08]       ; add RtlUserThreadStart frame
        add r14, [rdi + 0x18]       ; add BaseThreadInitThunk frame
        add r14, [rdi + 0x28]       ; add Gadget frame
        sub r14, 0x20               ; space for return address
        
        lea r10, [rsp + 0x28]

        ; ---------------------------------------------------------------------
        ; Stack Argument Processing Loop
        ; ---------------------------------------------------------------------
        .set_args:
            xor r15, r15     ; r15 will hold the offset + rsp base
            cmp r11d, r13d   ; comparing # of stack args added vs # of stack args we need to add
            je finish
        
            ; ---------------------------------------------------------------------
            ; Getting location to move the stack arg to
            ; ---------------------------------------------------------------------
            
            sub r14, 8          ; 1 arg means r11 is 0, r14 already 0x28 offset.
            mov r15, rsp        ; get current stack base
            sub r15, r14        ; subtract offset
            
            ; ---------------------------------------------------------------------
            ; Procuring the stack arg
            ; ---------------------------------------------------------------------
            
            add r10, 8

            push qword [r10]
            pop  qword [r15]   

            ; ---------------------------------------------------------------------
            ; Increment the counter and loop back in case we need more args
            ; ---------------------------------------------------------------------
            add r11, 1
            jmp .set_args

        ; ---------------------------------------------------------------------
        ; Setup Spoofed Call Stack
        ; ---------------------------------------------------------------------
        
        finish:
        sub rsp, 0x200
        push 0                      ; Terminate call stack with NULL return

        ; Build RtlUserThreadStart frame
        sub rsp, [rdi + 0x08]       ; Allocate frame space
        mov r11, [rdi + 0x00]       ; Get frame return address
        mov [rsp], r11              ; Set return address
        
        ; Build BaseThreadInitThunk frame  
        sub rsp, [rdi + 0x18]       ; Allocate frame space
        mov r11, [rdi + 0x10]       ; Get frame return address
        mov [rsp], r11              ; Set return address
        
        ; Build gadget frame
        sub rsp, [rdi + 0x28]       ; Allocate frame space
        mov r11, [rdi + 0x20]       ; Get frame return address
        mov [rsp], r11              ; Set return address

        ; ---------------------------------------------------------------------
        ; Prepare for Spoofed Call and Restoration
        ; ---------------------------------------------------------------------
        mov r11, rsi                ; Save target function address in r11
        
        ; Configure restoration information in struct:
        mov [rdi + 0x40], r12       ; Store real return address
        mov [rdi + 0x48], rbx       ; Preserve original rbx
        lea rbx, [rel .restore]     ; Get address of restore routine
        mov [rdi], rbx              ; Store restore address in struct
        mov rbx, rdi                ; Move struct address to rbx (will be preserved)
        
        ; Prepare for potential syscall
        mov r10, rcx                ; Preserve rcx
        mov rax, [rdi + 0x38]       ; Load potential syscall number
        
        jmp r11                     ; Jump to target function

        ; ---------------------------------------------------------------------
        ; Restoration Routine
        ; ---------------------------------------------------------------------
        .restore:
            mov rcx, rbx            ; Struct address to rcx
            
            ; Calculate total stack space to clean up
            add rsp, 0x200           ; add working space
            add rsp, [rbx + 0x08]    ; add RtlUserThreadStart frame
            add rsp, [rbx + 0x18]    ; add BaseThreadInitThunk frame
            add rsp, [rbx + 0x28]    ; add Gadget frame

            ; Restore all preserved registers
            mov rbx, [rcx + 0x48]   ; Restore original rbx
            mov rdi, [rcx + 0x50]   ; Restore original rdi
            mov rsi, [rcx + 0x58]   ; Restore original rsi
            mov r12, [rcx + 0x60]   ; Restore original r12
            mov r13, [rcx + 0x68]   ; Restore original r13
            mov r14, [rcx + 0x70]   ; Restore original r14
            mov r15, [rcx + 0x78]   ; Restore original r15

            jmp [rcx + 0x40]        ; Jump to real return address