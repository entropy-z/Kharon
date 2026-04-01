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
        ; ---------------------------------------------------------------------
        xor r11, r11                ; r11 = counter for processed stack args
        mov r13, [rdi + 0x80]       ; Get argument count from struct (ArgCount at 0x80)

        mov r14, 0x200
        add r14, 8                  ; NULL terminator (push 0)
        add r14, [rdi + 0x08]       ; RtlUserThreadStart frame size
        add r14, [rdi + 0x18]       ; BaseThreadInitThunk frame size
        add r14, [rdi + 0x28]       ; Gadget frame size
        add r14, 8                  ; Extra push for gadget return address on top

        ; r10 points to the first stack argument on the original stack
        lea r10, [rsp + 0x28]

        .set_args:
            xor r15, r15
            cmp r11d, r13d          ; Compare processed args vs total args needed
            je .finish

            ; Calculate destination: current rsp - total offset - per-arg offset
            sub r14, 8              ; Each arg occupies 8 bytes going downward
            mov r15, rsp
            sub r15, r14            ; r15 = destination address for this arg

            ; Fetch the next stack argument from the caller's frame
            add r10, 8

            push qword [r10]        ; Read source arg
            pop  qword [r15]        ; Write to destination slot

            ; Increment counter and loop
            add r11, 1
            jmp .set_args

    .finish:
        sub rsp, 0x200
        push 0                          ; NULL terminator

        ; --- Frame 3 (deepest): RtlUserThreadStart ---
        sub rsp, [rdi + 0x08]           ; Allocate RtlUserThreadStart frame
        mov r11, [rdi + 0x00]           ; RtlUserThreadStart+0x21
        mov [rsp], r11                  ; Return address for this frame

        ; --- Frame 2: BaseThreadInitThunk ---
        sub rsp, [rdi + 0x18]           ; Allocate BaseThreadInitThunk frame
        mov r11, [rdi + 0x10]           ; BaseThreadInitThunk+0x14
        mov [rsp], r11                  ; Return address for this frame

        sub rsp, [rdi + 0x28]           ; Allocate gadget function's frame
        mov r11, [rdi + 0x20]           ; Gadget address (jmp [rbx])
        mov [rsp], r11                  ; Return address: gadget itself
                                        ; (unwinder sees this as the return
                                        ; into the gadget's function)

        ; ---------------------------------------------------------------------
        ; Prepare registers and execute target
        ; ---------------------------------------------------------------------
        mov r11, rsi                    ; Target function address

        ; Store restoration context
        mov [rdi + 0x40], r12           ; Real return address
        mov [rdi + 0x48], rbx           ; Preserve caller's rbx

        lea rax, [rel .restore]
        mov [rdi], rax                  ; struct[0x00] = .restore address
        mov rbx, rdi                    ; rbx = &struct (so jmp [rbx] reads
                                        ; struct[0x00] = .restore)

        ; Syscall setup
        mov r10, rcx
        mov rax, [rdi + 0x38]           ; SSN

        jmp r11                         ; Execute target function
                                        ; Target does ret -> pops gadget addr
                                        ; Gadget (jmp [rbx]) -> .restore

        .restore:
            mov rcx, rbx

            add rsp, [rbx + 0x28]       ; Gadget frame
            sub rsp, 8                   ; ret already popped 8
            
            add rsp, [rbx + 0x18]       ; BaseThreadInitThunk frame
            add rsp, [rbx + 0x08]       ; RtlUserThreadStart frame
            add rsp, 8                   ; NULL terminator
            add rsp, 0x200              ; Working space

            ; Restore registers
            mov rbx, [rcx + 0x48]
            mov rdi, [rcx + 0x50]
            mov rsi, [rcx + 0x58]
            mov r12, [rcx + 0x60]
            mov r13, [rcx + 0x68]
            mov r14, [rcx + 0x70]
            mov r15, [rcx + 0x78]

            jmp [rcx + 0x40]