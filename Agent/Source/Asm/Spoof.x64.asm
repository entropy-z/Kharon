[BITS 64]

[SECTION text$B]
    Restore:
        ; restore the stack modified
        mov rsp, rbp
        add rsp, 0x200
        mov rbp, [rsp+0x08]
        mov rbx, [rsp+0x10]
        mov r15, [rsp+0x18]

    Spoof:
        ; saving non-vol registers
        mov [rsp+0x08], rbp
        mov [rsp+0x10], rbx
        mov [rsp+0x18], r15

        ; create stack ref to the jmp rbx gadget
        mov rbx, [r8+0x10]
        mov [rsp+0x20], rbx
        mov rbx, rsp
        add rbx, 0x20
        mov [r8+0x18], rbx

        ; prolog
        sub rsp, 0x200
        mov rbp, rsp

        ; create pointer to restore
        lea rax, Restore
        push rax
        lea rbx, [rsp]

        ; first frame prep
        push [r8]
