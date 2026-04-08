[BITS 64]

global ReadMmByGadget

[SECTION .text$B]
    ReadMmByGadget:
        mov  rax, rcx
        call rdx
        ret