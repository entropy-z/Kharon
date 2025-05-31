[BITS 64]

EXTERN Main

GLOBAL StartPtr
GLOBAL EndPtr

[SECTION .text$A]
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 0x20
        call  Main
        mov   rsp, rsi
        pop   rsi
        ret

    StartPtr:
        call RetStartPtr
        ret

    RetStartPtr:
        mov   rax, [rsp]
        sub   rax, 0x1b  
        ret     

[SECTION .text$C]
    EndPtr:
        call RetEndPtr
        ret

    RetEndPtr:
        mov	rax, [rsp]
        sub	rax, 0x5
        ret