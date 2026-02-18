[BITS 64]

EXTERN entry

GLOBAL startptr
GLOBAL endptr

[SECTION .text$A]
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 0x20
        call  entry
        mov   rsp, rsi
        pop   rsi
        ret

    startptr:
        call startretstart
        ret

    startretstart:
        mov   rax, [rsp]
        sub   rax, 0x1b  
        ret     

[SECTION .text$C]
    endptr:
        lea   rax, [rel section_end]
        ret
    
    section_end: