[BITS 64]

GLOBAL CLRCreateInstanceProxy
GLOBAL LoadLibraryAProxy

[SECTION .text$B]
    CLRCreateInstanceProxy:
        mov rbx, rcx        ; store the context in the rbx
        mov rax, [rbx]      ; function pointer
        mov rcx, [rbx+0x08] ; clsid metahost (first argument)
        mov rdx, [rbx+0x10] ; riid metahost (second argument)
        mov r8,  [rbx+0x18] ; ICLRMetaHost Interface (third argument)

        jmp rax ; jmp to CLRCreateInstance

    LoadLibraryAProxy:
        mov rbx, rcx        ; store the context in the rbx
        mov rax, [rbx]      ; function pointer
        mov rcx, [rbx+0x8]  ; library name (first argument)

        jmp rax ; jmp to LoadLibraryA