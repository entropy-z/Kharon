[BITS 64]

GLOBAL ClrCreateInstanceProxy
GLOBAL LoadLibraryAProxy

[SECTION .text$B]
    ClrCreateInstanceProxy:
        mov rbx, rcx        ; store the context in the rbx
        mov rax, [rbx]      ; function pointer
        mov rcx, [rbx+0x08] ; clsid metahost (first argument)
        mov rdx, [rbx+0x10] ; riid metahost (second argument)
        mov r8,  [rbx+0x18] ; ICLRMetaHost Interface (argument)

        jmp rax ; call the CLRCreateInstance

    LoadLibraryAProxy:
        mov rbx, rcx        ; store the context in the rbx
        mov rax, [rbx]      ; function pointer
        mov rcx, [rbx+0x8]  ; library name (first argument)

        jmp rax ; call the LoadLibraryA