[BITS 64]

GLOBAL ExecSyscall

[SECTION .text$B]
    ExecSyscall
	int3
		xor r10, r10                          
		mov rax, rcx                          
		mov r10, rax                
		mov eax, [r14]               
		jmp Child                               
		xor eax, eax      
		xor rcx, rcx      
		shl r10, 2        
	Child:
		jmp [r15]
        xor r15, r15
        xor r14, r14
		xor r10, r10                        
		mov r15, r10          
		ret