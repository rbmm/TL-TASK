_TEXT segment 'CODE'

?strnlen@NT@@YA_K_KPEBD@Z proc
	xor eax,eax
	jecxz @@2
	push rdi
	mov rdi,rdx
	repne scasb
	jne @@1
	dec rdi
@@1:
	sub rdi,rdx
	mov rax,rdi
	pop rdi
@@2:
	ret
?strnlen@NT@@YA_K_KPEBD@Z endp

?findDWORD@NT@@YAPEAK_KPEBKK@Z proc
	jrcxz @retz
	xchg rdi,rdx
	mov rax,r8
	repne scasd
	lea rax, [rdi-4]
	cmovne rax, rcx
	mov rdi,rdx
	ret
?findDWORD@NT@@YAPEAK_KPEBKK@Z endp

@retz proc
	xor eax,eax
	ret
@retz endp

_TEXT ENDS
END