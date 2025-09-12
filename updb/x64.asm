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

_TEXT ENDS
END