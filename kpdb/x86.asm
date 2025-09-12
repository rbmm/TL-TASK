.686

_TEXT segment

?strnlen@NT@@YIIIPBD@Z proc
	xor eax,eax
	jecxz @@2
	push edi
	mov edi,edx
	repne scasb
	jne @@1
	dec edi
@@1:
	sub edi,edx
	mov eax,edi
	pop edi
@@2:
	ret
?strnlen@NT@@YIIIPBD@Z endp

@retz4 proc
	xor eax,eax
	ret 4
@retz4 endp

?findDWORD@NT@@YIPAKKPBKK@Z proc
	jecxz @retz4
	xchg edi,edx
	mov eax,[esp + 4]
	repne scasd
	lea eax,[edi-4]
	cmovne eax,ecx
	mov edi,edx
	ret 4
?findDWORD@NT@@YIPAKKPBKK@Z endp

_TEXT ends
end