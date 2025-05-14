extern _G_DriverObject:QWORD
extern __imp_ObfDereferenceObject:QWORD

; void __cdecl NT::_RundownRoutine(struct NT::_KAPC *)
extern ?_RundownRoutine@NT@@YAXPEAU_KAPC@1@@Z : PROC

; void __cdecl NT::_KernelRoutine(struct NT::_KAPC *,void (__cdecl **)(void *,void *,void *),void **,void **,void **)
extern ?_KernelRoutine@NT@@YAXPEAU_KAPC@1@PEAP6AXPEAX11@ZPEAPEAX33@Z : PROC

; void __cdecl NT::_NormalRoutine(struct NT::_KAPC *,void *,int)
extern ?_NormalRoutine@NT@@YAXPEAU_KAPC@1@PEAXH@Z : PROC

.code

; void __cdecl NT::RundownRoutine(struct NT::_KAPC *)
?RundownRoutine@NT@@YAXPEAU_KAPC@1@@Z proc
	sub rsp,40
	call ?_RundownRoutine@NT@@YAXPEAU_KAPC@1@@Z
	add rsp,40
	mov rcx,_G_DriverObject
	jmp __imp_ObfDereferenceObject
?RundownRoutine@NT@@YAXPEAU_KAPC@1@@Z endp

; void __cdecl NT::KernelRoutine(struct NT::_KAPC *,void (__cdecl **)(void *,void *,void *),void **,void **,void **)
?KernelRoutine@NT@@YAXPEAU_KAPC@1@PEAP6AXPEAX11@ZPEAPEAX33@Z proc
	mov rax,[rsp + 40]
	mov [rsp + 24],rax
	mov rax,[rsp]
	mov [rsp + 32],rax
	push rax
	call ?_KernelRoutine@NT@@YAXPEAU_KAPC@1@PEAP6AXPEAX11@ZPEAPEAX33@Z
	pop rax
	mov rax,[rsp + 32]
	mov [rsp],rax
	mov rcx,_G_DriverObject
	jmp __imp_ObfDereferenceObject
?KernelRoutine@NT@@YAXPEAU_KAPC@1@PEAP6AXPEAX11@ZPEAPEAX33@Z endp

; void __cdecl NT::NormalRoutine(void *,void *,void *)
?NormalRoutine@NT@@YAXPEAX00@Z proc
	sub rsp,40
	call ?_NormalRoutine@NT@@YAXPEAU_KAPC@1@PEAXH@Z
	add rsp,40
	mov rcx,_G_DriverObject
	jmp __imp_ObfDereferenceObject
?NormalRoutine@NT@@YAXPEAX00@Z endp

.const

public ?SC_begin@@3QBEB, ?SC_end@@3QBEB, ?DLL_begin@@3QBEB, ?DLL_end@@3QBEB

?DLL_begin@@3QBEB LABEL BYTE
INCLUDE <../../SC/Y-D/x64.asm>
?DLL_end@@3QBEB LABEL BYTE

ALIGN 16

?SC_begin@@3QBEB LABEL BYTE
INCLUDE <../../SC/ScLfm/ScLfm.x64.asm>
?SC_end@@3QBEB LABEL BYTE

public ?SCx86_begin@@3QBEB, ?SCx86_end@@3QBEB, ?DLLx86_begin@@3QBEB, ?DLLx86_end@@3QBEB

?DLLx86_begin@@3QBEB LABEL BYTE
INCLUDE <../../SC/Y-D/x86.asm>
?DLLx86_end@@3QBEB LABEL BYTE

ALIGN 16

?SCx86_begin@@3QBEB LABEL BYTE
INCLUDE <../../SC/ScLfm/ScLfm.x86.asm>
?SCx86_end@@3QBEB LABEL BYTE

end