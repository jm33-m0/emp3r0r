	BITS 64

	section .text
	global  _start

_start:
	xor eax, eax
	xor edi, edi
	xor esi, esi

	;;     char *filename
	;[push filename here]

	mov sil, 2

	mov  rax, 0x7f040c32d930
	call rax
	int3
