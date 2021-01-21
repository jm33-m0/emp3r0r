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

wait4zombie:
	;;  wait to clean up zombies
	xor rdi, rdi
	mov rdi, rax
	xor rsi, rsi
	xor rdx, rdx
	xor r10, r10
	xor rax, rax
	mov al, 0x3d
	syscall

sleep:
	;;   sleep
	xor  rax, rax
	mov  al, 0x23; syscall nanosleep
	push 10; sleep nano sec
	push 20; sec
	mov  rdi, rsp
	xor  rsi, rsi
	xor  rdx, rdx
	syscall
	loop watchdog

exec:
	;;   char **envp
	xor  rdx, rdx
	xor  rax, rax
	push rdx; '\0'

	;;     char *filename
	;[push filename here]

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

	; exit:
	; ;; exit
	; xor rax, rax
	; xor rdi, rdi
	; xor rsi, rsi
	; mov al, 0x3c; syscall exit
	; mov di, 0x0; exit code
	; syscall
