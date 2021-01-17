	BITS 64

	section .data
	msg     db "emp3r0r", 0xa

	section .text
	global  _start

_start:
	;;  fork
	xor rax, rax
	xor rdi, rdi
	mov al, 0x39; syscall fork
	syscall

	cmp  rax, 0x0; if in child process
	je   write
	call pause; stop the parent

write:
	;;   write emp3r0r to stdout
	xor  rax, rax
	xor  rdi, rdi
	mov  al, 0x01; syscall write
	mov  di, 1; fd is stdout
	mov  esi, msg; the msg text
	mov  edx, 8; count
	syscall
	call exit

pause:
	;;  stop
	int 0x3

exit:
	;;  exit
	xor rax, rax
	xor rdi, rdi
	mov al, 0x3c; syscall exit
	mov di, 0x00; exit code
	syscall
