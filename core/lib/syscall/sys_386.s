//go:build 386 && windows

#include "textflag.h"

// Signature: func executeSyscall(ssn uint32, gadget uintptr, args []uintptr) uint32
// Allocates 80 bytes of stack frame and 24 bytes for argument/return space.
TEXT ·executeSyscall(SB), NOSPLIT, $80-24
    // Save non-volatile registers
    MOVL BX, 64(SP)
    MOVL SI, 68(SP)
    MOVL DI, 72(SP)
    MOVL BP, 76(SP)

    // Save current stack pointer in BP to handle stdcall stack cleanup
    MOVL SP, BP

    // Load SSN into EAX
    MOVL ssn+0(FP), AX

    // Load gadget memory address into ECX
    MOVL gadget+4(FP), CX

    // Load args slice pointer and length
    MOVL args_ptr+8(FP), SI
    MOVL args_len+12(FP), BX

    // Point EDI to 0(SP)
    LEAL 0(SP), DI

copy_loop:
    CMPL BX, $0
    JE do_call

    // Copy argument from slice to target stack frame
    MOVL (SI), DX
    MOVL DX, (DI)

    ADDL $4, SI
    ADDL $4, DI
    DECL BX
    JMP copy_loop

do_call:
    // Execute indirect syscall gadget call
    CALL CX

    // Restore stack pointer from BP to undo stdcall RET N stack shifts
    MOVL BP, SP

    // Restore non-volatile registers
    MOVL 64(SP), BX
    MOVL 68(SP), SI
    MOVL 72(SP), DI
    MOVL 76(SP), BP

    // Move return value from EAX into Go return slot
    MOVL AX, ret+20(FP)
    RET