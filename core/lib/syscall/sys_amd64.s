//go:build amd64 && windows

#include "textflag.h"

// Signature: func executeSyscall(ssn uint32, gadget uintptr, args []uintptr) uint32
// Stack frame: $160-44 allocates local stack space for up to 16 arguments.
// Argument size is 44 = 40 (aligned params) + 4 (uint32 result).
TEXT ·executeSyscall(SB), NOSPLIT, $160-44
    // Preserve non-volatile registers required by Windows x64 ABI
    MOVQ BX,  120(SP)
    MOVQ R12, 128(SP)
    MOVQ R13, 136(SP)
    MOVQ SI,  144(SP)
    MOVQ DI,  152(SP)

    // Load SSN into EAX and gadget pointer into R11
    MOVL ssn+0(FP), AX
    MOVQ gadget+8(FP), R11

    // Extract slice pointer and length
    MOVQ args_base+16(FP), SI
    MOVQ args_len+24(FP), CX

    CMPQ CX, $0
    JE do_call

    // Register arguments (1 to 4)
    MOVQ 0(SI), R10
    CMPQ CX, $1
    JE do_call

    MOVQ 8(SI), DX
    CMPQ CX, $2
    JE do_call

    MOVQ 16(SI), R8
    CMPQ CX, $3
    JE do_call

    MOVQ 24(SI), R9
    CMPQ CX, $4
    JE do_call

    // Stack argument copying loop (5+)
    LEAQ 32(SP), DI
    LEAQ 32(SI), BX
    SUBQ $4, CX

copy_loop:
    CMPQ CX, $0
    JE do_call

    MOVQ (BX), R12
    MOVQ R12, (DI)

    ADDQ $8, BX
    ADDQ $8, DI
    DECQ CX
    JMP copy_loop

do_call:
    // CALL executing the indirect syscall gadget
    CALL R11

    // Restore preserved registers
    MOVQ 120(SP), BX
    MOVQ 128(SP), R12
    MOVQ 136(SP), R13
    MOVQ 144(SP), SI
    MOVQ 152(SP), DI

    // Move return value from RAX into Go return frame slot
    MOVL AX, ret+40(FP)
    RET
