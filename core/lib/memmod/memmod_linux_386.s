//go:build linux && !android && !cgo && 386

#include "textflag.h"

// The cCall helpers are entered through the Go ABI with a uintptr receiver
// frame. They marshal stack arguments for the i386 SysV C ABI and deliberately
// avoid the x87 stack so integer-returning exports are not disturbed.

TEXT ·cCall0(SB), NOSPLIT, $0-8
	MOVL fn+0(FP), AX
	CALL AX
	MOVL AX, ret+4(FP)
	RET

TEXT ·cCall1(SB), NOSPLIT, $0-12
	MOVL fn+0(FP), AX
	MOVL a0+4(FP), BX
	SUBL $4, SP
	MOVL BX, 0(SP)
	CALL AX
	ADDL $4, SP
	MOVL AX, ret+8(FP)
	RET

TEXT ·cCall2(SB), NOSPLIT, $0-16
	MOVL fn+0(FP), AX
	MOVL a0+4(FP), BX
	MOVL a1+8(FP), CX
	SUBL $8, SP
	MOVL BX, 0(SP)
	MOVL CX, 4(SP)
	CALL AX
	ADDL $8, SP
	MOVL AX, ret+12(FP)
	RET

TEXT ·cCall3(SB), NOSPLIT, $0-20
	MOVL fn+0(FP), AX
	MOVL a0+4(FP), BX
	MOVL a1+8(FP), CX
	MOVL a2+12(FP), DX
	SUBL $12, SP
	MOVL BX, 0(SP)
	MOVL CX, 4(SP)
	MOVL DX, 8(SP)
	CALL AX
	ADDL $12, SP
	MOVL AX, ret+16(FP)
	RET

TEXT ·cCall4(SB), NOSPLIT, $0-24
	MOVL fn+0(FP), AX
	MOVL a0+4(FP), BX
	MOVL a1+8(FP), CX
	MOVL a2+12(FP), DX
	MOVL a3+16(FP), SI
	SUBL $16, SP
	MOVL BX, 0(SP)
	MOVL CX, 4(SP)
	MOVL DX, 8(SP)
	MOVL SI, 12(SP)
	CALL AX
	ADDL $16, SP
	MOVL AX, ret+20(FP)
	RET

TEXT ·cCall5(SB), NOSPLIT, $0-28
	MOVL fn+0(FP), AX
	MOVL a0+4(FP), BX
	MOVL a1+8(FP), CX
	MOVL a2+12(FP), DX
	MOVL a3+16(FP), SI
	MOVL a4+20(FP), DI
	SUBL $20, SP
	MOVL BX, 0(SP)
	MOVL CX, 4(SP)
	MOVL DX, 8(SP)
	MOVL SI, 12(SP)
	MOVL DI, 16(SP)
	CALL AX
	ADDL $20, SP
	MOVL AX, ret+24(FP)
	RET
