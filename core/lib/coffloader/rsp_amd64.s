//go:build windows && amd64

#include "textflag.h"

// func callBOF(entryPoint, argPtr, argLen uintptr)
TEXT ·callBOF(SB), NOSPLIT, $0-24
	MOVQ SP, BX
	MOVQ entryPoint+0(FP), AX
	MOVQ argPtr+8(FP), CX
	MOVQ argLen+16(FP), DX

	CALL runtime·entersyscall(SB)

	ANDQ $-16, SP
	SUBQ $40, SP
	MOVQ SP, ·currentSavedRSP(SB)
	CALL AX

	MOVQ BX, SP
	CALL runtime·exitsyscall(SB)
	RET
