//go:build windows && amd64

#include "textflag.h"

// func vehAsmHandler(exceptionPointers uintptr) uintptr
//
// Lightweight VEH handler — records BOF crash details for telemetry and
// returns EXCEPTION_CONTINUE_SEARCH. Go's cgocall SEH then handles the
// exception (converts to panic, which may terminate the goroutine).
// The timeout in LoadWithToken prevents hanging.
//
// This avoids CGo callback issues because we don't redirect execution.
TEXT ·vehAsmHandler(SB), NOSPLIT, $0-16
	// RCX = EXCEPTION_POINTERS*
	TESTQ CX, CX
	JZ return_0

	// Check isExecutingBOF
	LEAQ ·isExecutingBOF(SB), AX
	CMPB (AX), $0
	JEQ return_0

	// hasFaulted = true
	LEAQ ·hasFaulted(SB), BX
	MOVB $1, (BX)

	// isExecutingBOF = false
	LEAQ ·isExecutingBOF(SB), BX
	MOVB $0, (BX)

	// Return EXCEPTION_CONTINUE_SEARCH — let Go's cgocall handle recovery
return_0:
	XORL AX, AX
	RET

// vehAsmHandlerAddr exports the address of vehAsmHandler as a uintptr.
DATA ·vehAsmHandlerAddr+0(SB)/8, $·vehAsmHandler(SB)
GLOBL ·vehAsmHandlerAddr(SB), NOPTR, $8
