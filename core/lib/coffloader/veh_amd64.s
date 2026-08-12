//go:build windows && amd64

#include "textflag.h"

// func vehAsmHandler(exceptionPointers uintptr) uintptr
//
// Vectored Exception Handler written in pure assembly — no CGo, no
// windows.NewCallback. When Windows calls this directly with the
// platform ABI (RCX=ExceptionInfo), it checks isExecutingBOF and
// currentSavedRSP, redirects execution, records the fault, and returns
// EXCEPTION_CONTINUE_EXECUTION.
//
// This avoids the CGo callback machinery entirely, so there is no
// exitsyscall frame mismatch when execution is redirected.
TEXT ·vehAsmHandler(SB), NOSPLIT, $0-16
	// RCX = EXCEPTION_POINTERS*
	TESTQ CX, CX
	JZ return_0

	// Check isExecutingBOF
	LEAQ ·isExecutingBOF(SB), AX
	CMPB (AX), $0
	JEQ return_0

	// Load currentSavedRSP
	LEAQ ·currentSavedRSP(SB), DX
	MOVQ (DX), DX
	TESTQ DX, DX
	JEQ return_0

	// Read return address from [currentSavedRSP - 8] (CALL AX pushes at SP-8)
	MOVQ -8(DX), AX   // AX = return address from CALL AX

	// Load ContextRecord from EXCEPTION_POINTERS
	MOVQ 8(CX), CX  // CX = ContextRecord
	TESTQ CX, CX
	JEQ return_0

	// Set CONTEXT.RSP = currentSavedRSP (skip CALL AX ret addr, RET pops invokeMethod return)
	MOVQ DX, BX
	MOVQ BX, 0x98(CX)

	// Set CONTEXT.RIP = return address (from [savedRsp-8])
	MOVQ AX, 0xF8(CX)

	// hasFaulted = true
	LEAQ ·hasFaulted(SB), BX
	MOVB $1, (BX)

	// isExecutingBOF = false
	LEAQ ·isExecutingBOF(SB), BX
	MOVB $0, (BX)

	// Return EXCEPTION_CONTINUE_EXECUTION (-1)
	MOVQ $-1, AX
	RET

return_0:
	XORL AX, AX
	RET

// vehAsmHandlerAddr exports the address of vehAsmHandler as a uintptr
// that Go code can pass directly to AddVectoredExceptionHandler.
DATA ·vehAsmHandlerAddr+0(SB)/8, $·vehAsmHandler(SB)
GLOBL ·vehAsmHandlerAddr(SB), NOPTR, $8
