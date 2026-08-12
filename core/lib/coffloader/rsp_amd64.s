//go:build windows && amd64

#include "textflag.h"

// func callBOF(entryPoint, argPtr, argLen uintptr)
// callBOF calls a BOF entry point directly (no cgocall), saving the stack
// pointer for VEH crash recovery. If the BOF crashes, the VEH handler uses
// NtContinue to redirect execution back to the instruction after CALL AX,
// avoiding Go's callback return machinery entirely.
TEXT ·callBOF(SB), NOSPLIT, $0-24
	// Save stack pointer. After CALL AX pushes the return address,
	// currentSavedRSP+0 holds the return address — the VEH handler reads
	// * (currentSavedRSP) to find where to resume.
	// It then sets CONTEXT.RSP = currentSavedRSP+8 and CONTEXT.RIP = *currentSavedRSP,
	// so execution continues at the instruction after CALL AX with the stack
	// pointing past the return address. The subsequent RET returns to invokeMethod.
	MOVQ SP, ·currentSavedRSP(SB)

	// Load BOF entry point and arguments (Windows x64 fastcall convention)
	MOVQ entryPoint+0(FP), AX   // AX = BOF entry point
	MOVQ argPtr+8(FP), CX       // CX = first arg (buffer pointer)
	MOVQ argLen+16(FP), DX      // DX = second arg (buffer size)

	// Call the BOF. On crash, VEH restores RIP=*currentSavedRSP, RSP=currentSavedRSP+8
	CALL AX

	// Normal return or VEH redirect lands here.
	// Clear saved RSP so stale values don't affect next invocation.
	MOVQ $0, ·currentSavedRSP(SB)
	RET
