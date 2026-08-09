//go:build amd64 && windows

#include "textflag.h"

// Signature: func getPEBAddress() uintptr
// Allocates 0 bytes of stack frame and 8 bytes for the uintptr return value.
TEXT ·getPEBAddress(SB), NOSPLIT, $0-8
    // Read the PEB pointer from GS segment offset 0x60 into RAX
    MOVQ 0x60(GS), AX

    // Store the result into the Go return value slot
    MOVQ AX, ret+0(FP)
    RET
