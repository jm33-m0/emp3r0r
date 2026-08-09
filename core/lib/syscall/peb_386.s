//go:build 386 && windows

#include "textflag.h"

// Signature: func getPEBAddress() uintptr
// Allocates 0 bytes of stack frame and 4 bytes for the uintptr return value.
TEXT ·getPEBAddress(SB), NOSPLIT, $0-4
    // Read the PEB pointer from FS segment offset 0x30 into EAX
    MOVL 0x30(FS), AX

    // Store the result into the Go return value slot
    MOVL AX, ret+0(FP)
    RET
