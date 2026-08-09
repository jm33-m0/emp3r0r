//go:build arm64 && windows

#include "textflag.h"

// func executeSyscall(ssn uint32, gadget uintptr, args []uintptr) uint32
TEXT ·executeSyscall(SB), NOSPLIT, $0-48
	MOVW $0, R0
	MOVW R0, ret+40(FP)
	RET
