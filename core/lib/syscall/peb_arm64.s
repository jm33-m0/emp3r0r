//go:build arm64 && windows

#include "textflag.h"

// func getPEBAddress() uintptr
TEXT ·getPEBAddress(SB), NOSPLIT, $0-8
	MOVD $0, R0
	MOVD R0, ret+0(FP)
	RET
