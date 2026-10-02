//go:build !cgo && linux && !android && arm64

#include "textflag.h"

// func flushARM64InstructionCache(start, end uintptr)
//
// Clean the data cache and invalidate the instruction cache over [start, end).
// The DC CVAU and IC IVAU encodings are written as WORD literals because Go's
// assembler does not accept the IC IVAU mnemonic.
TEXT ·flushARM64InstructionCache(SB), NOSPLIT, $0-16
	MOVD start+0(FP), R0
	MOVD end+8(FP), R1
	CMP  R1, R0
	BGE  done

	WORD $0xd53b0022 // mrs x2, ctr_el0

	// Data cache line size: 4 << ((ctr >> 16) & 0xf).
	LSR  $16, R2, R3
	AND  $0xf, R3, R3
	MOVD $4, R4
	LSL  R3, R4, R3
	SUB  $1, R3, R5
	BIC  R5, R0, R6
dc_loop:
	CMP  R1, R6
	BGE  dc_done
	WORD $0xd50b7b26 // dc cvau, x6
	ADD  R3, R6, R6
	B    dc_loop
dc_done:
	DSB $11 // dsb ish

	// Instruction cache line size: 4 << (ctr & 0xf).
	AND  $0xf, R2, R3
	MOVD $4, R4
	LSL  R3, R4, R3
	SUB  $1, R3, R5
	BIC  R5, R0, R6
ic_loop:
	CMP  R1, R6
	BGE  ic_done
	WORD $0xd50b7526 // ic ivau, x6
	ADD  R3, R6, R6
	B    ic_loop
ic_done:
	DSB $11 // dsb ish
	ISB $11 // isb
done:
	RET
