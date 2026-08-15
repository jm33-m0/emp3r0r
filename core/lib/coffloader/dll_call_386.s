//go:build 386 && windows

#include "textflag.h"

// func cdeclCall3(fn, a, b, c uintptr) uintptr
//
// Calls a __cdecl function with three pointer-sized arguments and cleans the
// stack afterwards. COFFLoader's LoadAndRun is exported as __cdecl, unlike
// the stdcall convention assumed by syscall.SyscallN on 386 Windows.
TEXT ·cdeclCall3(SB), NOSPLIT, $4-20
    MOVL BX, 0(SP)        // preserve callee-saved BX
    MOVL fn+0(FP), AX
    MOVL a+4(FP), CX
    MOVL b+8(FP), DX
    MOVL c+12(FP), BX
    PUSHL BX
    PUSHL DX
    PUSHL CX
    CALL AX
    MOVL AX, BX           // save return value
    POPL AX
    POPL AX
    POPL AX               // cdecl caller cleanup (3 * 4 bytes)
    MOVL BX, ret+16(FP)
    MOVL 0(SP), BX        // restore BX
    RET
