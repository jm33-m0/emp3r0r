//go:build windows

package coffloader

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Vectored Exception Handler based crash protection for in-memory COFF/BOF
// execution.
//
// The COFFLoader DLL and the Beacon Object Files it runs are untrusted native
// code. A single bad pointer raises a native structured exception (usually
// EXCEPTION_ACCESS_VIOLATION) that Go's recover() cannot see. This guard
// follows the same pattern used by lib/script's win_call: register a Vectored
// Exception Handler that runs *first* in the chain, rewrite RIP/EIP in the
// faulting thread's CONTEXT to point at a small Go callback, and return
// EXCEPTION_CONTINUE_EXECUTION. The callback panics, and the panic is then
// recovered by the normal defer/recover in RunWindowsCOFFViaDLL.
//
// This is intentionally cgo-free and does not rely on the OS being able to
// unwind through the BOF's dynamically allocated code (which has no .pdata).
// ---------------------------------------------------------------------------

var (
	vehOnce      sync.Once
	vehHandle    uintptr
	recoveryFunc uintptr

	// vehMu serialises guarded executions and protects vehProtected. Holding
	// the mutex for the whole call guarantees the VEH handler never misses an
	// exception due to a stale vehProtected read on a different OS thread.
	vehMu        sync.Mutex
	vehProtected bool

	// Written by the VEH handler, read by vehRecoveryStub when it panics.
	lastExcCode uint32
	lastExcAddr uintptr
)

// winExceptionPointers mirrors the EXCEPTION_POINTERS the OS passes to a VEH
// handler. We only need the exception code/address and the CONTEXT pointer.
type winExceptionPointers struct {
	ExceptionRecord *winExceptionRecord
	ContextRecord   uintptr // really *CONTEXT
}

type winExceptionRecord struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

// initVEH registers a single Vectored Exception Handler (first-in-chain) on
// first use. The handler stays registered for the process lifetime.
func initVEH() {
	vehOnce.Do(func() {
		recoveryFunc = windows.NewCallback(vehRecoveryStub)
		handler := windows.NewCallback(vehExceptionHandler)
		vehHandle, _, _ = kernel32AddVectoredExceptionHandler.Call(1, handler)
	})
}

// vehRecoveryStub is the target the VEH handler writes into RIP/EIP. It simply
// panics with the saved exception info; the caller's defer/recover turns that
// into a normal Go error.
func vehRecoveryStub() uintptr {
	panic(fmt.Sprintf(
		"COFF/BOF native exception 0x%08X at address 0x%X",
		lastExcCode, lastExcAddr,
	))
}

// vehExceptionHandler is the VEH callback. When a guarded call is in flight
// and a fatal (code & 0x80000000) exception fires, it saves the details,
// clears the protection flag to avoid re-entrancy, rewrites RIP/EIP in the
// CONTEXT to vehRecoveryStub, and asks the OS to resume execution there.
func vehExceptionHandler(exceptionPointers uintptr) uintptr {
	if exceptionPointers == 0 || !vehProtected {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	ep := (*winExceptionPointers)(unsafe.Pointer(exceptionPointers))
	if ep == nil || ep.ExceptionRecord == nil || ep.ContextRecord == 0 {
		return 0
	}

	code := ep.ExceptionRecord.ExceptionCode
	if code&0x80000000 == 0 {
		return 0 // not a fatal exception, let someone else handle it
	}

	lastExcCode = code
	lastExcAddr = ep.ExceptionRecord.ExceptionAddress
	vehProtected = false // prevent re-entrancy

	// Rewrite the instruction pointer in the CONTEXT.
	// amd64 CONTEXT: RIP at offset 0xF8 (248)
	// x86   CONTEXT: EIP at offset 0xB4 (180)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xF8)) = recoveryFunc
	} else {
		*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xB4)) = recoveryFunc
	}

	return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
}

// guardedCallLoadAndRun calls the COFFLoader LoadAndRun export under the VEH
// crash gate. It locks the calling goroutine to an OS thread for the duration
// of the call; if the DLL or BOF raises a native exception, the VEH handler
// redirects execution to vehRecoveryStub which panics, and the panic unwinds
// through this frame into RunWindowsCOFFViaDLL's recover.
func guardedCallLoadAndRun(loadAndRun uintptr, buf []byte, callback uintptr) uintptr {
	initVEH()
	runtime.LockOSThread()
	vehMu.Lock()
	vehProtected = true

	defer func() {
		vehProtected = false
		vehMu.Unlock()
		runtime.UnlockOSThread()
	}()

	return callLoadAndRun(loadAndRun, buf, callback)
}

var kernel32AddVectoredExceptionHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("AddVectoredExceptionHandler")
