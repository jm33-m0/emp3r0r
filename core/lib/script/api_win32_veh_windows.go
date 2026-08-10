//go:build windows

package script

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// VEH-based crash protection for win_call / sys_call
//
// The BOF loader taught us the right pattern: register a Vectored Exception
// Handler that catches *every* native exception (0xC0000005, etc.) during a
// guarded call, rewrite RIP in the CONTEXT to point to a tiny Go callback
// that panics, and let Go's defer/recover machinery handle the rest.
//
// This is strictly superior to debug.SetPanicOnFault, which only converts
// faults inside Go-managed memory.
// ---------------------------------------------------------------------------

var (
	vehOnce      sync.Once
	vehHandle    uintptr
	recoveryFunc uintptr

	// Protected by vehMu; set to true only while a guarded call is in flight
	// on this OS thread.
	vehMu       sync.Mutex
	isProtected bool
	lastExcCode uint32
	lastExcAddr uintptr
)

// exceptionPointers mirrors what the OS passes to a VEH handler.
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

// initVEH registers a single Vectored Exception Handler (first-in-chain)
// on first use. The handler stays registered for the process lifetime.
func initVEH() {
	vehOnce.Do(func() {
		recoveryFunc = windows.NewCallback(vehRecoveryStub)
		handler := windows.NewCallback(vehExceptionHandler)
		vehHandle, _, _ = kernel32AddVectoredExceptionHandler.Call(1, handler)
	})
}

// vehRecoveryStub is the target the VEH handler writes into RIP.
// It simply panics with the saved exception info.
func vehRecoveryStub() uintptr {
	panic(fmt.Sprintf(
		"win_call: native exception 0x%08X at address 0x%X",
		lastExcCode, lastExcAddr,
	))
}

// vehExceptionHandler is the VEH callback.
//
// When isProtected is true and a "fatal" exception (code >= 0x80000000)
// fires, we save the exception details, clear the protection flag so the
// handler doesn't loop, rewrite RIP/EIP in the CONTEXT to vehRecoveryStub,
// and tell the OS to resume execution (= our stub will run and panic).
func vehExceptionHandler(exceptionPointers uintptr) uintptr {
	if exceptionPointers == 0 || !isProtected {
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

	// Save for the recovery stub.
	lastExcCode = code
	lastExcAddr = ep.ExceptionRecord.ExceptionAddress
	isProtected = false // prevent re-entrancy

	// Rewrite the instruction pointer in the CONTEXT.
	// AMD64 CONTEXT: RIP is at offset 0xF8 (248)
	// x86   CONTEXT: EIP is at offset 0xB4 (180)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xF8)) = recoveryFunc
	} else {
		*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xB4)) = recoveryFunc
	}

	return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
}

// enterProtectedGate must be called on the OS thread that is about to
// execute a dangerous Win32 call.  It returns a function that MUST be
// deferred to leave the gate.
//
// The mutex is held for the entire call — this serialises concurrent
// win_call invocations but guarantees the VEH handler will never miss
// an exception due to a stale isProtected read on a different thread.
func enterProtectedGate() (leave func()) {
	initVEH()
	runtime.LockOSThread()
	vehMu.Lock()
	isProtected = true

	return func() {
		isProtected = false
		vehMu.Unlock()
		runtime.UnlockOSThread()
	}
}

// callProcSafeVEH is the VEH-guarded implementation.  It locks the calling
// goroutine to an OS thread, activates the VEH gate, calls the Win32
// function through proc.Call(), and leaves the gate.
//
// If the DLL function raises a native exception the VEH handler rewrites
// RIP to vehRecoveryStub which panics.  The panic propagates through the
// defer stack: first the leave() gate, then the defer/recover in
// starlarkWinCall (or the caller), which converts it to a safe error dict.
func callProcSafeVEH(proc *windows.LazyProc, args ...uintptr) (r1, r2 uintptr, err error) {
	leave := enterProtectedGate()
	defer leave()

	// The actual call — if this crashes, VEH + recover() catches it.
	r1, r2, err = proc.Call(args...)
	return
}

func init() {
	callProcProtected = callProcSafeVEH
}

// Lazy references to kernel32 for VEH.
var kernel32AddVectoredExceptionHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("AddVectoredExceptionHandler")
