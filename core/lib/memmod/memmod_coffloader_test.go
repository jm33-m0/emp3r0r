//go:build windows && amd64

package memmod_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// ensureSyscallTable initializes the global syscall table used by memmod's
// Nt* wrappers if it has not already been set up.
func ensureSyscallTable(t *testing.T) *ntsyscall.SyscallTable {
	t.Helper()
	if ntsyscall.RuntimeSyscallTable == nil {
		table, err := ntsyscall.InitializeSyscallTable()
		if err != nil {
			t.Fatalf("InitializeSyscallTable failed: %v", err)
		}
		ntsyscall.RuntimeSyscallTable = table
	}
	return ntsyscall.RuntimeSyscallTable
}

// readFileBytes reads a file required by the test. The COFFLoader DLL and BOF
// object files are gitignored build artifacts, so skip instead of failing when
// they are not available in a fresh checkout.
func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("skipping: fixture %s not found: %v", path, err)
	}
	return data
}

// packBlob returns a 4-byte little-endian length followed by data, the
// format expected by BeaconDataExtract.
func packBlob(data []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(data)))
	return append(out, data...)
}

// packCString returns a length-prefixed, NUL-terminated C string.
func packCString(s string) []byte {
	return packBlob(append([]byte(s), 0))
}

// withBOFArgTotalLength prefixes packed BOF arguments with the total length
// field that BeaconDataParse skips.
func withBOFArgTotalLength(packed []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(packed)))
	return append(out, packed...)
}

// bofStringArgs packs a single string argument for a BOF entry point.
func bofStringArgs(s string) []byte {
	return withBOFArgTotalLength(packBlob(append([]byte(s), 0)))
}

// bofIntArgs packs a single 32-bit integer argument for a BOF entry point.
func bofIntArgs(v uint32) []byte {
	arg := make([]byte, 4)
	binary.LittleEndian.PutUint32(arg, v)
	return withBOFArgTotalLength(arg)
}

// loadAndRunBuffer builds the buffer expected by COFFLoader's LoadAndRun:
//
//	[4-byte header] [function name] [coff data] [bof args]
//
// where each component is length-prefixed.
func loadAndRunBuffer(entry string, coff, bofArgs []byte) []byte {
	buf := make([]byte, 4) // skipped by BeaconDataParse
	buf = append(buf, packCString(entry)...)
	buf = append(buf, packBlob(coff)...)
	buf = append(buf, packBlob(bofArgs)...)
	return buf
}

// runBOF calls COFFLoader's LoadAndRun export and returns the BOF output.
func runBOF(t *testing.T, module *memmod.Module, coff []byte, entry string, bofArgs []byte) string {
	t.Helper()

	loadAndRun, err := module.ProcAddressByName("LoadAndRun")
	if err != nil {
		t.Fatalf("ProcAddressByName(LoadAndRun) failed: %v", err)
	}
	if loadAndRun == 0 {
		t.Fatal("LoadAndRun address is 0")
	}

	buf := loadAndRunBuffer(entry, coff, bofArgs)

	var output []byte
	callback := windows.NewCallbackCDecl(func(data uintptr, size int32) uintptr {
		if data != 0 && size > 0 {
			output = append(output, unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))...)
		}
		return 0
	})

	r0, _, _ := syscall.SyscallN(loadAndRun, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), callback)
	if ret := int32(uint32(r0)); ret != 0 {
		t.Fatalf("LoadAndRun returned %d, want 0", ret)
	}

	return string(output)
}

func TestMemmodLoadCOFFLoaderDLL(t *testing.T) {
	ensureSyscallTable(t)

	dllPath := filepath.Join("..", "..", "..", "COFFLoader.x64.dll")
	module, err := memmod.LoadLibrary(readFileBytes(t, dllPath))
	if err != nil {
		t.Fatalf("LoadLibrary(COFFLoader.x64.dll) failed: %v", err)
	}
	defer module.Free()

	tests := []struct {
		name    string
		bofPath string
		entry   string
		args    []byte
	}{
		{
			name:    "get_priv",
			bofPath: filepath.Join("..", "..", "modules", "Remote-OPs", "src", "Remote", "get_priv", "get_priv.x64.o"),
			entry:   "go",
			args:    bofStringArgs("SeShutdownPrivilege"),
		},
		{
			name:    "ProcessListHandles",
			bofPath: filepath.Join("..", "..", "modules", "Remote-OPs", "src", "Remote", "ProcessListHandles", "ProcessListHandles.x64.o"),
			entry:   "go",
			args:    bofIntArgs(windows.GetCurrentProcessId()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coff := readFileBytes(t, tt.bofPath)
			out := runBOF(t, module, coff, tt.entry, tt.args)
			if strings.TrimSpace(out) == "" {
				t.Fatalf("%s BOF produced no output", tt.name)
			}
			t.Logf("%s BOF output:\n%s", tt.name, out)
		})
	}
}
