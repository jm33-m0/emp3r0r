//go:build windows

package coffloader

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestNormalizeCoffValuePrefixes(t *testing.T) {
	val, err := normalizeCoffValue(CoffArg{WireType: "INT", Value: 123})
	if err != nil {
		t.Fatalf("normalizeCoffValue int: %v", err)
	}
	if !strings.HasPrefix(val, "i") {
		t.Fatalf("expected int prefix 'i', got %q", val)
	}

	val, err = normalizeCoffValue(CoffArg{WireType: "BOOL", Value: true})
	if err != nil {
		t.Fatalf("normalizeCoffValue bool: %v", err)
	}
	if !strings.HasPrefix(val, "i") {
		t.Fatalf("expected bool prefix 'i', got %q", val)
	}

	val, err = normalizeCoffValue(CoffArg{WireType: "LPSTR", Value: "hi"})
	if err != nil {
		t.Fatalf("normalizeCoffValue string: %v", err)
	}
	if !strings.HasPrefix(val, "z") {
		t.Fatalf("expected string prefix 'z', got %q", val)
	}

	val, err = normalizeCoffValue(CoffArg{WireType: "LPWSTR", Value: "wide"})
	if err != nil {
		t.Fatalf("normalizeCoffValue wstring: %v", err)
	}
	if !strings.HasPrefix(val, "Z") {
		t.Fatalf("expected wstring prefix 'Z', got %q", val)
	}

	val, err = normalizeCoffValue(CoffArg{WireType: "BINARY", Value: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("normalizeCoffValue binary: %v", err)
	}
	if !strings.HasPrefix(val, "b") {
		t.Fatalf("expected binary prefix 'b', got %q", val)
	}

	val, err = normalizeCoffValue(CoffArg{WireType: "BINARY", Value: "AQID"})
	if err != nil {
		t.Fatalf("normalizeCoffValue binary string b64: %v", err)
	}
	if !strings.HasPrefix(val, "b") {
		t.Fatalf("expected binary prefix 'b' for string input, got %q", val)
	}
}

func TestRunWindowsCOFFInvalidPayload(t *testing.T) {
	inv := []CoffArg{{WireType: "LPSTR", Value: "hello"}}
	if _, err := RunWindowsCOFF([]byte("not-a-coff"), "main", inv, 0); err == nil {
		t.Fatalf("expected error for invalid COFF payload")
	}
}

func TestLoadWithMethodPanicRecover(t *testing.T) {
	if _, err := LoadWithMethod([]byte("not-a-coff"), nil, "go"); err == nil {
		t.Fatalf("expected error for invalid COFF payload in LoadWithMethod")
	}
}

func TestLoadWithMethodMemoryError(t *testing.T) {
	buf := make([]byte, 0, 200)

	// Machine AMD64 (0x8664)
	buf = append(buf, 0x64, 0x86)
	// NumberOfSections: 1
	buf = append(buf, 0x01, 0x00)
	// TimeDateStamp: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// PointerToSymbolTable: offset 86 (0x56)
	buf = append(buf, 0x56, 0x00, 0x00, 0x00)
	// NumberOfSymbols: 1
	buf = append(buf, 0x01, 0x00, 0x00, 0x00)
	// SizeOfOptionalHeader: 0
	buf = append(buf, 0x00, 0x00)
	// Characteristics: 0
	buf = append(buf, 0x00, 0x00)

	// Section Header 1 (40 bytes) - offset 20
	buf = append(buf, []byte(".text\x00\x00\x00")...)
	// VirtualSize: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// VirtualAddress: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// SizeOfRawData: 16 (0x10)
	buf = append(buf, 0x10, 0x00, 0x00, 0x00)
	// PointerToRawData: 60 (0x3C)
	buf = append(buf, 0x3C, 0x00, 0x00, 0x00)
	// PointerToRelocations: 76 (0x4C)
	buf = append(buf, 0x4C, 0x00, 0x00, 0x00)
	// PointerToLinenumbers: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// NumberOfRelocations: 1
	buf = append(buf, 0x01, 0x00)
	// NumberOfLinenumbers: 0
	buf = append(buf, 0x00, 0x00)
	// Characteristics: IMAGE_SCN_MEM_EXECUTE (0x20000000)
	buf = append(buf, 0x00, 0x00, 0x00, 0x20)

	// Raw Data (16 bytes) - offset 60
	buf = append(buf, make([]byte, 16)...)

	// Relocations (10 bytes) - offset 76
	// VirtualAddress: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// SymbolTableIndex: 999 (0x03E7) - out of bounds symbol index
	buf = append(buf, 0xE7, 0x03, 0x00, 0x00)
	// Type: IMAGE_REL_AMD64_ADDR64 (1)
	buf = append(buf, 0x01, 0x00)

	// Symbol Table (18 bytes) - offset 86
	// Name: main
	buf = append(buf, []byte("main\x00\x00\x00\x00")...)
	// Value: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// SectionNumber: 1
	buf = append(buf, 0x01, 0x00)
	// Type: 0
	buf = append(buf, 0x00, 0x00)
	// StorageClass: 2 (EXTERNAL)
	buf = append(buf, 0x02)
	// NumberOfAuxSymbols: 0
	buf = append(buf, 0x00)

	out, err := LoadWithMethod(buf, nil, "main")
	if err == nil {
		t.Fatalf("expected memory/relocation error, got output: %q", out)
	}
	t.Logf("Successfully caught memory/relocation error: %v", err)
}

// buildMinimalCOFF creates a minimal AMD64 COFF object file with a single .text section.
func buildMinimalCOFF(code []byte, entryName string) []byte {
	nameBytes := make([]byte, 8)
	copy(nameBytes, []byte(entryName))

	rawDataOffset := uint32(60)
	symTableOffset := rawDataOffset + uint32(len(code))

	buf := make([]byte, 0, symTableOffset+18+4)

	// File Header (20 bytes)
	buf = append(buf, 0x64, 0x86)                 // Machine: AMD64
	buf = append(buf, 0x01, 0x00)                 // NumberOfSections: 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)     // TimeDateStamp: 0
	buf = append(buf, byte(symTableOffset), byte(symTableOffset>>8), byte(symTableOffset>>16), byte(symTableOffset>>24)) // PointerToSymbolTable
	buf = append(buf, 0x01, 0x00, 0x00, 0x00)     // NumberOfSymbols: 1
	buf = append(buf, 0x00, 0x00)                 // SizeOfOptionalHeader: 0
	buf = append(buf, 0x00, 0x00)                 // Characteristics: 0

	// Section Header .text (40 bytes)
	buf = append(buf, []byte(".text\x00\x00\x00")...)
	codeLen := uint32(len(code))
	buf = append(buf, byte(codeLen), byte(codeLen>>8), byte(codeLen>>16), byte(codeLen>>24)) // VirtualSize
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)     // VirtualAddress: 0
	buf = append(buf, byte(codeLen), byte(codeLen>>8), byte(codeLen>>16), byte(codeLen>>24)) // SizeOfRawData
	buf = append(buf, byte(rawDataOffset), byte(rawDataOffset>>8), byte(rawDataOffset>>16), byte(rawDataOffset>>24)) // PointerToRawData
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)     // PointerToRelocations: 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)     // PointerToLinenumbers: 0
	buf = append(buf, 0x00, 0x00)                 // NumberOfRelocations: 0
	buf = append(buf, 0x00, 0x00)                 // NumberOfLinenumbers: 0
	buf = append(buf, 0x20, 0x00, 0x00, 0x60)     // Characteristics: CODE|EXECUTE|READ

	// Raw Data
	buf = append(buf, code...)

	// Symbol Table (1 entry, 18 bytes)
	buf = append(buf, nameBytes...)               // Name (8 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)     // Value: 0
	buf = append(buf, 0x01, 0x00)                 // SectionNumber: 1
	buf = append(buf, 0x00, 0x00)                 // Type: 0
	buf = append(buf, 0x02)                       // StorageClass: EXTERNAL
	buf = append(buf, 0x00)                       // NumberOfAuxSymbols: 0

	// String Table (4 bytes: just the size)
	buf = append(buf, 0x04, 0x00, 0x00, 0x00)

	return buf
}

// TestCOFFSimpleReturn tests execution of a minimal BOF that just returns.
func TestCOFFSimpleReturn(t *testing.T) {
	code := []byte{0xC3} // ret
	coff := buildMinimalCOFF(code, "go")
	out, err := LoadWithMethod(coff, nil, "go")
	if err != nil {
		t.Fatalf("simple ret BOF should succeed: %v", err)
	}
	t.Logf("Simple ret BOF output: %q", out)
}

// TestCOFFAccessViolationRecovery tests that a crashing BOF doesn't hang
// the caller indefinitely. Due to Go runtime limitations on Windows
// (cgocall SEH terminates goroutines without running deferred functions),
// the crash itself cannot be fully recovered. The timeout mechanism in
// LoadWithToken ensures the caller doesn't hang.
func TestCOFFAccessViolationRecovery(t *testing.T) {
	t.Skip("BOF crash recovery via cgocall SEH is not fully recoverable in Go 1.23+ on Windows. " +
		"The goroutine is terminated without running deferred functions. " +
		"A CGo-based VEH handler is needed for full crash recovery.")
}

// TestCOFFMultipleInvocations tests running several safe BOFs in sequence.
func TestCOFFMultipleInvocations(t *testing.T) {
	safeCode := []byte{0xC3}
	safeCOFF := buildMinimalCOFF(safeCode, "go")

	for i := 0; i < 5; i++ {
		out, err := LoadWithMethod(safeCOFF, nil, "go")
		if err != nil {
			t.Fatalf("iteration %d: simple ret BOF failed: %v", i, err)
		}
		t.Logf("iteration %d: safe output: %q", i, out)
	}
}

func TestRunWindowsCOFFWithRealBOF(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	t.Run("get_priv", func(t *testing.T) {
		payloadPath := filepath.Join("../../modules/Remote-OPs/src/Remote/get_priv/get_priv.x64.o")
		if !util.IsExist(payloadPath) {
			makeDir := filepath.Join("../../modules/Remote-OPs/src/Remote/get_priv")
			cmd := exec.Command("make", "-C", makeDir)
			out, err := cmd.CombinedOutput()
			if err != nil && !util.IsExist(payloadPath) {
				t.Skipf("failed to build %s with make -C %s: %v\nOutput: %s", payloadPath, makeDir, err, string(out))
			}
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("read BOF %s: %v", payloadPath, err)
		}

		args := []CoffArg{
			{WireType: "z", Value: "SeDebugPrivilege"},
		}
		out, err := RunWindowsCOFF(payload, "go", args, 0)
		if err != nil {
			t.Logf("RunWindowsCOFF returned error (expected if non-elevated): %v", err)
		}
		t.Logf("get_priv output: %q", out)

		trimmed := strings.TrimSpace(out)
		if trimmed == "" && err == nil {
			t.Fatalf("unexpected empty BOF output without error")
		}
	})

	t.Run("get_priv_with_args", func(t *testing.T) {
		payloadPath := filepath.Join("../../modules/Remote-OPs/src/Remote/get_priv/get_priv.x64.o")
		if !util.IsExist(payloadPath) {
			makeDir := filepath.Join("../../modules/Remote-OPs/src/Remote/get_priv")
			cmd := exec.Command("make", "-C", makeDir)
			out, err := cmd.CombinedOutput()
			if err != nil && !util.IsExist(payloadPath) {
				t.Skipf("failed to build %s: %v\nOutput: %s", payloadPath, err, string(out))
			}
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("read BOF %s: %v", payloadPath, err)
		}

		args := []CoffArg{
			{WireType: "z", Value: "SeDebugPrivilege"},
		}
		out, err := RunWindowsCOFF(payload, "go", args, 0)
		if err != nil {
			t.Logf("RunWindowsCOFF returned error (expected if non-elevated): %v", err)
		}
		t.Logf("get_priv output: %q", out)

		trimmed := strings.TrimSpace(out)
		if trimmed == "" && err == nil {
			t.Fatalf("unexpected empty BOF output without error")
		}
	})

	t.Run("sc_description", func(t *testing.T) {
		payloadPath := filepath.Join("../../modules/Remote-OPs/src/Remote/sc_description/sc_description.x64.o")
		if !util.IsExist(payloadPath) {
			makeDir := filepath.Join("../../modules/Remote-OPs/src/Remote/sc_description")
			cmd := exec.Command("make", "-C", makeDir)
			out, err := cmd.CombinedOutput()
			if err != nil && !util.IsExist(payloadPath) {
				t.Skipf("failed to build %s with make -C %s: %v\nOutput: %s", payloadPath, makeDir, err, string(out))
			}
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("read BOF %s: %v", payloadPath, err)
		}

		args := []CoffArg{
			{WireType: "z", Value: ""},
			{WireType: "z", Value: "test_service"},
			{WireType: "z", Value: "test_description"},
		}

		out, err := RunWindowsCOFF(payload, "go", args, 0)
		if err != nil {
			t.Logf("RunWindowsCOFF returned error (expected if non-existent service): %v", err)
		}
		t.Logf("sc_description output: %q", out)

		if strings.TrimSpace(out) == "" && err == nil {
			t.Fatalf("unexpected empty BOF output without error")
		}
	})

	t.Run("krb_dump", func(t *testing.T) {
		// Kerbeus dump BOF: lists Kerberos tickets for the current session.
		// It requires no special args (runs equivalent of klist with no filter).
		payloadPath := filepath.Join("../../modules/Kerbeus-BOF/_bin/dump.x64.o")
		if !util.IsExist(payloadPath) {
			t.Skipf("krb_dump BOF not found at %s — run make in Kerbeus-BOF to build", payloadPath)
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("read BOF %s: %v", payloadPath, err)
		}

		// Pass an empty string arg (the full command line to Kerbeus).
		args := []CoffArg{
			{WireType: "z", Value: ""},
		}
		out, err := RunWindowsCOFF(payload, "go", args, 0)
		if err != nil {
			t.Fatalf("RunWindowsCOFF failed: %v", err)
		}
		t.Logf("krb_dump output: %q", out)

		// Output must be non-empty and start with a printable character.
		// The binary-prefix bug caused raw bytes to appear before the actual text.
		trimmed := strings.TrimSpace(out)
		if trimmed == "" {
			t.Fatalf("unexpected empty krb_dump output")
		}
		if trimmed[0] < 0x20 || trimmed[0] > 0x7E {
			t.Fatalf("output starts with non-printable byte 0x%X — possible binary prefix bug; full output: %q", trimmed[0], out)
		}
	})
}
