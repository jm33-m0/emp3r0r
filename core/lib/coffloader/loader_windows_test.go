//go:build windows
// +build windows

package coffloader

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
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
	if _, err := RunWindowsCOFF([]byte("not-a-coff"), "main", inv); err == nil {
		t.Fatalf("expected error for invalid COFF payload")
	}
}

func TestLoadWithMethodPanicRecover(t *testing.T) {
	if _, err := LoadWithMethod([]byte("not-a-coff"), nil, "go"); err == nil {
		t.Fatalf("expected error for invalid COFF payload in LoadWithMethod")
	}
}

func TestLoadWithMethodMemoryError(t *testing.T) {
	// Construct a COFF binary with out-of-bounds relocation symbol index that produces a memory error if unhandled
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

func TestRunWindowsCOFFWithRealBOF(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	// Non-privileged BOF to avoid admin requirement
	const url = "https://github.com/chvancooten/goffloader/raw/refs/heads/main/cmd/bof_example/whoami.x64.o"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("download BOF: %v", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read BOF: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("downloaded empty BOF payload")
	}

	out, err := RunWindowsCOFF(payload, "main", nil)
	if err != nil {
		t.Fatalf("RunWindowsCOFF failed: %v", err)
	}

	if strings.TrimSpace(out) == "" {
		t.Fatalf("unexpected empty BOF output")
	}
}
