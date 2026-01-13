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

func TestParseCOFFArgs(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"args=zhello i42 bdeadbeef",
		"IGNORED=value",
	}

	args, err := ParseCOFFArgs(env)
	if err != nil {
		t.Fatalf("ParseCOFFArgs returned error: %v", err)
	}

	want := []string{"zhello", "i42", "bdeadbeef"}
	if len(args) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %s want %s", i, args[i], want[i])
		}
	}
}

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
	if !strings.HasPrefix(val, "z") {
		t.Fatalf("expected wstring prefix 'z', got %q", val)
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

func TestRunWindowsCOFFWithRealBOF(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	// Non-privileged BOF to avoid admin requirement
	const url = "https://github.com/praetorian-inc/goffloader/raw/refs/heads/main/cmd/bof_example/whoami.x64.o"
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
