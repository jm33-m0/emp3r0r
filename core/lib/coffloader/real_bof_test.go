//go:build windows

package coffloader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRealBOFsLoadAndRun loads and executes EVERY .x64.o BOF in the repo.
// The loader must handle BOF crashes gracefully — no BOF crash may kill
// the test process. Crashes are caught by VEH+NtContinue and reported
// as errors via the output channel.
func TestRealBOFsLoadAndRun(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	var bofPaths []string
	filepath.Walk("../../modules", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, ".x64.o") {
			bofPaths = append(bofPaths, path)
		}
		return nil
	})

	if len(bofPaths) == 0 {
		t.Fatal("no .x64.o BOFs found")
	}
	t.Logf("Testing %d BOFs — NONE may crash the process", len(bofPaths))

	passed, crashed, failed := 0, 0, 0

	for _, bofPath := range bofPaths {
		bofName := strings.TrimSuffix(filepath.Base(bofPath), ".x64.o")
		t.Run(bofName, func(t *testing.T) {
			payload, err := os.ReadFile(bofPath)
			if err != nil {
				t.Fatalf("read BOF: %v", err)
			}

			var args []CoffArg
			switch {
			case strings.Contains(bofPath, "Kerbeus-BOF"):
				args = []CoffArg{{WireType: "z", Value: ""}}
			case bofName == "get_priv":
				args = []CoffArg{{WireType: "z", Value: "SeDebugPrivilege"}}
			case bofName == "sc_description":
				args = []CoffArg{
					{WireType: "z", Value: ""},
					{WireType: "z", Value: "test"},
					{WireType: "z", Value: "desc"},
				}
			case bofName == "reg_save":
				args = []CoffArg{
					{WireType: "z", Value: "HKCU"},
					{WireType: "z", Value: "test.reg"},
				}
			default:
				args = []CoffArg{{WireType: "z", Value: ""}}
			}

			out, err := RunWindowsCOFF(payload, "go", args, 0)

			// Check if the BOF crashed (caught by VEH+NtContinue)
			if err != nil {
				if strings.Contains(err.Error(), "BOF native exception") {
					t.Logf("CRASH CAUGHT: %v (output: %q)", err, out)
					crashed++
				} else {
					t.Errorf("UNEXPECTED ERROR: %v (output: %q)", err, out)
					failed++
				}
			} else {
				t.Logf("OK: output=%q", out)
				passed++
			}
		})
	}

	t.Logf("=== RESULTS: %d passed, %d crashed (caught), %d failed ===", passed, crashed, failed)

	if failed > 0 {
		t.Fatalf("%d BOFs had unexpected errors", failed)
	}
	if crashed > 0 {
		// List the crashing BOFs
		t.Logf("NOTE: %d BOF(s) triggered native exceptions — all were caught cleanly", crashed)
	}
}

// TestCrashRecoveryEndToEnd explicitly verifies that a deliberate access
// violation is caught and reported without killing the process.
func TestCrashRecoveryEndToEnd(t *testing.T) {
	// x86-64 code that writes to address 0 → guaranteed access violation
	crashCode := []byte{
		0x48, 0x31, 0xC0,                         // xor rax, rax
		0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, // mov qword [rax], 0
		0xC3,                                     // ret
	}
	coff := buildMinimalCOFF(crashCode, "go")

	out, err := RunWindowsCOFF(coff, "go", nil, 0)
	if err == nil {
		t.Fatal("expected error from crashing BOF, got nil")
	}
	if !strings.Contains(err.Error(), "BOF native exception") && !strings.Contains(err.Error(), "0xC0000005") {
		t.Fatalf("expected crash error, got: err=%v out=%q", err, out)
	}
	t.Logf("Crash recovery works: err=%v out=%q", err, out)

	// Verify we can still run a normal BOF after recovery
	safeCode := []byte{0xC3}
	safeCOFF := buildMinimalCOFF(safeCode, "go")
	out2, err2 := RunWindowsCOFF(safeCOFF, "go", nil, 0)
	if err2 != nil {
		t.Fatalf("safe BOF after crash failed: %v", err2)
	}
	t.Logf("Safe BOF after crash: %q", out2)
	fmt.Println("All crash recovery tests passed!")
}
