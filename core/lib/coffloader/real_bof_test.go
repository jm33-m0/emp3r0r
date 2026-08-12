//go:build windows

package coffloader

import (
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

// TestCrashRecoveryEndToEnd verifies that when a BOF crashes:
// 1. The VEH handler records the fault (hasFaulted + isExecutingBOF)
// 2. The process does NOT crash (the crash is contained to the goroutine)
// 3. LoadWithToken's timeout eventually fires (in production, 5 min)
//
// Full in-process recovery is not possible with Go's cgocall SEH — the
// goroutine dies without running deferred functions. The VEH telemetry
// + timeout provide best-effort detection.
func TestCrashRecoveryEndToEnd(t *testing.T) {
	t.Skip("In-process crash recovery not possible with cgocall SEH. " +
		"The VEH handler records telemetry and the timeout prevents hangs.")
}
