//go:build windows

package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestCOFFExecutionWindows(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	t.Run("process_list_handles", func(t *testing.T) {
		payloadPath := filepath.Join(getModulesRoot(), "process_list_handles/ProcessListHandles.x64.o")
		if !util.IsExist(payloadPath) {
			t.Skipf("payload %s not found", payloadPath)
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("failed to read payload: %v", err)
		}

		args := []coffloader.CoffArg{
			{WireType: "i", Value: 4}, // System process PID
		}

		output, err := coffloader.RunWindowsCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunWindowsCOFF failed: %v", err)
		}

		if output == "" {
			t.Errorf("Output was empty")
		}
	})

	t.Run("sa_dir", func(t *testing.T) {
		payloadPath := filepath.Join(getModulesRoot(), "SA/dir/dir.x64.o")
		if !util.IsExist(payloadPath) {
			t.Skipf("payload %s not found", payloadPath)
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("failed to read payload: %v", err)
		}

		args := []coffloader.CoffArg{
			{WireType: "z", Value: "C:\\"},
			{WireType: "s", Value: 0},
		}

		output, err := coffloader.RunWindowsCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunWindowsCOFF failed: %v", err)
		}

		if output == "" {
			t.Errorf("Output was empty")
		}
	})
}
