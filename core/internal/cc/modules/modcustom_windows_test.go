//go:build windows

package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestCOFFExecutionWindows(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	t.Run("get_priv", func(t *testing.T) {
		payloadPath := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/get_priv/get_priv.x64.o")
		if !util.IsExist(payloadPath) {
			makeDir := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/get_priv")
			cmd := exec.Command("make", "-C", makeDir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("failed to build %s with make -C %s: %v\nOutput: %s", payloadPath, makeDir, err, string(out))
			}
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("failed to read payload %s: %v", payloadPath, err)
		}

		output, err := coffloader.RunWindowsCOFF(payload, "go", nil)
		if err != nil {
			t.Fatalf("RunWindowsCOFF failed: %v", err)
		}

		if output == "" {
			t.Errorf("Output was empty")
		}
	})

	t.Run("sc_description", func(t *testing.T) {
		payloadPath := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/sc_description/sc_description.x64.o")
		if !util.IsExist(payloadPath) {
			makeDir := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/sc_description")
			cmd := exec.Command("make", "-C", makeDir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("failed to build %s with make -C %s: %v\nOutput: %s", payloadPath, makeDir, err, string(out))
			}
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("failed to read payload %s: %v", payloadPath, err)
		}

		args := []coffloader.CoffArg{
			{WireType: "z", Value: ""},
			{WireType: "z", Value: "test_service"},
			{WireType: "z", Value: "test_description"},
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
