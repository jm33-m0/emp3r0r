//go:build linux

package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestCOFFExecutionLinux(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	t.Run("hello_linux", func(t *testing.T) {
		payloadPath := filepath.Join(getModulesRoot(), "hello_linux/hello_linux.o")
		if !util.IsExist(payloadPath) {
			t.Skipf("payload %s not found", payloadPath)
		}

		payload, err := os.ReadFile(payloadPath)
		if err != nil {
			t.Fatalf("failed to read payload: %v", err)
		}

		args := []coffloader.CoffArg{
			{WireType: "z", Value: "DeepMind"},
		}

		output, err := coffloader.RunLinuxCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunLinuxCOFF failed: %v", err)
		}

		if !strings.Contains(output, "Hello DeepMind!") {
			t.Errorf("Unexpected output: %s", output)
		}
	})
}
