//go:build windows
// +build windows

package agent

import (
	"fmt"
	"os/exec"
)

// RunScript runs encoded powershell script on windows
func RunScript(script string) (output string, err error) {
	shell := "powershell.exe"

	cmd := exec.Command(shell, "-EncodedCommand", script)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("run script failed: %v, %s", err, outBytes)
	}
	output = string(outBytes)
	return
}
