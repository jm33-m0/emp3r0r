//go:build windows
// +build windows

package agent

import (
	"fmt"
	"os/exec"
)

// RunPSScript runs powershell script on windows
func RunPSScript(scriptBytes []byte) (output string, err error) {
	shell := "powershell.exe"

	cmd := exec.Command(shell, "-Command", "-")

	return feedScriptToStdin(cmd, scriptBytes)
}

// RunBatchScript runs batch script on windows
func RunBatchScript(scriptBytes []byte) (output string, err error) {
	shell := "cmd.exe"

	cmd := exec.Command(shell)

	return feedScriptToStdin(cmd, scriptBytes)
}

func RunExe(scriptBytes []byte) (output string, err error) {
	err = fmt.Errorf("Not implemented")
	return
}
