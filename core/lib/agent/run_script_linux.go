//go:build linux
// +build linux

package agent

import (
	"fmt"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RunShellScript runs a bash script on target
func RunShellScript(scriptBytes []byte) (output string, err error) {
	shell := emp3r0r_data.DefaultShell
	if !util.IsFileExist(shell) {
		return "", fmt.Errorf("Shell not found: %s", shell)
	}

	cmd := exec.Command(shell)
	return feedScriptToStdin(cmd, scriptBytes)
}

// RunModuleScript runs a module script on target, default to bash
func RunModuleScript(scriptBytes []byte) (output string, err error) {
	return RunShellScript(scriptBytes)
}
