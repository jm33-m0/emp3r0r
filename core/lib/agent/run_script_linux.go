//go:build linux
// +build linux

package agent

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RunScript runs a bash script on target
func RunScript(scriptBytes []byte) (output string, err error) {
	shell := "/bin/bash"
	if !util.IsFileExist(shell) {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("Error obtaining stdin for %s: %v", shell, err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting command %s: %v", shell, err)
		return "", err
	}

	if _, err := stdin.Write(scriptBytes); err != nil {
		log.Printf("Error writing script to %s's stdin: %s", shell, err)
		return "", err
	}

	if err := stdin.Close(); err != nil {
		log.Printf("Error closing stdin: %s", err)
		return "", err
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("Error waiting for %s to finish: %s", shell, err)
		return "", err
	}
	stdoutBytes := stdoutBuf.Bytes()
	stderrBytes := stderrBuf.Bytes()
	output = fmt.Sprintf("%s%s", stdoutBytes, stderrBytes)
	return
}
