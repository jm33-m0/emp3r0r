package agent

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
)

func feedScriptToStdin(cmd *exec.Cmd, scriptBytes []byte) (output string, err error) {
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	shell := cmd.Args

	stdin, err := cmd.StdinPipe()
	if err != nil {
		err = fmt.Errorf("Error creating StdinPipe for Cmd %s: %s\n", shell, err)
		return
	}
	if err = cmd.Start(); err != nil {
		err = fmt.Errorf("Error starting Cmd %s: %s\n", shell, err)
		return
	}
	go func() {
		io.Copy(stdin, bytes.NewReader(scriptBytes))
		stdin.Close()
	}()
	if err = cmd.Wait(); err != nil {
		err = fmt.Errorf("Error waiting for Cmd %s: %s\n", shell, err)
		return
	}

	defer func() {
		stdoutBytes := stdoutBuf.Bytes()
		stderrBytes := stderrBuf.Bytes()
		output = string(stdoutBytes) + string(stderrBytes)
		if len(stderrBytes) > 0 {
			err = fmt.Errorf("Error output from Cmd %s: %s\n", shell, stderrBytes)
			return
		}
	}()
	return
}
