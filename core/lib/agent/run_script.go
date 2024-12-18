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
		err = fmt.Errorf("error creating StdinPipe for Cmd %s: %s", shell, err)
		return
	}

	collect_output := func() error {
		stdoutBytes := stdoutBuf.Bytes()
		stderrBytes := stderrBuf.Bytes()
		var outputError error
		output = string(stdoutBytes) + string(stderrBytes)
		if len(stderrBytes) > 0 {
			outputError = fmt.Errorf("error output from Cmd %s: %s", shell, stderrBytes)
		}

		return outputError
	}
	defer collect_output()

	if err = cmd.Start(); err != nil {
		err = fmt.Errorf("error starting Cmd %s: %s: %v", shell, err, collect_output())
		return
	}

	go func() {
		io.Copy(stdin, bytes.NewReader(scriptBytes))
		defer stdin.Close()
	}()
	if err = cmd.Wait(); err != nil {
		err = fmt.Errorf("error waiting for Cmd %s: %s: %v", shell, err, collect_output())
		return
	}

	return
}
