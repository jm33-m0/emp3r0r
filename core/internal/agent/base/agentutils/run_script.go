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

// ExecutePython runs a Python script in memory and returns the output.
func ExecutePython(scriptBytes []byte, argv []string, env []string) (output string, err error) {
	cmd := exec.Command("python")
	if len(argv) > 0 {
		cmd.Args = append(cmd.Args, argv...)
	}
	if len(env) > 0 {
		cmd.Env = env
	}
	return feedScriptToStdin(cmd, scriptBytes)
}

// ExecutePowerShell runs powershell script on windows
func ExecutePowerShell(scriptBytes []byte, argv []string, env []string) (output string, err error) {
	shell := "powershell.exe"

	cmd := exec.Command(shell, append([]string{"-Command", "-"}, argv...)...)
	if len(env) > 0 {
		cmd.Env = env
	}

	return feedScriptToStdin(cmd, scriptBytes)
}

// ExecuteBatch runs batch script on windows
func ExecuteBatch(scriptBytes []byte, argv []string, env []string) (output string, err error) {
	shell := "cmd.exe"

	cmd := exec.Command(shell, argv...)
	if len(env) > 0 {
		cmd.Env = env
	}

	return feedScriptToStdin(cmd, scriptBytes)
}

// ExecuteShell runs a bash script on target
func ExecuteShell(scriptBytes []byte, argv []string, env []string) (output string, err error) {
	shell := def.DefaultShell
	if !util.IsFileExist(shell) {
		return "", fmt.Errorf("shell not found: %s", shell)
	}

	cmd := exec.Command(shell, argv...)
	if len(env) > 0 {
		cmd.Env = env
	}
	return feedScriptToStdin(cmd, scriptBytes)
}
