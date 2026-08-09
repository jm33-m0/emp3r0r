package script

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"go.starlark.net/starlark"
)

// ExecWithToken is an optional hook that, when set on Windows, uses
// CreateProcessWithTokenW so the child process runs under the impersonation
// token instead of the primary process token.
//
// token is the raw HANDLE cast to uintptr; commandLine is the full command
// line (including arguments) to execute.
var ExecWithToken func(token uintptr, commandLine string) error

func starlarkReadFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	content, err := util.ReadFileAgent(path)
	if err != nil {
		return starlark.None, fmt.Errorf("read_file %s: %w", path, err)
	}
	return starlark.String(content), nil
}

func starlarkWriteFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var content string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path, "content", &content); err != nil {
		return starlark.None, err
	}
	err := util.WriteFileAgent(path, []byte(content), 0o644)
	if err != nil {
		return starlark.None, fmt.Errorf("write_file %s: %w", path, err)
	}
	return starlark.None, nil
}

func starlarkListDir(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}

	namesMap := make(map[string]bool)
	list := starlark.NewList(nil)

	// Read disk directory
	if diskEntries, err := os.ReadDir(path); err == nil {
		for _, entry := range diskEntries {
			name := entry.Name()
			if !namesMap[name] {
				namesMap[name] = true
				list.Append(starlark.String(name))
			}
		}
	}

	// Clean target path for memory file comparison
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = filepath.Clean(path)
	}

	// Retrieve all memory file keys directly from the exported MemFileMap map under lock
	util.MemFileLock.RLock()
	var memFiles []string
	for k := range util.MemFileMap {
		memFiles = append(memFiles, k)
	}
	util.MemFileLock.RUnlock()

	// Merge memory files residing in the target directory
	for _, memFile := range memFiles {
		absMemFile, err := filepath.Abs(memFile)
		if err != nil {
			absMemFile = filepath.Clean(memFile)
		}
		if filepath.Dir(absMemFile) == absPath {
			name := filepath.Base(absMemFile)
			if !namesMap[name] {
				namesMap[name] = true
				list.Append(starlark.String(name))
			}
		}
	}

	return list, nil
}

func starlarkExists(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	return starlark.Bool(util.IsExist(path)), nil
}

func starlarkMkdir(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return starlark.None, fmt.Errorf("mkdir %s: %w", path, err)
	}
	return starlark.None, nil
}

func starlarkRemove(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	err := util.RemoveFileAgent(path)
	if err != nil {
		return starlark.None, fmt.Errorf("remove %s: %w", path, err)
	}
	return starlark.None, nil
}

func starlarkExecCmd(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var command string
	var cmdArgs *starlark.List
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "cmd", &command, "args?", &cmdArgs); err != nil {
		return starlark.None, err
	}
	var goArgs []string
	if cmdArgs != nil {
		for i := 0; i < cmdArgs.Len(); i++ {
			v := cmdArgs.Index(i)
			s, ok := starlark.AsString(v)
			if !ok {
				return starlark.None, fmt.Errorf("exec_cmd argument at index %d is not a string", i)
			}
			goArgs = append(goArgs, s)
		}
	}

	// If a token is set (ExecuteAsToken is active), use CreateProcessWithTokenW
	// so the child process runs as the impersonated user.
	if tokenVal := thread.Local("token"); tokenVal != nil {
		if token, ok := tokenVal.(uintptr); ok && token != 0 && ExecWithToken != nil {
			cmdLine := command
			if len(goArgs) > 0 {
				cmdLine += " " + strings.Join(goArgs, " ")
			}
			if err := ExecWithToken(token, cmdLine); err != nil {
				return starlark.None, fmt.Errorf("exec_cmd with token: %w", err)
			}
			return starlark.String("started (token)"), nil
		}
	}

	c := exec.Command(command, goArgs...)
	out, err := c.CombinedOutput()
	if err != nil {
		return starlark.String(string(out)), fmt.Errorf("exec_cmd %s: %w (output: %s)", command, err, string(out))
	}
	return starlark.String(string(out)), nil
}
