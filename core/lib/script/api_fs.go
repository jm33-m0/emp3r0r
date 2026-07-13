package script

import (
	"fmt"
	"os"
	"os/exec"

	"go.starlark.net/starlark"
)

func starlarkReadFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	content, err := os.ReadFile(path)
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
	err := os.WriteFile(path, []byte(content), 0o644)
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
	entries, err := os.ReadDir(path)
	if err != nil {
		return starlark.None, fmt.Errorf("list_dir %s: %w", path, err)
	}
	list := starlark.NewList(nil)
	for _, entry := range entries {
		list.Append(starlark.String(entry.Name()))
	}
	return list, nil
}

func starlarkExists(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	_, err := os.Stat(path)
	return starlark.Bool(err == nil), nil
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
	err := os.RemoveAll(path)
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
	c := exec.Command(command, goArgs...)
	out, err := c.CombinedOutput()
	if err != nil {
		return starlark.String(string(out)), fmt.Errorf("exec_cmd %s: %w (output: %s)", command, err, string(out))
	}
	return starlark.String(string(out)), nil
}
