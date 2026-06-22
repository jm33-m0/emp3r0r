package script

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"go.starlark.net/starlark"
)

// getAPIs returns the mapping of Go functions exposed to Starlark
func getAPIs() starlark.StringDict {
	return starlark.StringDict{
		"read_file":  starlark.NewBuiltin("read_file", starlarkReadFile),
		"write_file": starlark.NewBuiltin("write_file", starlarkWriteFile),
		"list_dir":   starlark.NewBuiltin("list_dir", starlarkListDir),
		"exists":     starlark.NewBuiltin("exists", starlarkExists),
		"mkdir":      starlark.NewBuiltin("mkdir", starlarkMkdir),
		"remove":     starlark.NewBuiltin("remove", starlarkRemove),
		"http_get":   starlark.NewBuiltin("http_get", starlarkHTTPGet),
		"http_post":  starlark.NewBuiltin("http_post", starlarkHTTPPost),
		"exec_cmd":   starlark.NewBuiltin("exec_cmd", starlarkExecCmd),
	}
}

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
	err := os.WriteFile(path, []byte(content), 0644)
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
	err := os.MkdirAll(path, 0755)
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

func starlarkHTTPGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "url", &url); err != nil {
		return starlark.None, err
	}
	resp, err := http.Get(url)
	if err != nil {
		return starlark.None, fmt.Errorf("http_get %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return starlark.None, fmt.Errorf("http_get %s: reading body: %w", url, err)
	}
	return starlark.String(body), nil
}

func starlarkHTTPPost(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var contentType string
	var bodyData string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "url", &url, "content_type", &contentType, "body", &bodyData); err != nil {
		return starlark.None, err
	}
	resp, err := http.Post(url, contentType, strings.NewReader(bodyData))
	if err != nil {
		return starlark.None, fmt.Errorf("http_post %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return starlark.None, fmt.Errorf("http_post %s: reading body: %w", url, err)
	}
	return starlark.String(body), nil
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
