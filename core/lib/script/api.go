package script

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// StarlarkAPI defines a Go function signature exposed to Starlark.
type StarlarkAPI func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)

// Global registry for Starlark APIs
var apis = make(map[string]StarlarkAPI)

// RegisterAPI registers a Go function under the given name to be callable from Starlark scripts.
func RegisterAPI(name string, api StarlarkAPI) {
	apis[name] = api
}

// getAPIs returns the mapping of registered Go functions exposed to Starlark
func getAPIs() starlark.StringDict {
	dict := make(starlark.StringDict)
	for name, fn := range apis {
		dict[name] = starlark.NewBuiltin(name, fn)
	}
	return dict
}

var builtInAPIs = map[string]StarlarkAPI{
	"read_file":      starlarkReadFile,
	"write_file":     starlarkWriteFile,
	"list_dir":       starlarkListDir,
	"exists":         starlarkExists,
	"mkdir":          starlarkMkdir,
	"remove":         starlarkRemove,
	"http_get":       starlarkHTTPGet,
	"http_post":      starlarkHTTPPost,
	"exec_cmd":       starlarkExecCmd,
	"list_processes": starlarkListProcesses,
}

func init() {
	for name, fn := range builtInAPIs {
		RegisterAPI(name, fn)
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

func starlarkListProcesses(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
		return starlark.None, err
	}
	procs, err := listProcesses()
	if err != nil {
		return starlark.None, fmt.Errorf("list_processes: %w", err)
	}

	starList := starlark.NewList(nil)
	for _, p := range procs {
		starDict := starlark.NewDict(4)
		starDict.SetKey(starlark.String("pid"), starlark.MakeInt(p["pid"].(int)))
		starDict.SetKey(starlark.String("ppid"), starlark.MakeInt(p["ppid"].(int)))
		starDict.SetKey(starlark.String("name"), starlark.String(p["name"].(string)))
		starDict.SetKey(starlark.String("cmdline"), starlark.String(p["cmdline"].(string)))
		starList.Append(starDict)
	}
	return starList, nil
}

func listProcesses() ([]map[string]any, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("process listing is only supported on linux")
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []map[string]any
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		// Read Name and PPID from /proc/<pid>/stat
		statBytes, err := os.ReadFile(filepath.Join("/proc", f.Name(), "stat"))
		if err != nil {
			continue
		}
		statStr := string(statBytes)
		openParen := strings.Index(statStr, "(")
		closeParen := strings.LastIndex(statStr, ")")
		if openParen == -1 || closeParen == -1 || closeParen <= openParen {
			continue
		}
		name := statStr[openParen+1 : closeParen]
		afterParen := strings.TrimSpace(statStr[closeParen+1:])
		fields := strings.Fields(afterParen)
		if len(fields) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])

		// Read cmdline
		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", f.Name(), "cmdline"))
		cmdline := ""
		if err == nil {
			cmdline = strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
			cmdline = strings.TrimSpace(cmdline)
		}
		if cmdline == "" {
			cmdline = "[" + name + "]"
		}

		procs = append(procs, map[string]any{
			"pid":     pid,
			"ppid":    ppid,
			"name":    name,
			"cmdline": cmdline,
		})
	}
	return procs, nil
}
