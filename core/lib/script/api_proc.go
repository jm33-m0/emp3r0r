package script

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

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
