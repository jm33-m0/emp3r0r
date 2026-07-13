package script

import (
	"fmt"
	"runtime"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"go.starlark.net/starlark"
)

func starlarkListProcesses(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if runtime.GOOS != "linux" {
		return starlark.None, fmt.Errorf("list_processes is only supported on Linux")
	}

	processes := util.ProcessList(0, "", "", "")
	list := starlark.NewList(nil)

	for _, proc := range processes {
		pDict := starlark.NewDict(4)
		pDict.SetKey(starlark.String("pid"), starlark.MakeInt(proc.PID))
		pDict.SetKey(starlark.String("ppid"), starlark.MakeInt(proc.PPID))
		pDict.SetKey(starlark.String("name"), starlark.String(proc.Name))
		pDict.SetKey(starlark.String("cmdline"), starlark.String(proc.Cmdline))

		list.Append(pDict)
	}

	return list, nil
}
