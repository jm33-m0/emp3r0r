package script

import (
	"go.starlark.net/starlark"
)

func init() {
	RegisterAPI("notify", starlarkNotify)
}

// starlarkNotify streams a message to the operator immediately instead of
// buffering it until the script returns. The module handler injects the sender
// through WithNotifier; when none is wired (standalone tools and tests) the
// message is dropped. This is what lets a long-lived background operation
// (e.g. an eBPF uprobe capture) report events as they happen.
func starlarkNotify(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "message", &msg); err != nil {
		return starlark.None, err
	}
	if notify := notifierFromThread(thread); notify != nil {
		notify(msg)
	}
	return starlark.None, nil
}

// notifierFromThread returns the run's streaming sender, or nil when the run
// has none.
func notifierFromThread(thread *starlark.Thread) func(string) {
	if thread == nil {
		return nil
	}
	fn, _ := thread.Local("notify").(func(string))
	return fn
}
