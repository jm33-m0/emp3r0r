package modules

import (
	"fmt"
	"strings"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// BuildLocalModule builds one C2-local module with the given flag values and
// returns its build log. Local modules do not produce an agent job; the
// artifact stays on the host running the module runner.
func BuildLocalModule(moduleName string, flags map[string]string) (string, error) {
	moduleName = strings.TrimSpace(moduleName)
	mod, ok := def.GetModule(moduleName)
	if !ok || mod == nil {
		return "", fmt.Errorf("module %q is not installed", moduleName)
	}
	if !mod.IsLocal {
		return "", fmt.Errorf("module %q is not a local C2 module", moduleName)
	}
	if mod.Build == "" {
		return "", fmt.Errorf("module %q has no build step", moduleName)
	}
	for name, value := range flags {
		opt, ok := mod.Options[name]
		if !ok || opt == nil {
			return "", fmt.Errorf("unknown option --%s for %s", name, moduleName)
		}
		if opt.Internal {
			return "", fmt.Errorf("--%s is filled in by the C2", name)
		}
		if err := modconfig.ValidateOption(opt, value); err != nil {
			return "", err
		}
	}

	dispatchMu.Lock()
	defer dispatchMu.Unlock()
	out, err := build_module(mod, flags)
	if err != nil {
		return string(out), err
	}
	logGeneratedPayloads(out)
	return string(out), nil
}

// DispatchModule dispatches one custom payload module on target with the given
// flag values and returns the job carrying its output. Only payload modules
// that return a job result are accepted: built-in Go modules, local C2 modules
// and shared-library dependencies are rejected.
//
// The console module command and the MCP run_module tool both use it.
//
// The caller is responsible for the target: the server enforces the operator
// lock when the command reaches it.
func DispatchModule(target *def.Emp3r0rAgent, moduleName string, flags map[string]string) (string, error) {
	moduleName = strings.TrimSpace(moduleName)
	mod, ok := def.GetModule(moduleName)
	if !ok || mod == nil {
		return "", fmt.Errorf("module %q is not installed", moduleName)
	}
	if target == nil {
		return "", fmt.Errorf("no active target")
	}
	if mod.IsLocal {
		return "", fmt.Errorf("module %q runs on the C2 and has no target output", moduleName)
	}
	switch strings.ToLower(strings.TrimSpace(mod.AgentConfig.Type)) {
	case "coff", "starlark", "dll":
	default:
		return "", fmt.Errorf("module %q is not a runnable payload module", moduleName)
	}

	for name, value := range flags {
		opt, ok := mod.Options[name]
		if !ok || opt == nil {
			return "", fmt.Errorf("unknown option --%s for %s", name, moduleName)
		}
		if opt.Internal {
			return "", fmt.Errorf("--%s is filled in by the C2", name)
		}
		if err := modconfig.ValidateOption(opt, value); err != nil {
			return "", err
		}
	}
	for name, opt := range mod.Options {
		if opt == nil || opt.Internal || !opt.Required {
			continue
		}
		value, ok := flags[name]
		if !ok {
			value = opt.Val
		}
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("required option --%s is missing", name)
		}
	}

	dispatchMu.Lock()
	defer dispatchMu.Unlock()

	prev := live.ActiveModule
	SetActiveModule(moduleName)
	defer func() { live.ActiveModule = prev }()
	if live.ActiveModule == nil || !strings.EqualFold(live.ActiveModule.Name, moduleName) {
		return "", fmt.Errorf("module %q is not available", moduleName)
	}

	job := jobs.CreateJob(moduleName, moduleName, target.Tag)
	if job == nil {
		return "", fmt.Errorf("cannot create a job for %s", util.AgentRef(target.UUID))
	}
	ctx := &c2context.C2Context{Target: target, Flags: flags}
	jobID := moduleCustomWithJobID(ctx, job.ID)
	if jobID != job.ID {
		return "", fmt.Errorf("dispatching %s", moduleName)
	}
	return job.ID, nil
}
