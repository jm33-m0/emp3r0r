package modules

import (
	"fmt"
	"strings"
	"sync"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ModExec is the command-execution BOF a C agent runs for `exec`.
const ModExec = "exec"

// execDispatchMu serializes the module selection around a dispatch: the module
// runner reads live.ActiveModule, which the console also owns.
var execDispatchMu sync.Mutex

// CanRunExecBOF reports whether target runs `exec` through the exec BOF. The Go
// agent has command execution built in; the C agent runs the BOF. x86-64 runs
// the native object, every other Linux architecture runs the RV32 guest.
func CanRunExecBOF(target *def.Emp3r0rAgent) bool {
	if target == nil || !strings.EqualFold(target.GOOS, "linux") {
		return false
	}
	return strings.EqualFold(target.AgentImpl, "c")
}

// DispatchExec runs command on target through the exec BOF. It returns the job
// that carries the command's output, so the caller (and tests) can wait for it.
//
// shell selects `/bin/sh -c`; without it the agent splits the command line into
// words and execs the program directly, so no shell process appears.
func DispatchExec(target *def.Emp3r0rAgent, command string, shell bool) (string, error) {
	if !CanRunExecBOF(target) {
		return "", fmt.Errorf("agent %s does not run the exec BOF",
			util.AgentRef(target.UUID))
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("command is empty")
	}
	if _, ok := def.GetModule(ModExec); !ok {
		return "", fmt.Errorf("module %s is not installed", ModExec)
	}

	arch := target.GOArch
	if arch == "" {
		arch = target.Arch
	}
	mode := "exec"
	if shell {
		mode = "shell"
	}
	flags := map[string]string{"cmd": command, "mode": mode}
	if normalizeAgentArch(arch) != "amd64" {
		// A non-x86-64 agent runs the module as an RV32 guest. The C2 builds
		// the guest on first use and reuses it on later dispatches instead of
		// recompiling per command.
		flags["riscv"] = "1"
		flags["skip_rv_build"] = "1"
	}

	execDispatchMu.Lock()
	defer execDispatchMu.Unlock()
	prev := live.ActiveModule
	SetActiveModule(ModExec)
	defer func() { live.ActiveModule = prev }()
	if live.ActiveModule == nil || !strings.EqualFold(live.ActiveModule.Name, ModExec) {
		return "", fmt.Errorf("module %s is not available", ModExec)
	}

	job := jobs.CreateJob(command, "command", target.Tag)
	if job == nil {
		return "", fmt.Errorf("cannot create a job for agent %s",
			util.AgentRef(target.UUID))
	}

	ctx := &c2context.C2Context{Target: target, Flags: flags}
	jobID := moduleCustomWithJobID(ctx, job.ID)
	if jobID != job.ID {
		return "", fmt.Errorf("dispatching %s", ModExec)
	}
	return job.ID, nil
}
