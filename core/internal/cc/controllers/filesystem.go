package controllers

import (
	"fmt"
	"strings"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// Filesystem command builders
// These are pure business logic - no UI dependencies

// BuildLsCommand builds ls command
func BuildLsCommand(path string) string {
	return fmt.Sprintf("ls --dst '%s'", path)
}

// BuildCatCommand builds cat command
func BuildCatCommand(path string) string {
	return fmt.Sprintf("cat --dst '%s'", path)
}

// BuildCpCommand builds cp command
func BuildCpCommand(src, dst string) string {
	return fmt.Sprintf("cp --src '%s' --dst '%s'", src, dst)
}

// BuildRmCommand builds rm command
func BuildRmCommand(path string) string {
	return fmt.Sprintf("rm --dst '%s'", path)
}

// BuildMkdirCommand builds mkdir command
func BuildMkdirCommand(path string) string {
	return fmt.Sprintf("mkdir --dst '%s'", path)
}

// BuildMvCommand builds mv command
func BuildMvCommand(src, dst string) string {
	return fmt.Sprintf("mv --src '%s' --dst '%s'", src, dst)
}

// BuildPwdCommand builds pwd command
func BuildPwdCommand() string {
	return "pwd"
}

// BuildCdCommand builds cd command
func BuildCdCommand(path string) string {
	return fmt.Sprintf("cd --dst %s", path)
}

// BuildPsCommand builds process listing command with filters
func BuildPsCommand(pid int, user, name, cmdline string) string {
	cmdArgs := "ps"
	if pid != 0 {
		cmdArgs = fmt.Sprintf("%s --pid %d", cmdArgs, pid)
	}
	if user != "" {
		cmdArgs = fmt.Sprintf("%s --user %s", cmdArgs, user)
	}
	if name != "" {
		cmdArgs = fmt.Sprintf("%s --name %s", cmdArgs, name)
	}
	if cmdline != "" {
		cmdArgs = fmt.Sprintf("%s --cmdline %s", cmdArgs, cmdline)
	}
	return cmdArgs
}

// BuildKillCommand builds kill command for PIDs
// Returns error if any PID is invalid
func BuildKillCommand(pids []int) (string, error) {
	if len(pids) == 0 {
		return "", fmt.Errorf("no PIDs specified")
	}

	// Validate PIDs
	for _, pid := range pids {
		if pid <= 0 {
			return "", fmt.Errorf("invalid PID %d: must be positive", pid)
		}
	}

	// Convert to strings
	pidStrs := make([]string, len(pids))
	for i, pid := range pids {
		pidStrs[i] = fmt.Sprintf("%d", pid)
	}

	return fmt.Sprintf("kill %s", strings.Join(pidStrs, " ")), nil
}

// BuildNetHelperCommand builds net_helper command
func BuildNetHelperCommand() string {
	return "net_helper"
}

// BuildSuicideCommand builds suicide command
func BuildSuicideCommand() string {
	return "suicide"
}

// ExecuteAgentCommand sends a command to an agent
// This is the generic command execution function used by all filesystem commands
func ExecuteAgentCommand(agent *def.Emp3r0rAgent, cmd string, opSession string) error {
	if agent == nil {
		return fmt.Errorf("no agent specified")
	}

	ctx := &c2context.C2Context{
		Target:    agent,
		OpSession: opSession,
		Flags:     make(map[string]string),
	}
	ctx.Flags["cmd_to_exec"] = cmd

	modules.ModuleCmd(ctx)
	return nil
}
