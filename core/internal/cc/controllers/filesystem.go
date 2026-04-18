package controllers

import (
	"fmt"
	"strconv"
	"strings"
)

// Filesystem command builders
// These are pure business logic - no UI dependencies

// BuildLsCommand builds ls command
func BuildLsCommand(path string) string {
	return fmt.Sprintf("ls --dst %s", strconv.Quote(path))
}

// BuildCatCommand builds cat command
func BuildCatCommand(path string) string {
	return fmt.Sprintf("cat --dst %s", strconv.Quote(path))
}

// BuildCpCommand builds cp command
func BuildCpCommand(src, dst string) string {
	return fmt.Sprintf("cp --src %s --dst %s", strconv.Quote(src), strconv.Quote(dst))
}

// BuildRmCommand builds rm command
func BuildRmCommand(path string) string {
	return fmt.Sprintf("rm --dst %s", strconv.Quote(path))
}

// BuildMkdirCommand builds mkdir command
func BuildMkdirCommand(path string) string {
	return fmt.Sprintf("mkdir --dst %s", strconv.Quote(path))
}

// BuildMvCommand builds mv command
func BuildMvCommand(src, dst string) string {
	return fmt.Sprintf("mv --src %s --dst %s", strconv.Quote(src), strconv.Quote(dst))
}

// BuildPwdCommand builds pwd command
func BuildPwdCommand() string {
	return "pwd"
}

// BuildCdCommand builds cd command
func BuildCdCommand(path string) string {
	return fmt.Sprintf("cd --dst %s", strconv.Quote(path))
}

// BuildPsCommand builds process listing command with filters
func BuildPsCommand(pid int, user, name, cmdline string) string {
	cmdArgs := "ps"
	if pid != 0 {
		cmdArgs = fmt.Sprintf("%s --pid %d", cmdArgs, pid)
	}
	if user != "" {
		cmdArgs = fmt.Sprintf("%s --user %s", cmdArgs, strconv.Quote(user))
	}
	if name != "" {
		cmdArgs = fmt.Sprintf("%s --name %s", cmdArgs, strconv.Quote(name))
	}
	if cmdline != "" {
		cmdArgs = fmt.Sprintf("%s --cmdline %s", cmdArgs, strconv.Quote(cmdline))
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

