package agents

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SendCmd send command to agent
var SendCmd = func(cmd, job_id string, a *def.Emp3r0rAgent) error {
	if a == nil {
		return fmt.Errorf("SendCmd: agent is nil")
	}

	var cmdData def.MsgTunData
	// if cmd_id is empty, generate a new one
	if job_id == "" {
		job_id = uuid.New().String()
	}

	// parse command
	cmdSlice := util.ParseCmd(cmd)
	cmdData.CmdSlice = cmdSlice
	cmdData.Tag = a.Tag
	cmdData.JobID = job_id

	// timestamp
	cmdData.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")

	return SendMessageToAgent(&cmdData, a)
}

// SendCmdToCurrentAgent sends a command to the currently active agent
func SendCmdToCurrentAgent(cmd, job_id string) error {
	target := live.ActiveAgent
	if target == nil {
		return fmt.Errorf("SendCmdToCurrentAgent: no active agent")
	}
	return SendCmd(cmd, job_id, target)
}

// SanitizeAgentData cleans all string fields in Emp3r0rAgent to prevent terminal injection
func SanitizeAgentData(a *def.Emp3r0rAgent) {
	if a == nil {
		return
	}

	// Sanitize string fields
	a.Tag = util.StripANSI(a.Tag)
	a.Name = util.StripANSI(a.Name)
	a.ShortID = util.StripANSI(a.ShortID)
	a.Version = util.StripANSI(a.Version)
	a.Transport = util.StripANSI(a.Transport)
	a.Hostname = util.StripANSI(a.Hostname)
	a.Hardware = util.StripANSI(a.Hardware)
	a.Container = util.StripANSI(a.Container)
	a.Uptime = util.StripANSI(a.Uptime)
	a.Groups = util.StripANSI(a.Groups)
	a.CPU = util.StripANSI(a.CPU)
	a.GPU = util.StripANSI(a.GPU)
	a.Mem = util.StripANSI(a.Mem)
	a.OS = util.StripANSI(a.OS)
	a.GOOS = util.StripANSI(a.GOOS)
	a.Kernel = util.StripANSI(a.Kernel)
	a.Arch = util.StripANSI(a.Arch)
	a.From = util.StripANSI(a.From)
	a.User = util.StripANSI(a.User)
	a.CWD = util.StripANSI(a.CWD)
	a.UUID = util.StripANSI(a.UUID)
	a.UUIDSig = util.StripANSI(a.UUIDSig)
	a.PublicKey = util.StripANSI(a.PublicKey)
	a.C2Host = util.StripANSI(a.C2Host)

	// Sanitize string slices
	for i, ip := range a.IPs {
		a.IPs[i] = util.StripANSI(ip)
	}
	for i, entry := range a.ARP {
		a.ARP[i] = util.StripANSI(entry)
	}
	for i, exe := range a.Exes {
		a.Exes[i] = util.StripANSI(exe)
	}

	// Sanitize AgentProcess
	if a.Process != nil {
		a.Process.Cmdline = util.StripANSI(a.Process.Cmdline)
		a.Process.Parent = util.StripANSI(a.Process.Parent)
	}
}

// MustGetActiveAgent check if current target is set and alive
func MustGetActiveAgent() *def.Emp3r0rAgent {
	// find target
	if live.ActiveAgent == nil {
		logging.Debugf("Validate active target: target does not exist")
		return nil
	}

	// find target in live.AgentList
	for _, agent := range live.AgentList {
		if live.ActiveAgent.Tag == agent.Tag {
			return agent
		}
	}

	return nil
}
