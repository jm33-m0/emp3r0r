package controllers

import (
	"context"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// PortMapping represents a single port forward session
type PortMapping struct {
	ID          string
	LocalPort   string
	RemoteAddr  string
	BindAddr    string
	AgentTag    string
	Description string
	IsReverse   bool
}

// GetActiveForwards returns all active port mappings as a data structure
// (no UI rendering)
func GetActiveForwards() ([]PortMapping, error) {
	mappings := []PortMapping{}

	network.PortFwds.Range(func(id, value interface{}) bool {
		portmap := value.(*network.PortFwdSession)
		// Skip invalid sessions
		if portmap.Sh == nil {
			portmap.Cancel()
			return true // continue iteration
		}

		bindAddr := portmap.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1"
		}

		// Build local and remote addresses
		localPort := bindAddr + ":" + portmap.Lport
		remoteAddr := portmap.To

		// Add context for reverse vs forward
		var description string
		if portmap.Reverse {
			localPort = portmap.Lport + " (Agent)"
			remoteAddr = portmap.To + " (CC)"
			description = fmt.Sprintf("Reverse: %s -> %s", localPort, remoteAddr)
		} else {
			localPort = localPort + " (CC)"
			remoteAddr = remoteAddr + " (Agent)"
			description = fmt.Sprintf("Forward: %s -> %s", localPort, remoteAddr)
		}

		mappings = append(mappings, PortMapping{ // Changed sessions to mappings, def.PortFwdSession to PortMapping
			ID:          id.(string),
			LocalPort:   localPort,
			RemoteAddr:  remoteAddr,
			BindAddr:    bindAddr,
			AgentTag:    portmap.Agent.Tag,
			Description: description,
			IsReverse:   portmap.Reverse, // Changed Reverse to IsReverse
		})
		return true
	})

	return mappings, nil
}

// AddForward creates a new port forward session
func AddForward(ctx *c2context.C2Context) error {
	if ctx.Target == nil {
		return fmt.Errorf("no active agent selected")
	}

	switchOpt, ok := ctx.Flags["switch"]
	if !ok {
		return fmt.Errorf("option 'switch' not found")
	}

	switch switchOpt {
	case "on":
		var pf network.PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = ctx.Flags["listen_port"], ctx.Flags["to"]

		// Get bind address option, default to localhost if not specified
		bindAddrOpt, ok := ctx.Flags["bind_addr"]
		if ok {
			pf.BindAddr = bindAddrOpt
		} else {
			pf.BindAddr = "127.0.0.1"
		}

		pf.SendCmdFunc = modules.CmdSender
		pf.RegisterFunc = modules.RegisterPortFwdFunc
		pf.Protocol = ctx.Flags["protocol"]
		pf.Agent = ctx.Target

		go func() {
			runErr := pf.RunPortFwd()
			if runErr != nil {
				// Log error but don't crash
				_ = runErr
			}
		}()

		return nil

	case "reverse":
		var pf network.PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = ctx.Flags["listen_port"], ctx.Flags["to"]

		// Get bind address option, default to localhost if not specified
		bindAddrOpt, ok := ctx.Flags["bind_addr"]
		if ok {
			pf.BindAddr = bindAddrOpt
		} else {
			pf.BindAddr = "127.0.0.1"
		}

		pf.SendCmdFunc = modules.CmdSender
		pf.RegisterFunc = modules.RegisterPortFwdFunc
		pf.Agent = ctx.Target

		go func() {
			initErr := pf.InitReversedPortFwd()
			if initErr != nil {
				// Log error but don't crash
				_ = initErr
			}
		}()

		return nil

	default:
		return fmt.Errorf("unknown switch option: %s", switchOpt)
	}
}

// RemoveForward stops a port forward session by lport and to combination
func RemoveForward(lport, to string, agentTag string) error {
	found := false

	network.PortFwds.Range(func(id, value any) bool {
		session := value.(*network.PortFwdSession)
		if session.To == to && session.Lport == lport && session.Agent.Tag == agentTag {
			session.Cancel()
			network.PortFwds.Delete(id)
			found = true
			return false // stop iteration
		}
		return true
	})
	if !found {
		return fmt.Errorf("port mapping (to %s, listening on %s) not found for agent %s", to, lport, agentTag)
	}

	return nil
}

// CleanupPortFwdsByAgent stops and removes all port forwarding sessions for a specific agent
func CleanupPortFwdsByAgent(agent *def.Emp3r0rAgent) {
	if agent == nil {
		return
	}

	network.PortFwds.Range(func(id, value any) bool {
		session := value.(*network.PortFwdSession)
		if session.Agent != nil && session.Agent.Tag == agent.Tag {
			session.Cancel()
			network.PortFwds.Delete(id)
		}
		return true
	})
}
