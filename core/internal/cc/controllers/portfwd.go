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

	for id, portmap := range network.PortFwds {
		// Skip invalid sessions
		if portmap.Sh == nil {
			portmap.Cancel()
			continue
		}

		bindAddr := portmap.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1"
		}

		mapping := PortMapping{
			ID:          id,
			LocalPort:   portmap.Lport,
			RemoteAddr:  portmap.To,
			BindAddr:    bindAddr,
			AgentTag:    portmap.Agent.Tag,
			Description: portmap.Description,
			IsReverse:   portmap.Reverse,
		}

		mappings = append(mappings, mapping)
	}

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

	for id, session := range network.PortFwds {
		if session.To == to && session.Lport == lport && session.Agent.Tag == agentTag {
			session.Cancel() // cancel the PortFwd session
			delete(network.PortFwds, id)

			// Tell the agent to close connection
			cmd := fmt.Sprintf("%s --shID %s --operation stop", def.C2CmdPortFwd, id)
			sendCMDerr := modules.CmdSender(cmd, "", agentTag)
			if sendCMDerr != nil {
				return fmt.Errorf("failed to send stop command to agent: %w", sendCMDerr)
			}

			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("could not find port mapping (to %s, listening on %s)", to, lport)
	}

	return nil
}
