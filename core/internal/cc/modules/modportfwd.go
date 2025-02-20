package modules

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/def"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/util"
)

func modulePortFwd() {
	switchOpt, ok := def.AvailableModuleOptions["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	switch switchOpt.Val {
	case "off":
		// ugly, i know, it will delete port mappings matching current lport-to combination
		for id, session := range network.PortFwds {
			toOpt, ok := def.AvailableModuleOptions["to"]
			if !ok {
				logging.Errorf("Option 'to' not found")
				return
			}
			listenPortOpt, ok := def.AvailableModuleOptions["listen_port"]
			if !ok {
				logging.Errorf("Option 'listen_port' not found")
				return
			}
			if session.To == toOpt.Val && session.Lport == listenPortOpt.Val {
				session.Cancel()             // cancel the PortFwd session
				delete(network.PortFwds, id) // remove from port mapping list

				// tell the agent to close connection
				// make sure handler returns
				// cmd format: !port_fwd [to/listen] [shID] [operation]
				cmd := fmt.Sprintf("%s --shID %s --operation stop", emp3r0r_def.C2CmdPortFwd, id)
				sendCMDerr := agents.SendCmd(cmd, "", def.ActiveAgent)
				if sendCMDerr != nil {
					logging.Errorf("SendCmd: %v", sendCMDerr)
					return
				}
				return
			}
			logging.Errorf("Could not find port mapping (to %s, listening on %s)",
				toOpt.Val, listenPortOpt.Val)
		}
	case "reverse": // expose a dest from CC to agent
		var pf network.PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = def.AvailableModuleOptions["listen_port"].Val, def.AvailableModuleOptions["to"].Val
		go func() {
			logging.Printf("RunReversedPortFwd: %s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.Lport, pf.To, pf.Protocol)
			initErr := pf.InitReversedPortFwd()
			if initErr != nil {
				logging.Errorf("PortFwd (reverse) failed: %v", initErr)
			}
		}()
	case "on":
		var pf network.PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = def.AvailableModuleOptions["listen_port"].Val, def.AvailableModuleOptions["to"].Val
		pf.Protocol = def.AvailableModuleOptions["protocol"].Val
		go func() {
			logging.Printf("RunPortFwd: %s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.Lport, pf.To, pf.Protocol)
			runErr := pf.RunPortFwd()
			if runErr != nil {
				logging.Errorf("PortFwd failed: %v", runErr)
			}
		}()
	default:
	}
}

func moduleProxy() {
	portOpt, ok := def.AvailableModuleOptions["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	port := portOpt.Val

	statusOpt, ok := def.AvailableModuleOptions["status"]
	if !ok {
		logging.Errorf("Option 'status' not found")
		return
	}
	status := statusOpt.Val

	// port-fwd
	pf := new(network.PortFwdSession)
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, "127.0.0.1:"+def.RuntimeConfig.AgentSocksServerPort
	pf.Description = fmt.Sprintf("Agent Proxy (TCP):\n%s (Local) -> %s (Agent)", pf.Lport, pf.To)
	pf.Protocol = "tcp"
	pf.Timeout = def.RuntimeConfig.AgentSocksTimeout

	// udp port fwd
	pfu := new(network.PortFwdSession)
	pfu.Ctx, pfu.Cancel = context.WithCancel(context.Background())
	pfu.Lport, pfu.To = port, "127.0.0.1:"+def.RuntimeConfig.AgentSocksServerPort
	pfu.Description = fmt.Sprintf("Agent Proxy (UDP):\n%s (Local) -> %s (Agent)", pfu.Lport, pfu.To)
	pfu.Protocol = "udp"
	pfu.Timeout = def.RuntimeConfig.AgentSocksTimeout

	switch status {
	case "on":
		// tell agent to start local socks5 proxy
		cmd_id := uuid.NewString()
		err := agents.SendCmdToCurrentTarget("!proxy --mode on --addr 0.0.0.0:"+def.RuntimeConfig.AgentSocksServerPort, cmd_id)
		if err != nil {
			logging.Errorf("Starting SOCKS4 proxy on target failed: %v", err)
			return
		}
		var ok bool
		for i := 0; i < 120; i++ {
			_, ok = def.CmdResults[cmd_id]
			if ok {
				def.CmdResultsMutex.Lock()
				delete(def.CmdResults, cmd_id)
				def.CmdResultsMutex.Unlock()
				break
			}
			util.TakeABlink()
		}

		if !ok {
			logging.Errorf("Timeout waiting for agent to start SOCKS5 proxy")
			return
		} else {
			logging.Printf("Agent started SOCKS5 proxy")
			// TCP forwarding
			go func() {
				err := pf.RunPortFwd()
				if err != nil {
					logging.Errorf("PortFwd (TCP) failed: %v", err)
				}
			}()
			// UDP forwarding
			go func() {
				for pf.Sh == nil {
					util.TakeABlink()
				}
				err := pfu.RunPortFwd()
				if err != nil {
					logging.Errorf("PortFwd (UDP) failed: %v", err)
				}
			}()
		}
	case "off":
		for id, session := range network.PortFwds {
			if session.Description == pf.Description ||
				session.Description == pfu.Description {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("%s --id %s", emp3r0r_def.C2CmdDeletePortFwd, id)
				err := agents.SendCmd(cmd, "", session.Agent)
				if err != nil {
					logging.Errorf("SendCmd: %v", err)
					return
				}
			}
		}
	default:
		logging.Errorf("Unknown operation '%s'", status)
	}
}
