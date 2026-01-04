package modules

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func modulePortFwd() {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("No active agent")
		return
	}
	switchOpt, ok := live.ActiveModule.Options["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	switch switchOpt.Val {
	case "off":
		// ugly, i know, it will delete port mappings matching current lport-to combination
		for id, session := range network.PortFwds {
			toOpt, ok := live.ActiveModule.Options["to"]
			if !ok {
				logging.Errorf("Option 'to' not found")
				return
			}
			listenPortOpt, ok := live.ActiveModule.Options["listen_port"]
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
				cmd := fmt.Sprintf("%s --shID %s --operation stop", def.C2CmdPortFwd, id)
				sendCMDerr := CmdSender(cmd, "", activeAgent.Tag)
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
		pf.Lport, pf.To = live.ActiveModule.Options["listen_port"].Val, live.ActiveModule.Options["to"].Val

		// Get bind address option, default to localhost if not specified
		bindAddrOpt, ok := live.ActiveModule.Options["bind_addr"]
		if ok {
			pf.BindAddr = bindAddrOpt.Val
		} else {
			pf.BindAddr = "127.0.0.1"
		}

		pf.SendCmdFunc = CmdSender
		pf.Agent = activeAgent
		go func() {
			logging.Printf("RunReversedPortFwd: %s:%s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.BindAddr, pf.Lport, pf.To, pf.Protocol)
			initErr := pf.InitReversedPortFwd()
			if initErr != nil {
				logging.Errorf("PortFwd (reverse) failed: %v", initErr)
			}
		}()
	case "on":
		var pf network.PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = live.ActiveModule.Options["listen_port"].Val, live.ActiveModule.Options["to"].Val

		// Get bind address option, default to localhost if not specified
		bindAddrOpt, ok := live.ActiveModule.Options["bind_addr"]
		if ok {
			pf.BindAddr = bindAddrOpt.Val
		} else {
			pf.BindAddr = "127.0.0.1"
		}

		pf.SendCmdFunc = CmdSender
		pf.Protocol = live.ActiveModule.Options["protocol"].Val
		pf.Agent = activeAgent
		go func() {
			logging.Printf("RunPortFwd: %s:%s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.BindAddr, pf.Lport, pf.To, pf.Protocol)
			runErr := pf.RunPortFwd()
			if runErr != nil {
				logging.Errorf("PortFwd failed: %v", runErr)
			}
		}()
	default:
	}
}

func moduleProxy() {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Errorf("No active agent")
		return
	}
	portOpt, ok := live.ActiveModule.Options["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	port := portOpt.Val

	statusOpt, ok := live.ActiveModule.Options["status"]
	if !ok {
		logging.Errorf("Option 'status' not found")
		return
	}
	status := statusOpt.Val

	// Get bind address option, default to localhost if not specified
	bindAddr := "127.0.0.1"
	bindAddrOpt, ok := live.ActiveModule.Options["bind_addr"]
	if ok {
		bindAddr = bindAddrOpt.Val
		if bindAddr == "localhost" {
			bindAddr = "127.0.0.1"
		}
	}

	// port-fwd
	pf := new(network.PortFwdSession)
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, "127.0.0.1:"+live.RuntimeConfig.AgentSocksServerPort
	pf.BindAddr = bindAddr
	pf.SendCmdFunc = CmdSender
	pf.Description = fmt.Sprintf("Agent Proxy (TCP):\n%s:%s (Local) -> %s (Agent)", bindAddr, pf.Lport, pf.To)
	pf.Protocol = "tcp"
	pf.Timeout = live.RuntimeConfig.AgentSocksTimeout
	pf.Agent = activeAgent

	// udp port fwd
	pfu := new(network.PortFwdSession)
	pfu.Ctx, pfu.Cancel = context.WithCancel(context.Background())
	pfu.Lport, pfu.To = port, "127.0.0.1:"+live.RuntimeConfig.AgentSocksServerPort
	pfu.BindAddr = bindAddr
	pfu.Description = fmt.Sprintf("Agent Proxy (UDP):\n%s:%s (Local) -> %s (Agent)", bindAddr, pfu.Lport, pfu.To)
	pfu.Protocol = "udp"
	pfu.Timeout = live.RuntimeConfig.AgentSocksTimeout
	pfu.SendCmdFunc = CmdSender
	pfu.Agent = activeAgent

	switch status {
	case "on":
		// tell agent to start local socks5 proxy
		cmd_id := uuid.NewString()
		err := CmdSender("!proxy --mode on --addr 0.0.0.0:"+live.RuntimeConfig.AgentSocksServerPort, cmd_id, pf.Agent.Tag)
		if err != nil {
			logging.Errorf("Starting SOCKS5 proxy on target failed: %v", err)
			return
		}
		var ok bool
		for i := 0; i < 120; i++ {
			_, ok = live.CmdResults.Load(cmd_id)
			if ok {
				live.CmdResults.Delete(cmd_id)
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
				cmd := fmt.Sprintf("%s --id %s", def.C2CmdDeletePortFwd, id)
				err := CmdSender(cmd, "", session.Agent.Tag)
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
