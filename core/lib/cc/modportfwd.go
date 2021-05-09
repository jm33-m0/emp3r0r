package cc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
)

func modulePortFwd() {
	switch Options["switch"].Val {
	case "off":
		// ugly, i know, it will delete port mappings matching current lport-to combination
		for id, session := range PortFwds {
			if session.To == Options["to"].Val && session.Lport == Options["listen_port"].Val {
				session.Cancel()     // cancel the PortFwd session
				delete(PortFwds, id) // remove from port mapping list

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("!port_fwd %s stop stop", id) // cmd format: !port_fwd [to/listen] [shID] [operation]
				err := SendCmd(cmd, CurrentTarget)
				if err != nil {
					CliPrintError("SendCmd: %v", err)
					return
				}
				return
			}
			CliPrintError("Could not find port mapping (to %s, listening on %s)",
				Options["to"].Val, Options["listen_port"].Val)
		}
	case "reverse": // expose a dest from CC to agent
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = Options["listen_port"].Val, Options["to"].Val
		go func() {
			err := pf.InitReversedPortFwd()
			if err != nil {
				CliPrintError("PortFwd (reverse) failed: %v", err)
			}
		}()
	case "on":
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = Options["listen_port"].Val, Options["to"].Val
		go func() {
			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	default:
	}
}

func moduleProxy() {
	port := Options["port"].Val
	status := Options["status"].Val

	// port-fwd
	var pf PortFwdSession
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, "127.0.0.1:"+agent.ProxyPort

	switch status {
	case "on":
		// proxy
		proxyCtx, proxyCancel := context.WithCancel(context.Background())
		// proxy command, start socks5 server on agent
		go func() {
			if _, err := strconv.Atoi(port); err != nil {
				CliPrintError("Invalid port: %v", err)
				return
			}
			cmd := fmt.Sprintf("!proxy %s %s", status, pf.To)
			err := SendCmd(cmd, CurrentTarget)
			if err != nil {
				CliPrintError("SendCmd: %v", err)
				return
			}
			defer proxyCancel() // mark proxy command as done
		}()

		// port mapping
		go func() {
			for proxyCtx.Err() == nil {
				time.Sleep(100 * time.Millisecond)
			}

			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	case "off":
		for id, session := range PortFwds {
			if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)",
				port,
				port) {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("!port_fwd %s stop", id)
				err := SendCmd(cmd, CurrentTarget)
				if err != nil {
					CliPrintError("SendCmd: %v", err)
					return
				}
			}
		}
	default:
		CliPrintError("Unknown operation '%s'", status)
	}
}
