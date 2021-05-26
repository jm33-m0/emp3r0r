package cc

import (
	"context"
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
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
	pf.Lport, pf.To = port, "127.0.0.1:"+emp3r0r_data.ProxyPort

	switch status {
	case "on":
		// port mapping of default socks5 proxy
		go func() {
			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	case "off":
		for id, session := range PortFwds {
			if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)",
				pf.Lport,
				pf.To) {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("!delete_portfwd %s", id)
				err := SendCmd(cmd, session.Agent)
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
