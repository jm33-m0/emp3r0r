package cc

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

func modulePortFwd() {
	switch Options["switch"].Val {
	case "off":
		for id, session := range PortFwds {
			if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)",
				Options["listen_port"].Val,
				Options["to"].Val) {
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
	case "reverse": // expose a dest from CC to agent
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = Options["listen_port"].Val, Options["to"].Val
		go func() {
			err := pf.RunReversedPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	default:
		var pf PortFwdSession
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = Options["listen_port"].Val, Options["to"].Val
		go func() {
			err := pf.RunPortFwd()
			if err != nil {
				CliPrintError("PortFwd failed: %v", err)
			}
		}()
	}
}

func moduleProxy() {
	// proxy
	proxyCtx, proxyCancel := context.WithCancel(context.Background())
	port := Options["port"].Val
	status := Options["status"].Val

	// port-fwd
	var pf PortFwdSession
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	pf.Lport, pf.To = port, port

	// proxy command, start socks5 server on agent
	go func() {
		if _, err := strconv.Atoi(port); err != nil {
			CliPrintError("Invalid port: %v", err)
			return
		}
		cmd := fmt.Sprintf("!proxy %s %s", status, port)
		err := SendCmd(cmd, CurrentTarget)
		if err != nil {
			CliPrintError("SendCmd: %v", err)
			return
		}
		defer proxyCancel() // mark proxy command as done
	}()

	switch status {
	case "on":
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
