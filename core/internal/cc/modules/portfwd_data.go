package modules

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// GetPortFwdSessions returns all active port forwarding sessions
func GetPortFwdSessions() []def.PortFwdSession {
	// If the callback is set, use it to fetch from server
	// This is set by the operator when it starts up
	if RegisterPortFwdFunc != nil && GetPortFwdSessionsFunc != nil {
		sessions, err := GetPortFwdSessionsFunc()
		if err == nil {
			return sessions
		}
	}

	var sessions []def.PortFwdSession

	network.PortFwds.Range(func(id, value any) bool {
		portmap := value.(*network.PortFwdSession)
		// Skip invalid sessions
		if portmap.Sh == nil {
			portmap.Cancel()
			return true // continue iteration
		}

		bindAddr := portmap.BindAddr
		if bindAddr == "" {
			bindAddr = def.Localhost
		}

		// Build local and remote addresses
		localPort := bindAddr + ":" + portmap.Lport
		remoteAddr := portmap.To

		// Add context for reverse vs forward
		if portmap.Reverse {
			localPort = portmap.Lport + " (Agent)"
			remoteAddr = portmap.To + " (CC)"
		} else {
			localPort = localPort + " (CC)"
			remoteAddr = remoteAddr + " (Agent)"
		}

		sessions = append(sessions, def.PortFwdSession{
			ID:          id.(string),
			LocalPort:   localPort,
			RemoteAddr:  remoteAddr,
			BindAddr:    bindAddr,
			AgentTag:    portmap.Agent.Tag,
			Description: portmap.Description,
			Reverse:     portmap.Reverse,
		})
		return true
	})

	return sessions
}
