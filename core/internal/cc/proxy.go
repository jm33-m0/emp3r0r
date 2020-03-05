package cc

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
)

// PortFwdSessions collect all port fwds, provide a way to cancel each of them
var PortFwdSessions = make(map[string]context.CancelFunc)

// PortFwd forward from ccPort to dstPort on agent, via h2conn
// as if the dstPort is listening on CC machine
func PortFwd(ctx context.Context, cancel context.CancelFunc, listenPort, toPort string) (err error) {
	fwdID := uuid.New().String()
	cmd := fmt.Sprintf("!port_fwd %s %s", toPort, fwdID)
	err = SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}

	defer cancel()

	// listen on listenPort, and do the forward
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		return err
	}

	// mark this session
	PortFwdHandlers[fwdID] = nil
	PortFwdSessions[fwdID] = cancel

	for ctx.Err() == nil {
		if PortFwdHandlers[fwdID] == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleRequest(conn, fwdID)
	}

	return
}

func handleRequest(conn net.Conn, fwdID string) {
	sh := PortFwdHandlers[fwdID]
	if sh == nil {
		CliPrintError("PortFwd: StreamHandler not found")
		return
	}

	go func() {
		defer conn.Close()
		_, err := io.Copy(conn, sh.H2x.Conn)
		if err != nil {
			CliPrintError("iocopy TCP to h2conn: %v", err)
		}
	}()

	go func() {
		defer conn.Close()
		_, err := io.Copy(sh.H2x.Conn, conn)
		if err != nil {
			CliPrintError("iocopy h2conn to TCP: %v", err)
		}
	}()
}
