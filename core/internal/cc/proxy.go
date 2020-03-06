package cc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
)

// PortFwdSession holds controller interface of a port-fwd session
type PortFwdSession struct {
	Sh          *StreamHandler
	Cancel      context.CancelFunc
	Description string
}

// ListPortFwds list currently active port mappings
func ListPortFwds() {
	color.Cyan("Active port mappings\n")
	color.Cyan("====================\n\n")
	for id, portmap := range PortFwds {
		color.Green("%s: %s\n", id, portmap.Description)
	}
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

	defer func() {
		cancel()
		ln.Close()
		delete(PortFwds, fwdID)
		CliPrintInfo("PortFwd (%s): %s exited", fwdID, portfwd.Description)
	}()

	for ctx.Err() == nil {
		if PortFwds[fwdID].Sh == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handlePerConn(conn, fwdID)
	}

	return
}

func handlePerConn(conn net.Conn, fwdID string) {
	sh := PortFwds[fwdID].Sh
	if sh == nil {
		CliPrintError("PortFwd: StreamHandler not found")
		return
	}
	var err error
	send := make(chan []byte)
	recv := make(chan []byte)

	connCtx, cancel := context.WithCancel(context.Background())

	// send data to listen port
	go func() {
		defer cancel()
		for incoming := range recv {
			select {
			case <-connCtx.Done():
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
		defer cancel()
		for outgoing := range send {
			select {
			case <-connCtx.Done():
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
		defer cancel()
		for connCtx.Err() == nil {
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
	defer func() {
		err = conn.Close()
		if err != nil {
			CliPrintWarning("PortFwd closing client connection: %v", err)
		}
		cancel()
		CliPrintInfo("PortFwd request finished")
	}()
	for readbuf := range sh.Buf {
		select {
		case <-connCtx.Done():
			return
		default:
			recv <- readbuf
		}
	}
}
