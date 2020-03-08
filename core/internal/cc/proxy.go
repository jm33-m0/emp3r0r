package cc

import (
	"bytes"
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
	Sh          *StreamHandler     // related to HTTP handler
	Ctx         context.Context    // PortFwd context
	Cancel      context.CancelFunc // PortFwd cancel
	Description string             // fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, toPort)
}

// ListPortFwds list currently active port mappings
func ListPortFwds() {
	color.Cyan("Active port mappings\n")
	color.Cyan("====================\n\n")
	for id, portmap := range PortFwds {
		color.Green("%s (%s)\n", portmap.Description, id)
	}
}

// PortFwd forward from ccPort to dstPort on agent, via h2conn
// as if the dstPort is listening on CC machine
func PortFwd(ctx context.Context, cancel context.CancelFunc, listenPort, toPort string) (err error) {
	// is this mapping already active?
	for id, session := range PortFwds {
		if session.Description == fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, toPort) {
			return fmt.Errorf("Such mapping already exists:\n%s", id)
		}
	}

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
	portfwd.Ctx = ctx
	portfwd.Cancel = cancel
	PortFwds[fwdID] = &portfwd

	cleanup := func() {
		cancel()
		ln.Close()
		delete(PortFwds, fwdID)
		CliPrintInfo("PortFwd session (%s: %s) has finished", fwdID, portfwd.Description)
	}

	// catch cancel event, and trigger the termination of parent function
	go func() {
		for ctx.Err() == nil {
			time.Sleep(1 * time.Second)
		}
		_, _ = net.Dial("tcp", "127.0.0.1:"+listenPort)
	}()

	defer cleanup()
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
	pf, exist := PortFwds[fwdID]
	if !exist {
		return
	}
	sh := pf.Sh
	if sh == nil {
		CliPrintWarning("PortFwd: StreamHandler not found")
		return
	}
	var err error
	send := make(chan []byte)
	recv := make(chan []byte)

	connCtx, connCancel := context.WithCancel(context.Background())

	// clean up all goroutines
	cleanup := func() {
		conn.Close()
		send <- []byte("exit\n")
		recv <- []byte("exit\n")
		CliPrintInfo("PortFwd conn handler (%s) finished", conn.RemoteAddr().String())
		connCancel()
	}

	// send data to listen port
	go func() {
		defer cleanup()
		for incoming := range recv {
			incoming = bytes.Trim(incoming, "\x00") // trim NULLs
			if connCtx.Err() != nil {
				return
			}
			_, err = conn.Write(incoming)
			if err != nil {
				CliPrintWarning("PortFwd write to listenPort %s\n%v", conn.RemoteAddr().String(), err)
				return
			}
		}
	}()

	// send data to agent via h2conn
	go func() {
		defer cleanup()
		for outgoing := range send {
			if connCtx.Err() != nil {
				return
			}

			// FIXME check destination
			CliPrintInfo("PortFwd write to agent port: %s", pf.Description)

			_, err = sh.H2x.Conn.Write(outgoing)
			if err != nil {
				CliPrintWarning("PortFwd write to agent port: %v", err)
				return
			}
		}
	}()

	// read from local listen port, push to send channel, to be sent to agent via h2conn
	go func() {
		defer cleanup()
		for connCtx.Err() == nil {
			buf := make([]byte, agent.ProxyBufSize)
			_, err = conn.Read(buf)
			if err != nil {
				CliPrintWarning("PortFwd read from tcp: %s to h2conn\nERROR: %v", conn.RemoteAddr().String(), err)
				return
			}
			send <- buf
		}
	}()

	// read from h2conn, push to recv channel
	defer cleanup()
	for readbuf := range sh.Buf {
		if connCtx.Err() != nil {
			return
		}
		recv <- readbuf
	}
}
