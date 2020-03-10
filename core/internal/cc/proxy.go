package cc

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
)

// PortFwdSession holds controller interface of a port-fwd session
type PortFwdSession struct {
	Lport       string // listen_port
	Tport       string // to_port
	Description string // fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, toPort)

	Sh     *StreamHandler     // related to HTTP handler
	Ctx    context.Context    // PortFwd context
	Cancel context.CancelFunc // PortFwd cancel
}

// ListPortFwds list currently active port mappings
func ListPortFwds() {
	color.Cyan("Active port mappings\n")
	color.Cyan("====================\n\n")
	for id, portmap := range PortFwds {
		if portmap.Sh == nil {
			portmap.Cancel()
			continue
		}
		color.Green("%s (%s)\n", portmap.Description, id)
	}
}

// RunPortFwd forward from ccPort to dstPort on agent, via h2conn
// as if the dstPort is listening on CC machine
func (pf *PortFwdSession) RunPortFwd() (err error) {
	/*
		handle connections to "localhost:listenPort"
	*/

	handlePerConn := func(conn net.Conn, fwdID string) {
		var err error

		pf, exist := PortFwds[fwdID]
		if !exist {
			return
		}
		sh := pf.Sh
		if sh == nil {
			CliPrintWarning("PortFwd: StreamHandler not found")
			return
		}

		connCtx, connCancel := context.WithCancel(context.Background())

		// clean up all goroutines
		cleanup := func() {
			_, _ = conn.Write([]byte("exit"))
			conn.Close()
			CliPrintInfo("PortFwd conn handler (%s) finished", conn.RemoteAddr().String())
			connCancel()
		}

		// io.Copy
		go func() {
			defer cleanup()
			_, err = io.Copy(sh.H2x.Conn, conn)
			if err != nil {
				CliPrintWarning("conn -> h2: %v", err)
				return
			}
		}()
		go func() {
			defer cleanup()
			_, err = io.Copy(conn, sh.H2x.Conn)
			if err != nil {
				CliPrintWarning("h2 -> conn: %v", err)
				return
			}
		}()

		// keep running until context is canceled
		defer cleanup()
		for connCtx.Err() == nil {
			time.Sleep(500 * time.Millisecond)
		}
	}

	/*
		start port mapping
	*/

	ctx := pf.Ctx
	cancel := pf.Cancel
	toPort := pf.Tport
	listenPort := pf.Lport

	_, e1 := strconv.Atoi(toPort)
	_, e2 := strconv.Atoi(listenPort)
	if e1 != nil || e2 != nil {
		return fmt.Errorf("Invalid port: %v (to_port), %v (listen_port)", e1, e2)
	}

	// is this mapping already active?
	for id, session := range PortFwds {
		if session.Description == pf.Description {
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

	// mark this session, save to PortFwds
	pf.Sh = nil
	pf.Description = fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, toPort)
	PortFwds[fwdID] = pf

	cleanup := func() {
		cancel()
		ln.Close()
		delete(PortFwds, fwdID)
		CliPrintWarning("PortFwd session (%s: %s) has finished", fwdID, pf.Description)
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
		p, exist := PortFwds[fwdID]
		if !exist {
			return
		}
		if p.Sh == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// listen
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		handlePerConn(conn, fwdID)
	}

	return
}
