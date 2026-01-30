package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
	"github.com/spf13/cobra"
)

// HandlePortMapping handles proxy/port forwarding.
func HandlePortMapping(sh *StreamHandler, wrt http.ResponseWriter, req *http.Request) {
	var err error
	h2x := new(def.H2Conn)
	sh.H2x = h2x
	sh.H2x.Conn, err = h2conn.Accept(wrt, req)
	if err != nil {
		logging.Errorf("handlePortForwarding: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	sh.H2x.Ctx = ctx
	sh.H2x.Cancel = cancel

	udpHandler := func(dstAddr string, listener *net.UDPConn) {
		logging.Debugf("Handling UDP packet for %s", dstAddr)
		for ctx.Err() == nil {
			buf := make([]byte, 1024)
			n, err := sh.H2x.Conn.Read(buf)
			if err != nil {
				logging.Errorf("Read error: %v", err)
			}
			udpClientAddr, err := net.ResolveUDPAddr("udp4", dstAddr)
			if err != nil {
				logging.Errorf("Resolve UDP addr error for %s: %v", dstAddr, err)
				return
			}
			if listener == nil {
				logging.Errorf("Nil UDP listener for %s", dstAddr)
				return
			}
			_, err = listener.WriteToUDP(buf[:n], udpClientAddr)
			if err != nil {
				logging.Errorf("Write to UDP client %s: %v", udpClientAddr.String(), err)
			}
		}
	}
	// port-forwarding logic, token parsing and session lookup
	vars := mux.Vars(req)
	token := vars["token"]
	origToken := token
	isSubSession := strings.Contains(token, "_")
	if isSubSession {
		token = strings.Split(token, "_")[0]
	}
	sessionID, err := uuid.Parse(token)
	if err != nil {
		logging.Errorf("Parse UUID failed from %s: %v", req.RemoteAddr, err)
		return
	}
	pf, exist := PortFwds[sessionID.String()]
	if !exist {
		logging.Errorf("Port mapping session %s unknown", sessionID.String())
		return
	}
	pf.Sh = make(map[string]*StreamHandler)
	if !isSubSession {
		pf.Sh[sessionID.String()] = sh
		logging.Debugf("Port forwarding connection (%s) from %s", sessionID.String(), req.RemoteAddr)
	} else {
		pf.Sh[origToken] = sh
		if strings.HasSuffix(origToken, "-reverse") {
			logging.Debugf("Reverse connection (%s) from %s", origToken, req.RemoteAddr)
			err = pf.RunReversedPortFwd(sh)
			if err != nil {
				logging.Errorf("RunReversedPortFwd error: %v", err)
			}
		} else if strings.HasSuffix(origToken, "-udp") {
			dstAddr := strings.Split(strings.Split(origToken, "_")[1], "-udp")[0]
			go udpHandler(dstAddr, pf.Listener)
		}
	}
	defer func() {
		if sh.H2x.Conn != nil {
			err = sh.H2x.Conn.Close()
			if err != nil {
				logging.Errorf("Close error in port forwarding: %v", err)
			}
		}
		if origToken != sessionID.String() {
			cancel()
			logging.Debugf("Closed sub-connection %s", origToken)
			return
		}
		if pf, exist = PortFwds[sessionID.String()]; exist {
			pf.Cancel()
		} else {
			logging.Warningf("Port mapping %s not found", sessionID.String())
		}
		cancel()
		logging.Warningf("Closed port forwarding connection from %s", req.RemoteAddr)
	}()
	for pf.Ctx.Err() == nil {
		if _, exist := PortFwds[sessionID.String()]; !exist {
			logging.Warningf("Port mapping %s disconnected", sessionID.String())
			return
		}
		util.TakeASnap(false)
	}
}

// CmdDeletePortFwdSession deletes a port mapping session by ID.
func CmdDeletePortFwdSession(cmd *cobra.Command, args []string) {
	sessionID, err := cmd.Flags().GetString("id")
	if err != nil {
		logging.Errorf("DeletePortFwdSession: %v", err)
		return
	}
	if sessionID == "" {
		logging.Errorf("DeletePortFwdSession: no session ID provided")
		return
	}
	PortFwdsMutex.Lock()
	defer PortFwdsMutex.Unlock()
	for id, session := range PortFwds {
		if id == sessionID {
			err := session.SendCmdFunc(fmt.Sprintf("%s --id %s", def.C2CmdDeletePortFwd, id), "", session.Agent.Tag)
			if err != nil {
				logging.Warningf("Tell agent %s to delete port mapping %s: %v", session.Agent.Tag, sessionID, err)
			}
			session.Cancel()
			delete(PortFwds, id)
		}
	}
}

// CmdListPortFwds lists currently active port mappings.
func CmdListPortFwds(cmd *cobra.Command, args []string) {
	tdata := [][]string{}
	for id, portmap := range PortFwds {
		if portmap.Sh == nil {
			portmap.Cancel()
			continue

		}
		bindAddr := portmap.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1"
		}
		to := portmap.To + " (Agent) "
		lport := bindAddr + ":" + portmap.Lport + " (CC) "
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
	header := []string{"Local Port", "To", "Agent", "Description", "ID"}
	tableStr := cli.BuildTable(header, tdata)
	cli.AdaptiveTable(tableStr)
	logging.Infof("\n\033[0m%s\n\n", tableStr)
}
