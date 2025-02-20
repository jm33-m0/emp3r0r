package server

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handlePortForwarding handles proxy/port forwarding.
func handlePortForwarding(wrt http.ResponseWriter, req *http.Request) {
	var err error
	var h2x emp3r0r_def.H2Conn
	sh := new(network.StreamHandler)
	sh.H2x = &h2x
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
	pf, exist := network.PortFwds[sessionID.String()]
	if !exist {
		logging.Errorf("Port mapping session %s unknown", sessionID.String())
		return
	}
	pf.Sh = make(map[string]*network.StreamHandler)
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
		if pf, exist = network.PortFwds[sessionID.String()]; exist {
			pf.Cancel()
		} else {
			logging.Warningf("Port mapping %s not found", sessionID.String())
		}
		cancel()
		logging.Warningf("Closed port forwarding connection from %s", req.RemoteAddr)
	}()
	for pf.Ctx.Err() == nil {
		if _, exist := network.PortFwds[sessionID.String()]; !exist {
			logging.Warningf("Port mapping %s disconnected", sessionID.String())
			return
		}
		util.TakeASnap()
	}
}
