package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// HandlePortFwdStream natively handles port forwarding over a pure io.ReadWriteCloser stream.
func HandlePortFwdStream(sh *StreamHandler, conn io.ReadWriteCloser, agentUUID string, token string, remoteAddr string, cancel context.CancelFunc) {
	token = strings.TrimSpace(token)
	if token == "" {
		logging.Errorf("HandlePortFwdStream: blocked proxy stream from %s with empty token", remoteAddr)
		cancel()
		conn.Close()
		return
	}

	if agentUUID == "" {
		logging.Errorf("HandlePortFwdStream: blocked proxy stream from %s with empty agentUUID", remoteAddr)
		cancel()
		conn.Close()
		return
	}

	// SECURITY: Verify that agent is enrolled and has an active session.
	// Auxiliary routes (FTP, Proxy, WWW) are sub-operations of the main agent session.
	if agents.AgentDB == nil {
		logging.Errorf("HandlePortFwdStream: AgentDB unavailable for %s from %s", strconv.Quote(agentUUID), remoteAddr)
		cancel()
		conn.Close()
		return
	}
	pinnedKey, _, found, lookupErr := agents.GetPinnedIdentity(agentUUID)
	if lookupErr != nil {
		logging.Warningf("HandlePortFwdStream: AgentDB lookup failed for %s from %s: %v", strconv.Quote(agentUUID), remoteAddr, lookupErr)
		cancel()
		conn.Close()
		return
	}
	if !found || pinnedKey == "" {
		logging.Warningf("HandlePortFwdStream: agent %s not enrolled or has empty pinned key from %s", strconv.Quote(agentUUID), remoteAddr)
		cancel()
		conn.Close()
		return
	}

	// Update heartbeat to show activity on this auxiliary channel
	_ = agents.UpdateSessionHeartbeat(agentUUID)

	sh.Secure = conn
	sh.Token = token
	sh.Ctx, sh.Cancel = context.WithCancel(context.Background())
	// Wrap the cancel to also call the parent context's cancel
	origCancel := sh.Cancel
	sh.Cancel = func() {
		origCancel()
		if cancel != nil {
			cancel()
		}
	}
	ctx := sh.Ctx

	udpHandler := func(dstAddr string, listener *net.UDPConn) {
		logging.Debugf("Handling UDP packet for %s", dstAddr)
		for ctx.Err() == nil {
			buf := make([]byte, 1024)
			n, err := sh.Read(buf)
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
	origToken := token
	isSubSession := strings.Contains(token, "_")
	if isSubSession {
		parts := strings.SplitN(token, "_", 2)
		token = parts[0]
		if token == "" {
			logging.Errorf("HandlePortFwdStream: malformed proxy token %q from %s", origToken, remoteAddr)
			cancel()
			conn.Close()
			return
		}
	}
	sessionID, err := uuid.Parse(token)
	if err != nil {
		logging.Errorf("Parse UUID failed from %s: %v", remoteAddr, err)
		cancel()
		conn.Close()
		return
	}
	val, exist := PortFwds.Load(sessionID.String())
	if !exist {
		logging.Debugf("Port mapping session %s unknown. Did you remove it?", sessionID.String())
		cancel()
		conn.Close()
		return
	}
	pf := val.(*PortFwdSession)
	if pf.Ctx == nil || pf.Cancel == nil {
		// Session may come from operator registration and miss runtime context fields.
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	}
	if pf.Sh == nil {
		pf.Sh = make(map[string]*StreamHandler)
	}
	if !isSubSession {
		pf.Sh[sessionID.String()] = sh
		logging.Debugf("Port forwarding connection (%s) from %s", sessionID.String(), remoteAddr)
	} else {
		pf.Sh[origToken] = sh
		if readyAny, ok := portFwdStreamReady.LoadAndDelete(origToken); ok {
			close(readyAny.(chan struct{}))
			logging.Debugf("Signaled stream handler ready for %s", origToken)
		}
		if strings.HasSuffix(origToken, "-reverse") {
			logging.Debugf("Reverse connection (%s) from %s", origToken, remoteAddr)
			err = pf.RunReversedPortFwd(sh)
			if err != nil {
				logging.Errorf("RunReversedPortFwd error: %v", err)
			}
		} else if strings.HasSuffix(origToken, "-udp") {
			dstAddr := strings.Split(strings.Split(origToken, "_")[1], "-udp")[0]
			go udpHandler(dstAddr, pf.Listener)
		}
	}

	// Signal that Sh map is ready (close channel to wake up waiters)
	if pf.ShReady != nil {
		select {
		case <-pf.ShReady:
			// Already closed, ignore
		default:
			close(pf.ShReady)
		}
	}
	defer func() {
		err := sh.Close()
		if err != nil {
			logging.Errorf("Close error in port forwarding: %v", err)
		}

		if origToken != sessionID.String() {
			sh.Cancel()
			logging.Debugf("Closed sub-connection %s", origToken)
			_ = agents.UpdateSessionHeartbeat(agentUUID)
			return
		}
		if val, exist := PortFwds.Load(sessionID.String()); exist {
			pf := val.(*PortFwdSession)
			if pf.Cancel != nil {
				pf.Cancel()
			}
		} else {
			logging.Debugf("Port mapping %s not found (likely deleted)", sessionID.String())
		}
		sh.Cancel()
		_ = agents.UpdateSessionHeartbeat(agentUUID)
		logging.Debugf("Closed port forwarding connection from %s", remoteAddr)
	}()
	for pf.Ctx != nil && pf.Ctx.Err() == nil {
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
	agentTag := ""
	if session.Agent != nil {
		agentTag = session.Agent.Tag
	}
	err := session.SendCmdFunc(fmt.Sprintf("%s --id %s", def.C2CmdDeletePortFwd, sessionID), "", agentTag)
	if err != nil {
		logging.Warningf("Tell agent %s to delete port mapping %s: %v", agentTag, sessionID, err)
	}

	// Cancel and delete locally
	if session.Cancel != nil {
		session.Cancel()
	}
	PortFwds.Delete(sessionID)

	if session.UnregisterFunc != nil {
		if err = session.UnregisterFunc(sessionID); err != nil {
			logging.Errorf("DeletePortFwdSession: failed to unregister %s: %v", sessionID, err)
		}
	}

	logging.Debugf("Deleted port forwarding session %s", sessionID)
	return nil
}
