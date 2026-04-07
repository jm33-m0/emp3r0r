package server

import (
	"context"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// handleFileUploadStream processes an FTP upload directly over the pure CBOR encrypted stream.
// It bypasses the legacy HTTP multiplexer and injects the raw SecureConn into the stream handler.
func handleFileUploadStream(conn *transport.SecureConn, agentUUID string, streamID string, remoteAddr string, ctx context.Context, cancel context.CancelFunc) {
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

	logging.Infof("CBOR FTP routing: delegating stream %s from %s to core FTP handler", streamID, remoteAddr)

	// Since we are not using an HTTP roundtripper to monitor Context cancelation for us,
	// we spawn a goroutine to force-close the underlying connection when the parent context
	// (or the dispatcher's stream timeout/cancellation) finishes.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// The legacy FTP package accepts io.ReadWriteCloser directly now.
	ftp.HandleFTPStream(conn, streamID, remoteAddr, cancel)
}
