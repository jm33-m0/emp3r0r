package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// handleFileUploadStream processes an FTP upload directly over the pure CBOR encrypted stream.
// It bypasses the legacy HTTP multiplexer and injects the raw SecureConn into the stream handler.
func handleFileUploadStream(conn *transport.SecureConn, streamID string, remoteAddr string, ctx context.Context, cancel context.CancelFunc) {
	if streamID == "" {
		logging.Errorf("handleFileUploadStream: blocked FTP stream from %s with empty StreamID", remoteAddr)
		cancel()
		conn.Close()
		return
	}

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
