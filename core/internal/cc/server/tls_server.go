package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2AgentTLSServer starts the single C2 endpoint selected by
// C2ChannelMode. It is used by tests and embedders that exercise one transport
// at a time; production ServerMain serves all compiled transports through
// startAllC2Transports, because an agent's channel mode must not decide which
// listeners the server exposes. The h2conn/http_poll modes use the TLS
// frontend; QUIC returns an error when it is not compiled into the build.
func StartC2AgentTLSServer() error {
	prepareC2ServerPrerequisites()

	mode := live.GetRuntimeConfig().C2ChannelMode
	if mode == "" {
		mode = def.C2ChannelModeDefault
	}
	if mode == def.C2ChannelModeQUIC {
		return StartC2QUICServer()
	}
	if mode == def.C2ChannelModeH2Conn || mode == def.C2ChannelModeDefault || mode == def.C2ChannelModePlainHTTP {
		return StartC2TLSStreamServer()
	}
	return startRawC2TLSServer()
}

func prepareC2ServerPrerequisites() {
	if agents.AgentDB == nil || agents.AgentDB.Ping() != nil {
		dbPath := filepath.Join(live.EmpWorkSpace, "agents.db")
		if err := agents.InitAgentDB(dbPath); err != nil {
			logging.Fatalf("StartC2AgentTLSServer: init AgentDB: %v", err)
		}
		if active, purged, err := agents.ReconcileSessionsOnStartup(); err != nil {
			logging.Fatalf("StartC2AgentTLSServer: reconcile sessions: %v", err)
		} else {
			logging.Infof("Session restore: active=%d purged_stale=%d", active, purged)
		}
	}

	if _, err := os.Stat(paths.WWWRoot); os.IsNotExist(err) {
		if err = os.MkdirAll(paths.WWWRoot, 0o700); err != nil {
			logging.Fatalf("StartC2AgentTLSServer: %v", err)
		}
	}

	transport.SetCACrtPEM([]byte(live.GetRuntimeConfig().CAPEM))
}

func setupC2TLSListener() net.Listener {
	network.StopEmpTLSServer()
	ctx, cancel := context.WithCancel(context.Background())
	network.EmpTLSServerCtx = ctx
	network.EmpTLSServerCancel = cancel

	if err := transport.ReloadServerTLSCert(); err != nil {
		logging.Fatalf("StartC2AgentTLSServer: load TLS keypair: %v", err)
	}
	tlsCfg := &tls.Config{
		GetCertificate: transport.GetServerTLSCert,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		// This single certificate is presented regardless of the client's SNI:
		// agents may send a cover SNI and pin the C2 CA instead of matching a
		// hostname, and a mismatch must not abort the handshake.
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%s", live.GetRuntimeConfig().CCH2Port), tlsCfg)
	if err != nil {
		logging.Fatalf("Failed to start C2 TLS listener at *:%s: %v", live.GetRuntimeConfig().CCH2Port, err)
	}
	network.EmpTLSListener = listener

	return listener
}

// startRawC2TLSServer starts the raw TLS-over-TCP C2 listener.
// It accepts encrypted byte streams and delegates directly to the CBOR protocol core.
// No HTTP semantics are used at this boundary.
func startRawC2TLSServer() error {
	listener := setupC2TLSListener()

	logging.Successf("🚀 Starting C2 agent listener service with TLS at port %s", live.GetRuntimeConfig().CCH2Port)
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				logging.Warningf("C2 TLS service is shutdown")
				return nil
			}
			if network.EmpTLSServerCtx != nil {
				select {
				case <-network.EmpTLSServerCtx.Done():
					logging.Warningf("C2 TLS service is shutdown")
					return nil
				default:
				}
			}
			if ne, ok := acceptErr.(net.Error); ok && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			logging.Warningf("StartC2AgentTLSServer: accept failed: %v", acceptErr)
			continue
		}

		go func(c net.Conn) {
			stream := transport.NewStreamTransport(c, c.RemoteAddr().String())
			cborStreamAccept(stream)
		}(conn)
	}
}
