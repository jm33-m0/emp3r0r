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
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2AgentTLSServer starts the C2 server entrypoint.
// The default h2 stream mode uses a separate HTTP/h2 stream server; the raw TLS core
// remains available for non-HTTP stream modes.
func StartC2AgentTLSServer() {
	prepareC2ServerPrerequisites()

	mode := live.RuntimeConfig.C2ChannelMode
	if mode == "" {
		mode = def.C2ChannelModeDefault
	}
	if mode == def.C2ChannelModeH2Conn || mode == def.C2ChannelModeDefault || mode == def.C2ChannelModePlainHTTP {
		StartC2H2StreamServer()
		return
	}
	startRawC2TLSServer()
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

	if _, err := os.Stat(live.Temp + transport.WWW); os.IsNotExist(err) {
		if err = os.MkdirAll(live.Temp+transport.WWW, 0o700); err != nil {
			logging.Fatalf("StartC2AgentTLSServer: %v", err)
		}
	}

	transport.SetCACrtPEM([]byte(live.RuntimeConfig.CAPEM))
}

func setupC2TLSListener() net.Listener {
	network.StopEmpTLSServer()
	ctx, cancel := context.WithCancel(context.Background())
	network.EmpTLSServerCtx = ctx
	network.EmpTLSServerCancel = cancel

	cert, err := tls.LoadX509KeyPair(transport.ServerCrtFile, transport.ServerKeyFile)
	if err != nil {
		logging.Fatalf("StartC2AgentTLSServer: load TLS keypair: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%s", live.RuntimeConfig.CCH2Port), tlsCfg)
	if err != nil {
		logging.Fatalf("Failed to start C2 TLS listener at *:%s: %v", live.RuntimeConfig.CCH2Port, err)
	}
	network.EmpTLSListener = listener

	return listener
}

// startRawC2TLSServer starts the raw TLS-over-TCP C2 listener.
// It accepts encrypted byte streams and delegates directly to the CBOR protocol core.
// No HTTP semantics are used at this boundary.
func startRawC2TLSServer() {
	listener := setupC2TLSListener()

	logging.Successf("🚀 Starting C2 agent listener service with TLS at port %s", live.RuntimeConfig.CCH2Port)
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				logging.Warningf("C2 TLS service is shutdown")
				return
			}
			if network.EmpTLSServerCtx != nil {
				select {
				case <-network.EmpTLSServerCtx.Done():
					logging.Warningf("C2 TLS service is shutdown")
					return
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
