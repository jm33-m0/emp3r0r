package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// The bridge listener is the local IPC ingress for custom transports. A bridge
// process accepts an agent's custom wire, opens one Unix connection per agent
// stream, writes a small preface, and then pumps raw bytes. The C2 wraps the
// connection in the same StreamTransport used by every built-in listener, so
// SecureConn, MsgAuth, PFS, routes, jobs, and modules are unchanged.
const (
	bridgeVersion       = 1
	bridgeHeaderMax     = 4096
	bridgeHeaderTimeout = 5 * time.Second
	bridgeStreamsMax    = 1024
	bridgeRemoteMax     = 256
)

type bridgeHeader struct {
	Version   int               `json:"version"`
	Transport string            `json:"transport"`
	Remote    string            `json:"remote"`
	Stream    string            `json:"stream"`
	Options   map[string]string `json:"options"`
}

type bridgeAcceptor func(transport.StreamTransport)

// bridgeSocketPath returns the configured socket path, or a default under the
// operator workspace.
func bridgeSocketPath() string {
	if path := live.GetRuntimeConfig().BridgeSocket; path != "" {
		return path
	}
	if live.EmpWorkSpace != "" {
		return filepath.Join(live.EmpWorkSpace, "bridge.sock")
	}
	return filepath.Join(os.TempDir(), "c2-bridge.sock")
}

// StartC2BridgeListener serves the local IPC socket until ctx is cancelled.
func StartC2BridgeListener(ctx context.Context) error {
	path := bridgeSocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create bridge socket directory: %w", err)
	}
	if err := removeStaleBridgeSocket(path); err != nil {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on bridge socket %s: %w", path, err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set bridge socket permissions: %w", err)
	}

	logging.Successf("🚀 Starting C2 transport bridge at %s", path)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return serveC2Bridge(ctx, listener, cborProtocolDispatch)
}

// serveC2Bridge is separated from StartC2BridgeListener so tests can supply a
// fake acceptor without starting the real dispatcher.
func serveC2Bridge(ctx context.Context, listener net.Listener, accept bridgeAcceptor) error {
	streams := make(chan struct{}, bridgeStreamsMax)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept bridge stream: %w", err)
		}
		select {
		case streams <- struct{}{}:
		default:
			logging.Warningf("C2 bridge: too many pending streams, dropping %s", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		go func(conn net.Conn) {
			defer func() { <-streams }()
			handleBridgeConn(conn, accept)
		}(conn)
	}
}

// handleBridgeConn reads the bridge preface and hands the remaining connection
// to the dispatcher. It owns closing conn.
func handleBridgeConn(conn net.Conn, accept bridgeAcceptor) {
	defer conn.Close()

	if err := checkBridgePeer(conn); err != nil {
		logging.Warningf("C2 bridge: reject peer %s: %v", conn.RemoteAddr(), err)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(bridgeHeaderTimeout))
	header, err := readBridgeHeader(conn)
	if err != nil {
		logging.Warningf("C2 bridge: invalid preface from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		logging.Warningf("C2 bridge: clear deadline for %s: %v", conn.RemoteAddr(), err)
		return
	}

	remote := sanitizeBridgeRemote(header.Transport, header.Remote)
	logging.Debugf("C2 bridge: new %q stream from %s", header.Transport, remote)
	accept(transport.NewStreamTransport(conn, remote))
}

func readBridgeHeader(r io.Reader) (bridgeHeader, error) {
	var lengthBuf [4]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return bridgeHeader{}, fmt.Errorf("read preface length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length == 0 || length > bridgeHeaderMax {
		return bridgeHeader{}, fmt.Errorf("preface length %d out of range (max %d)", length, bridgeHeaderMax)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return bridgeHeader{}, fmt.Errorf("read preface body: %w", err)
	}

	var header bridgeHeader
	if err := json.Unmarshal(body, &header); err != nil {
		return bridgeHeader{}, fmt.Errorf("decode preface: %w", err)
	}
	if header.Version != bridgeVersion {
		return bridgeHeader{}, fmt.Errorf("unsupported preface version %d", header.Version)
	}
	if err := validateBridgeTransportName(header.Transport); err != nil {
		return bridgeHeader{}, err
	}
	return header, nil
}

func validateBridgeTransportName(name string) error {
	if name == "" {
		return fmt.Errorf("transport name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("transport name is too long")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		case r >= 'A' && r <= 'Z':
			// Accept upper-case but reject it explicitly: names are compared
			// as opaque strings, and mixed case invites mismatches.
			return fmt.Errorf("transport name must be lower-case")
		default:
			return fmt.Errorf("invalid character %q at position %d", r, i)
		}
	}
	return nil
}

func sanitizeBridgeRemote(transportName, remote string) string {
	remote = util.SanitizeOneLine(remote)
	if len(remote) > bridgeRemoteMax {
		remote = remote[:bridgeRemoteMax]
	}
	if remote == "" {
		return "bridge:" + transportName
	}
	return remote
}

// removeStaleBridgeSocket removes a leftover socket from an unclean shutdown.
// A regular file at the same path is never removed: it may be a symlink attack
// or an operator mistake, and failing is safer than unlinking it.
func removeStaleBridgeSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect bridge socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("bridge path %s exists and is not a socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale bridge socket %s: %w", path, err)
	}
	return nil
}
