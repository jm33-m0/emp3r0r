package transport

import (
	"net"
	"time"

	"github.com/posener/h2conn"
)

// C2Transport is the interface every pluggable C2 transport must satisfy.
// The C2 protocol layer only calls Read, Write, Close, and RemoteAddr.
// HTTP concepts (headers, URLs, status codes) are never visible above this boundary.
type C2Transport interface {
	net.Conn
	// RemoteAddrString returns a string representation of the remote peer (logging only).
	RemoteAddrString() string
}

// H2Transport wraps an h2conn.Conn together with a remote-address string
// to satisfy the C2Transport interface. It is the default adapter for h2conn.Conn.
type H2Transport struct {
	H2Conn *h2conn.Conn // exported so callers can type-assert for FTP session linking
	addr   string
}

// NewH2Transport creates a C2Transport wrapping conn (e.g. *h2conn.Conn).
func NewH2Transport(conn *h2conn.Conn, remoteAddr string) C2Transport {
	return &H2Transport{H2Conn: conn, addr: remoteAddr}
}

// Read implements io.Reader.
func (h *H2Transport) Read(p []byte) (int, error) { return h.H2Conn.Read(p) }

// Write implements io.Writer.
func (h *H2Transport) Write(p []byte) (int, error) { return h.H2Conn.Write(p) }

// Close implements io.Closer.
func (h *H2Transport) Close() error { return h.H2Conn.Close() }

// RemoteAddrString returns the address of the remote peer as a string.
func (h *H2Transport) RemoteAddrString() string {
	return h.addr
}

// net.Conn implementation stubs
func (h *H2Transport) LocalAddr() net.Addr                { return nil }
func (h *H2Transport) RemoteAddr() net.Addr               { return nil }
func (h *H2Transport) SetDeadline(t time.Time) error      { return nil }
func (h *H2Transport) SetReadDeadline(t time.Time) error  { return nil }
func (h *H2Transport) SetWriteDeadline(t time.Time) error { return nil }
