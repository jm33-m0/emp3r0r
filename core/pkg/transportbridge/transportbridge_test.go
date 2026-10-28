package transportbridge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestRelay(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "bridge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	prefaceCh := make(chan Preface, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var length [4]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(length[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var preface Preface
		if err := json.Unmarshal(body, &preface); err != nil {
			return
		}
		prefaceCh <- preface
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}()

	agentConn, agentPeer := net.Pipe()
	defer agentPeer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Relay(ctx, agentConn, Config{Transport: "tor", C2Socket: socket})
	}()

	if _, err := agentPeer.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(agentPeer, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}

	preface := <-prefaceCh
	if preface.Version != PrefaceVersion || preface.Transport != "tor" {
		t.Fatalf("preface = %+v", preface)
	}
	if err := <-done; err != nil {
		t.Fatalf("Relay: %v", err)
	}
}

func TestServeRejectsMissingConfig(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if err := Serve(context.Background(), ln, Config{}); err == nil {
		t.Fatal("Serve accepted an empty configuration")
	}
}
