package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func bridgePreface(t *testing.T, header bridgeHeader) []byte {
	t.Helper()
	body, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal bridge header: %v", err)
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

func TestReadBridgeHeaderValid(t *testing.T) {
	header := bridgeHeader{
		Version:   bridgeVersion,
		Transport: "dns",
		Remote:    "203.0.113.9:53000",
		Stream:    "stream-1",
		Options:   map[string]string{"zone": "example.com"},
	}
	got, err := readBridgeHeader(bytes.NewReader(bridgePreface(t, header)))
	if err != nil {
		t.Fatalf("readBridgeHeader: %v", err)
	}
	if got.Transport != header.Transport || got.Remote != header.Remote {
		t.Fatalf("header = %+v, want %+v", got, header)
	}
}

func TestReadBridgeHeaderRejects(t *testing.T) {
	valid := bridgePreface(t, bridgeHeader{Version: bridgeVersion, Transport: "dns"})

	cases := map[string][]byte{
		"empty":          nil,
		"zero length":    {0, 0, 0, 0},
		"oversize":       {0, 0, 0x10, 0x01},
		"truncated body": append([]byte{0, 0, 0, 10}, []byte(`{"v`)...),
		"invalid json":   append([]byte{0, 0, 0, 1}, '{'),
		"bad version":    bridgePreface(t, bridgeHeader{Version: 99, Transport: "dns"}),
		"empty name":     bridgePreface(t, bridgeHeader{Version: bridgeVersion}),
		"uppercase name": bridgePreface(t, bridgeHeader{Version: bridgeVersion, Transport: "DNS"}),
		"bad character":  bridgePreface(t, bridgeHeader{Version: bridgeVersion, Transport: "dns/1"}),
	}
	for name, preface := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readBridgeHeader(bytes.NewReader(preface)); err == nil {
				t.Fatal("readBridgeHeader succeeded, want error")
			}
		})
	}

	if _, err := readBridgeHeader(bytes.NewReader(valid)); err != nil {
		t.Fatalf("valid preface rejected: %v", err)
	}
}

func TestHandleBridgeConn(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	remoteCh := make(chan string, 1)
	go handleBridgeConn(server, func(stream transport.StreamTransport) {
		remoteCh <- stream.RemoteAddrString()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return
		}
		_, _ = stream.Write([]byte("pong"))
	})

	preface := bridgePreface(t, bridgeHeader{
		Version:   bridgeVersion,
		Transport: "dns",
		Remote:    "203.0.113.9:53000",
	})
	if _, err := client.Write(preface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(resp) != "pong" {
		t.Fatalf("response = %q, want pong", resp)
	}
	if remote := <-remoteCh; remote != "203.0.113.9:53000" {
		t.Fatalf("remote = %q", remote)
	}
}

func TestSanitizeBridgeRemote(t *testing.T) {
	if got := sanitizeBridgeRemote("dns", " 1.2.3.4:53\n"); got != "1.2.3.4:53" {
		t.Fatalf("sanitized remote = %q", got)
	}
	if got := sanitizeBridgeRemote("dns", ""); got != "bridge:dns" {
		t.Fatalf("fallback remote = %q", got)
	}
	long := make([]byte, bridgeRemoteMax+10)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeBridgeRemote("dns", string(long)); len(got) != bridgeRemoteMax {
		t.Fatalf("long remote length = %d, want %d", len(got), bridgeRemoteMax)
	}
}

func TestRemoveStaleBridgeSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bridge.sock")

	// A regular file must never be removed.
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := removeStaleBridgeSocket(path); err == nil {
		t.Fatal("removeStaleBridgeSocket removed a regular file")
	}

	// A real stale socket is removed.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if err := removeStaleBridgeSocket(path); err != nil {
		t.Fatalf("remove stale socket: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket still exists: %v", err)
	}
}

func TestServeC2Bridge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bridge.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveC2Bridge(ctx, ln, func(stream transport.StreamTransport) {
			defer stream.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(stream, buf); err != nil {
				got <- "read error: " + err.Error()
				return
			}
			got <- string(buf) + "@" + stream.RemoteAddrString()
		})
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	preface := bridgePreface(t, bridgeHeader{
		Version:   bridgeVersion,
		Transport: "dns",
		Remote:    "203.0.113.9:53000",
	})
	if _, err := conn.Write(preface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.Close()

	select {
	case value := <-got:
		if value != "ping@203.0.113.9:53000" {
			t.Fatalf("accepted stream = %q", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bridge stream")
	}

	cancel()
	_ = ln.Close()
	if err := <-done; err != nil {
		t.Fatalf("serveC2Bridge: %v", err)
	}
}

func TestStartC2BridgeListenerRejectsBadFrame(t *testing.T) {
	oldRuntime := live.GetRuntimeConfig()
	oldWorkspace := live.EmpWorkSpace
	defer func() {
		live.SetRuntimeConfig(oldRuntime)
		live.EmpWorkSpace = oldWorkspace
	}()

	dir := t.TempDir()
	socket := filepath.Join(dir, "bridge.sock")
	live.EmpWorkSpace = dir
	live.SetRuntimeConfig(&def.Config{BridgeSocket: socket})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- StartC2BridgeListener(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("bridge socket was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		cancel()
		t.Fatalf("dial bridge: %v", err)
	}
	preface := bridgePreface(t, bridgeHeader{Version: bridgeVersion, Transport: "dns"})
	if _, err := conn.Write(preface); err != nil {
		conn.Close()
		cancel()
		t.Fatalf("write preface: %v", err)
	}
	// A frame length above SecureConn's 10 MiB limit must be rejected.
	if _, err := conn.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		conn.Close()
		cancel()
		t.Fatalf("write frame: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("bridge accepted an invalid frame")
	}
	_ = conn.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartC2BridgeListener: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge listener did not stop")
	}
}
