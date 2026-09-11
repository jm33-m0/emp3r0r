//go:build windows

package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	smbTestPort     = 44444
	smbTestPassword = "smb-e2e-password"
)

func smbTestAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", smbTestPort)
}

// smbTestListen starts an SMB listener with a per-test salt (unique pipe name)
// and tears it down when the test ends.
func smbTestListen(t *testing.T, salt string) (net.Listener, SMBTransport) {
	t.Helper()
	srv := SMBTransport{}
	l, err := srv.Listen(strconv.Itoa(smbTestPort), smbTestPassword, salt)
	if err != nil {
		t.Fatalf("SMBTransport.Listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, srv
}

// smbTestAcceptDial dials the listener from a goroutine and accepts on the
// server side, returning both ends.
func smbTestAcceptDial(t *testing.T, l net.Listener, srv SMBTransport, salt string) (client, server net.Conn) {
	t.Helper()
	type dialRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialRes, 1)
	go func() {
		c, err := srv.Dial(smbTestAddr(), smbTestPassword, salt)
		ch <- dialRes{c, err}
	}()

	server, err := srv.Accept(context.Background(), l)
	if err != nil {
		t.Fatalf("SMBTransport.Accept: %v", err)
	}
	res := <-ch
	if res.err != nil {
		server.Close()
		t.Fatalf("SMBTransport.Dial: %v", res.err)
	}
	t.Cleanup(func() { res.conn.Close() })
	t.Cleanup(func() { server.Close() })
	return res.conn, server
}

func TestSMBTransportRoundTrip(t *testing.T) {
	l, srv := smbTestListen(t, "e2e-round-trip")
	client, server := smbTestAcceptDial(t, l, srv, "e2e-round-trip")

	// Larger than the 64 KiB pipe buffer to exercise chunked framing.
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
}

func TestSMBTransportReadDeadline(t *testing.T) {
	l, srv := smbTestListen(t, "e2e-deadline")
	client, server := smbTestAcceptDial(t, l, srv, "e2e-deadline")

	if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 16)
	_, err := server.Read(buf)
	if !os.IsTimeout(err) {
		t.Fatalf("expected i/o timeout, got %v", err)
	}

	// Clearing the deadline must restore blocking reads.
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go client.Write([]byte("after-timeout"))
	if _, err := io.ReadFull(server, buf[:13]); err != nil {
		t.Fatalf("read after deadline reset: %v", err)
	}
	if string(buf[:13]) != "after-timeout" {
		t.Fatalf("unexpected payload %q", buf[:13])
	}
}

func TestSMBTransportSequentialConnections(t *testing.T) {
	const salt = "e2e-sequential"
	l, srv := smbTestListen(t, salt)

	for i := 0; i < 3; i++ {
		client, err := srv.Dial(smbTestAddr(), smbTestPassword, salt)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		server, err := srv.Accept(context.Background(), l)
		if err != nil {
			client.Close()
			t.Fatalf("accept %d: %v", i, err)
		}

		msg := []byte(fmt.Sprintf("message-%d", i))
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("connection %d: got %q want %q", i, got, msg)
		}
		server.Close()
		client.Close()
	}
}

func TestSMBTransportConcurrentConnections(t *testing.T) {
	const (
		salt = "e2e-concurrent"
		n    = 4
	)
	l, srv := smbTestListen(t, salt)

	errs := make(chan error, n*2)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := srv.Dial(smbTestAddr(), smbTestPassword, salt)
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", i, err)
				return
			}
			defer client.Close()

			msg := []byte(fmt.Sprintf("client-%d", i))
			if _, err := client.Write(msg); err != nil {
				errs <- fmt.Errorf("client %d write: %w", i, err)
				return
			}
			got := make([]byte, 64)
			read, err := client.Read(got)
			if err != nil {
				errs <- fmt.Errorf("client %d read: %w", i, err)
				return
			}
			want := append([]byte("ack-"), msg...)
			if !bytes.Equal(got[:read], want) {
				errs <- fmt.Errorf("client %d got %q want %q", i, got[:read], want)
			}
		}(i)
	}

	for i := 0; i < n; i++ {
		server, err := srv.Accept(context.Background(), l)
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 64)
			read, err := c.Read(buf)
			if err != nil {
				errs <- fmt.Errorf("server read: %w", err)
				return
			}
			if _, err := c.Write(append([]byte("ack-"), buf[:read]...)); err != nil {
				errs <- fmt.Errorf("server write: %w", err)
			}
		}(server)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSMBIsLocalHost(t *testing.T) {
	for _, host := range []string{"", ".", "localhost", "LOCALHOST", "127.0.0.1", "::1"} {
		if !isSMBLocalHost(host) {
			t.Errorf("isSMBLocalHost(%q) = false, want true", host)
		}
	}
	if isSMBLocalHost("192.0.2.1") {
		t.Error("isSMBLocalHost(192.0.2.1) = true, want false")
	}
	if isSMBLocalHost("host.example.com") {
		t.Error("isSMBLocalHost(host.example.com) = true, want false")
	}
}

func TestSMBTransportSupportedOnWindows(t *testing.T) {
	srv := SMBTransport{}
	if !srv.Supported() {
		t.Fatal("SMBTransport.Supported() = false on Windows")
	}
	if !PeerDialable(smbTransportName, "mtls") {
		t.Fatal("PeerDialable(smb) = false on Windows")
	}
	if _, name, err := ResolvePeerTransport(smbTransportName, "mtls"); err != nil || name != smbTransportName {
		t.Fatalf("ResolvePeerTransport(smb) = (%q, %v), want (smb, nil)", name, err)
	}
}
