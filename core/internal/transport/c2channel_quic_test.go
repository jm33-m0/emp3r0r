//go:build with_quic

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestQUICStaticKey pins the key derivation contract: obfuscation is on by
// default and deterministic, the explicit QUICKey wins over MagicString, and
// the standard-key opt-out disables the transform entirely.
func TestQUICStaticKey(t *testing.T) {
	oldKey, oldMagic := def.QUICKey, def.MagicString
	t.Cleanup(func() {
		def.QUICKey = oldKey
		def.MagicString = oldMagic
		SetQUICStandardKey(false)
	})

	SetQUICStandardKey(false)
	def.QUICKey = ""
	def.MagicString = "seed-a"
	ka := QUICStaticKey()
	if len(ka) != 32 {
		t.Fatalf("QUICStaticKey length = %d, want 32", len(ka))
	}
	if !bytes.Equal(ka, QUICStaticKey()) {
		t.Fatal("QUICStaticKey is not deterministic")
	}

	def.MagicString = "seed-b"
	kb := QUICStaticKey()
	if bytes.Equal(ka, kb) {
		t.Fatal("different MagicString seeds produced the same key")
	}

	def.QUICKey = "explicit-seed"
	kc := QUICStaticKey()
	if bytes.Equal(kc, kb) {
		t.Fatal("explicit QUICKey did not override MagicString")
	}

	SetQUICStandardKey(true)
	if got := QUICStaticKey(); got != nil {
		t.Fatalf("standard-key mode returned a key: %x", got)
	}
}

// TestQUICObfuscatorRoundTrip verifies the transform is reversible, adds only
// the salt, randomizes equal plaintexts, and rejects datagrams without a salt.
func TestQUICObfuscatorRoundTrip(t *testing.T) {
	psk := bytes.Repeat([]byte{0x5a}, 32)
	ob := newQUICObfuscator(psk)
	plain := bytes.Repeat([]byte("probe-payload"), 200)

	wire := ob.obfuscate(nil, plain)
	if len(wire) != len(plain)+quicObfsSaltLen {
		t.Fatalf("wire length = %d, want %d", len(wire), len(plain)+quicObfsSaltLen)
	}
	if bytes.Equal(wire[quicObfsSaltLen:], plain) {
		t.Fatal("payload was not obfuscated")
	}
	got := ob.deobfuscate(nil, wire)
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %d bytes", len(got))
	}

	// A destination too small must still decode via the returned slice.
	if small := ob.deobfuscate(make([]byte, 1), wire); !bytes.Equal(small, plain) {
		t.Fatalf("small-destination round trip mismatch: got %d bytes", len(small))
	}

	// The random salt must make equal plaintexts produce different wire bytes.
	if bytes.Equal(ob.obfuscate(nil, plain), wire) {
		t.Fatal("obfuscation reused the same salt")
	}

	// A datagram too short to carry a salt must be rejected, not mis-parsed.
	if ob.deobfuscate(nil, []byte{1, 2, 3, 4}) != nil {
		t.Fatal("short datagram should be rejected")
	}
}

// TestQUICTransportRoundTrip exercises the real QUIC listener and dialer over a
// self-signed CA, in both obfuscated and standard modes.
func TestQUICTransportRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name     string
		standard bool
	}{
		{"custom-key", false},
		{"standard-key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetQUICStandardKey(tc.standard)
			t.Cleanup(func() { SetQUICStandardKey(false) })

			listener, addr := startTestQUICListener(t)
			t.Cleanup(func() { _ = listener.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			key := QUICStaticKey()
			clientErr := make(chan error, 1)
			go func() {
				stream, err := dialQUIC(ctx, "https://"+addr, key)
				if err != nil {
					clientErr <- fmt.Errorf("dial: %w", err)
					return
				}
				defer stream.Close()
				msg := []byte("ping-from-agent")
				if _, err := stream.Write(msg); err != nil {
					clientErr <- fmt.Errorf("client write: %w", err)
					return
				}
				buf := make([]byte, len(msg))
				if _, err := io.ReadFull(stream, buf); err != nil {
					clientErr <- fmt.Errorf("client read: %w", err)
					return
				}
				if !bytes.Equal(buf, msg) {
					clientErr <- fmt.Errorf("echo mismatch: %q", buf)
					return
				}
				clientErr <- nil
			}()

			serverStream, err := listener.AcceptStream(ctx)
			if err != nil {
				t.Fatalf("accept stream: %v", err)
			}
			defer serverStream.Close()
			buf := make([]byte, len("ping-from-agent"))
			if _, err := io.ReadFull(serverStream, buf); err != nil {
				t.Fatalf("server read: %v", err)
			}
			if _, err := serverStream.Write(buf); err != nil {
				t.Fatalf("server write: %v", err)
			}
			if err := <-clientErr; err != nil {
				t.Fatalf("client: %v", err)
			}
		})
	}
}

// TestQUICMismatchedKeyFails proves the obfuscation boundary is real: a
// custom-key client cannot complete a handshake with a standard-key listener.
func TestQUICMismatchedKeyFails(t *testing.T) {
	SetQUICStandardKey(true)
	listener, addr := startTestQUICListener(t)
	t.Cleanup(func() {
		_ = listener.Close()
		SetQUICStandardKey(false)
	})

	SetQUICStandardKey(false) // client obfuscates, server does not
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dialQUIC(ctx, "https://"+addr, QUICStaticKey()); err == nil {
		t.Fatal("obfuscated client unexpectedly handshook with a standard-key listener")
	}
}

// TestQUICChannelWrapperRegistered verifies the agent-facing wrapper is
// registered under the quic mode and dials without an http.Client.
func TestQUICChannelWrapperRegistered(t *testing.T) {
	wrapper, err := GetC2ChannelWrapper(def.C2ChannelModeQUIC)
	if err != nil {
		t.Fatalf("GetC2ChannelWrapper(quic): %v", err)
	}

	SetQUICStandardKey(false)
	t.Cleanup(func() { SetQUICStandardKey(false) })
	listener, addr := startTestQUICListener(t)
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)
	go func() {
		rw, resp, err := wrapper.Dial(ctx, nil, "https://"+addr)
		if err != nil {
			clientErr <- fmt.Errorf("wrapper dial: %w", err)
			return
		}
		if resp != nil {
			clientErr <- fmt.Errorf("unexpected http response from quic wrapper")
			return
		}
		defer rw.Close()
		if _, err := rw.Write([]byte("auth-envelope")); err != nil {
			clientErr <- err
			return
		}
		buf := make([]byte, len("auth-envelope"))
		if _, err := io.ReadFull(rw, buf); err != nil {
			clientErr <- err
			return
		}
		clientErr <- nil
	}()

	serverStream, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	defer serverStream.Close()
	buf := make([]byte, len("auth-envelope"))
	if _, err := io.ReadFull(serverStream, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if _, err := serverStream.Write(buf); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func startTestQUICListener(t *testing.T) (*QUICListener, string) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca-cert.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	if _, err := GenCerts(nil, caCert, caKey, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	serverCert := filepath.Join(dir, "server-cert.pem")
	serverKey := filepath.Join(dir, "server-key.pem")
	if _, err := GenCerts([]string{"127.0.0.1"}, serverCert, serverKey, caKey, caCert, false); err != nil {
		t.Fatalf("GenCerts server: %v", err)
	}
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}

	oldPEM := GetCACrtPEM()
	SetCACrtPEM(caPEM)
	SetC2ServerName("")
	t.Cleanup(func() {
		SetCACrtPEM(oldPEM)
		SetC2ServerName("")
	})

	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{QUICALPN},
		MinVersion:   tls.VersionTLS13,
	}
	listener, err := ListenQUIC("127.0.0.1:0", tlsCfg, QUICStaticKey())
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	return listener, listener.Addr().String()
}
