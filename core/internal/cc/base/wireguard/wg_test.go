package wireguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// freeUDPPort reserves a loopback UDP port and releases it. The WireGuard
// transport needs a concrete port to expose to the peer.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// TestUserspaceTunnelRoundTrip brings up two userspace WireGuard devices that
// talk to each other over loopback and verifies TCP traffic flows through the
// gVisor stack. It asserts that the tunnel works with no OS interface and no
// elevated privileges.
func TestUserspaceTunnelRoundTrip(t *testing.T) {
	serverPort := freeUDPPort(t)
	clientPort := freeUDPPort(t)

	serverKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	clientKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	serverPub, err := PublicKeyFromPrivate(serverKey)
	if err != nil {
		t.Fatalf("derive server public key: %v", err)
	}
	clientPub, err := PublicKeyFromPrivate(clientKey)
	if err != nil {
		t.Fatalf("derive client public key: %v", err)
	}

	server, err := CreateWireGuardDevice(WireGuardConfig{
		InterfaceName: "wg-test-server",
		IPAddress:     "10.88.0.1/24",
		PrivateKey:    serverKey,
		ListenPort:    serverPort,
		Peers: []PeerConfig{{
			PublicKey:  clientPub,
			AllowedIPs: "10.88.0.2/32",
		}},
	})
	if err != nil {
		t.Fatalf("create server device: %v", err)
	}
	defer server.Close()

	client, err := CreateWireGuardDevice(WireGuardConfig{
		InterfaceName: "wg-test-client",
		IPAddress:     "10.88.0.2/24",
		PrivateKey:    clientKey,
		ListenPort:    clientPort,
		Peers: []PeerConfig{{
			PublicKey:  serverPub,
			AllowedIPs: "10.88.0.1/32",
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		}},
	})
	if err != nil {
		t.Fatalf("create client device: %v", err)
	}
	defer client.Close()

	if !client.Contains("10.88.0.1:80") {
		t.Fatal("client should classify the peer address as part of the tunnel")
	}
	if client.Contains("203.0.113.1:80") {
		t.Fatal("client must not classify a public address as part of the tunnel")
	}

	ln, err := server.Listen("tcp", "10.88.0.1:0")
	if err != nil {
		t.Fatalf("listen on server tunnel: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, len("ping"))
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				_, _ = conn.Write(buf)
			}(conn)
		}
	}()

	target := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The WireGuard handshake is lazy, so the first dials may fail while the
	// peers negotiate. Retry until the context deadline.
	var conn net.Conn
	for {
		conn, err = client.DialContext(ctx, "tcp", target)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("dial through userspace tunnel: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	buf := make([]byte, len("ping"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo through tunnel: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected echo: %q", buf)
	}

	if err := client.ConfigureWireGuardDevice(nil); err != nil {
		t.Fatalf("reconfigure device with no peers: %v", err)
	}
}

func TestCreateWireGuardDeviceRejectsInvalidAddress(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := CreateWireGuardDevice(WireGuardConfig{
		IPAddress:  "not-an-address",
		PrivateKey: key,
	}); err == nil {
		t.Fatal("expected invalid tunnel address to be rejected")
	}
}

func TestBuildUAPIConfigValidatesInput(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := PublicKeyFromPrivate(key)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}

	uapi, err := buildUAPIConfig(key, 51820, []PeerConfig{{
		PublicKey:  pub,
		AllowedIPs: "10.0.0.0/24, 10.0.1.0/24",
		Endpoint:   "127.0.0.1:51820",
	}})
	if err != nil {
		t.Fatalf("build UAPI config: %v", err)
	}
	for _, want := range []string{"private_key=", "listen_port=51820", "public_key=", "allowed_ip=10.0.0.0/24", "allowed_ip=10.0.1.0/24", "endpoint=127.0.0.1:51820", "persistent_keepalive_interval=25"} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("UAPI config missing %q:\n%s", want, uapi)
		}
	}

	if _, err := buildUAPIConfig(key, 0, []PeerConfig{{PublicKey: "bad-key", AllowedIPs: "10.0.0.0/24"}}); err == nil {
		t.Fatal("expected invalid peer key to be rejected")
	}
	if _, err := buildUAPIConfig(key, 0, []PeerConfig{{PublicKey: pub, AllowedIPs: "not-a-cidr"}}); err == nil {
		t.Fatal("expected invalid allowed IP to be rejected")
	}
}
