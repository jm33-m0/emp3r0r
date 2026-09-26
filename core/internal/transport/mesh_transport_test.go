package transport

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestCamouflageMTLSSendsNoSNI verifies the mesh mTLS client sends no SNI:
// internal peers have no domain names and a name here would be a fingerprint.
// The configured camouflage CN still names the ephemeral certificate only.
func TestCamouflageMTLSSendsNoSNI(t *testing.T) {
	const cn = "svc.mesh.local"
	SetMeshCamouflageIdentity("", cn)
	t.Cleanup(func() { SetMeshCamouflageIdentity("", "") })

	serverCert, err := GenerateEphemeralCert("", cn)
	if err != nil {
		t.Fatalf("GenerateEphemeralCert: %v", err)
	}

	sniCh := make(chan string, 1)
	conf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniCh <- chi.ServerName:
			default:
			}
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// tls.Listener.Accept is lazy: the server side must drive Handshake()
	// before the ClientHello callback fires.
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c.(*tls.Conn); ok {
			if err := tc.Handshake(); err != nil {
				return
			}
		}
		srvCh <- c
	}()

	conn, err := (CamouflageMTLS{}).Dial(ln.Addr().String(), "password", "salt")
	if err != nil {
		t.Fatalf("CamouflageMTLS.Dial: %v", err)
	}
	defer conn.Close()

	select {
	case sc := <-srvCh:
		defer sc.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("server never finished the handshake")
	}

	select {
	case sni := <-sniCh:
		if sni != "" {
			t.Fatalf("mesh mTLS sent SNI %q, want none", sni)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never observed a ClientHello")
	}
}

// TestC2ServerNames pins the C2 SNI/verification mapping: with no override the
// SNI is the C2 host; with an override the cover name is sent as SNI while the
// certificate is still verified against the real C2 host.
func TestC2ServerNames(t *testing.T) {
	t.Cleanup(func() { SetC2ServerName("") })

	SetC2ServerName("")
	sni, verify := c2ServerNames("203.0.113.9")
	if sni != "203.0.113.9" || verify != "" {
		t.Fatalf("default: sni=%q verify=%q, want %q and empty", sni, verify, "203.0.113.9")
	}

	SetC2ServerName("cdn.example.net")
	sni, verify = c2ServerNames("203.0.113.9")
	if sni != "cdn.example.net" || verify != "203.0.113.9" {
		t.Fatalf("override: sni=%q verify=%q, want cover name and real host", sni, verify)
	}
}
