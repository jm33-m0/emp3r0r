package server

// operator_flow_e2e_test.go exercises the real operator API over mTLS with
// genuinely signed operator claims. The earlier security tests built claims by
// hand and never ran them through the server's verification, so a clock-skew
// bug in claim validation (which rejected every FTP registration when the
// operator and C2 clocks differed) slipped through. These tests drive the real
// handler over a real TLS connection instead.

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// signOperatorClaim builds a real, signed operator stream claim with the
// operator client identity provisioned in dir, exactly like the operator
// console does. Timestamps are supplied by the caller so tests can simulate
// operator/server clock skew.
func signOperatorClaim(t *testing.T, dir, session, streamID, capability string, issuedAt, expiresAt int64) *def.OperatorStreamClaim {
	t.Helper()
	claim := &def.OperatorStreamClaim{
		OperatorSession: session,
		StreamID:        streamID,
		Capability:      capability,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		Nonce:           uuid.NewString(),
	}
	priv, err := transport.ParseKeyPemFile(filepath.Join(dir, "operator-client-key.pem"))
	if err != nil {
		t.Fatalf("parse operator client key: %v", err)
	}
	sig, err := transport.SignECDSA([]byte(transport.CanonicalOperatorStreamClaimString(claim)), priv)
	if err != nil {
		t.Fatalf("sign operator claim: %v", err)
	}
	claim.Signature = sig
	return claim
}

// startOperatorAPIServer starts the real operator mTLS API server for a test
// and returns the port and an mTLS client.
func startOperatorAPIServer(t *testing.T, serverDir string) (int, *http.Client) {
	t.Helper()
	port := freeTCPPort(t)
	go StartOperatorMTLSServer(port)
	waitForTCP(t, port)
	t.Cleanup(func() {
		if network.MTLSServer != nil && network.MTLSServerCtx != nil {
			_ = network.MTLSServer.Shutdown(network.MTLSServerCtx)
		}
	})
	return port, operatorHTTPClient(t, serverDir)
}

// TestFTPRegistrationToleratesClockSkew is the regression test for the FTP
// registration failure that broke every transfer as soon as the operator and C2
// clocks disagreed. The claim's own TTL is skew-independent, and the absolute
// window is only a sanity bound backed by the server-side nonce cache.
func TestFTPRegistrationToleratesClockSkew(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)
	MarkOperatorOnline("op-a")
	t.Cleanup(func() { MarkOperatorOffline("op-a") })

	port, httpClient := startOperatorAPIServer(t, serverDir)

	now := time.Now().Unix()
	cases := []struct {
		name                string
		issuedAt, expiresAt int64
	}{
		{"synced clocks", now, now + 120},
		{"operator clock ahead", now + 240, now + 360},
		{"operator clock behind", now - 240, now - 120},
	}
	for i, tc := range cases {
		token := fmt.Sprintf("ftp-skew-%d", i)
		claim := signOperatorClaim(t, serverDir, "op-a", token, def.OperatorCapabilityRegisterFTP, tc.issuedAt, tc.expiresAt)
		code := operatorPost(t, httpClient, port, "op-a", transport.OperatorRegisterFTPStream, def.FTPStreamRequest{
			Token: token, FilePath: "/tmp/" + token, Claim: claim,
		})
		if code != http.StatusOK {
			t.Fatalf("%s: register = %d, want 200", tc.name, code)
		}
		if _, ok := network.FTPStreams.Load("token:" + token); !ok {
			t.Fatalf("%s: token was not registered", tc.name)
		}
		network.FTPStreams.Delete("token:" + token)
	}
}

// TestFTPRegistrationRejectsReplayedClaim verifies a captured claim cannot be
// replayed: the nonce is single-use even though the signature stays valid.
func TestFTPRegistrationRejectsReplayedClaim(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)
	MarkOperatorOnline("op-a")
	t.Cleanup(func() { MarkOperatorOffline("op-a") })

	port, httpClient := startOperatorAPIServer(t, serverDir)

	now := time.Now().Unix()
	const token = "ftp-replay"
	claim := signOperatorClaim(t, serverDir, "op-a", token, def.OperatorCapabilityRegisterFTP, now, now+120)
	body := def.FTPStreamRequest{Token: token, FilePath: "/tmp/" + token, Claim: claim}
	t.Cleanup(func() { network.FTPStreams.Delete("token:" + token) })

	if code := operatorPost(t, httpClient, port, "op-a", transport.OperatorRegisterFTPStream, body); code != http.StatusOK {
		t.Fatalf("first register = %d, want 200", code)
	}
	if code := operatorPost(t, httpClient, port, "op-a", transport.OperatorRegisterFTPStream, body); code != http.StatusUnauthorized {
		t.Fatalf("replayed register = %d, want 401", code)
	}
}

// TestFTPRegistrationRejectsOversizedTTL verifies the claim's own TTL is still
// bounded, so the skew tolerance cannot be abused for an unbounded-validity
// claim.
func TestFTPRegistrationRejectsOversizedTTL(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)
	MarkOperatorOnline("op-a")
	t.Cleanup(func() { MarkOperatorOffline("op-a") })

	port, httpClient := startOperatorAPIServer(t, serverDir)

	now := time.Now().Unix()
	const token = "ftp-long-ttl"
	claim := signOperatorClaim(t, serverDir, "op-a", token, def.OperatorCapabilityRegisterFTP, now, now+3600)
	code := operatorPost(t, httpClient, port, "op-a", transport.OperatorRegisterFTPStream, def.FTPStreamRequest{
		Token: token, FilePath: "/tmp/" + token, Claim: claim,
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("oversized-ttl register = %d, want 401", code)
	}
}
