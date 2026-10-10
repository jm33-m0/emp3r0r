package server

// operator_flow_e2e_test.go drives the real operator API over its plain HTTP
// transport (bound to the userspace WireGuard stack in production; the test
// uses the host-network fallback) to verify stream ownership and the identity
// requirement.

import (
	"net/http"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// startOperatorAPIServer starts the real operator API server for a test and
// returns the port and a plain HTTP client.
func startOperatorAPIServer(t *testing.T) (int, *http.Client) {
	t.Helper()
	port := freeTCPPort(t)
	go StartOperatorServer(port)
	waitForTCP(t, port)
	t.Cleanup(func() {
		if network.OperatorServer != nil && network.OperatorServerCtx != nil {
			_ = network.OperatorServer.Shutdown(network.OperatorServerCtx)
		}
	})
	return port, operatorHTTPClient(t)
}

// TestFTPRegistrationOwnership verifies a stream is owned by the operator that
// registered it and that no other operator can unregister it.
func TestFTPRegistrationOwnership(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	t.Cleanup(func() {
		MarkOperatorOffline("op-a")
		MarkOperatorOffline("op-b")
	})

	port, httpClient := startOperatorAPIServer(t)

	const token = "ftp-owner"
	t.Cleanup(func() { network.FTPStreams.Delete("token:" + token) })
	body := def.FTPStreamRequest{Token: token, FilePath: "/tmp/" + token, ExpectedSize: 10, Checksum: "deadbeef"}

	if code := operatorPost(t, httpClient, port, "op-a", transport.OperatorRegisterFTPStream, body); code != http.StatusOK {
		t.Fatalf("op-a register = %d, want 200", code)
	}
	val, ok := network.FTPStreams.Load("token:" + token)
	if !ok {
		t.Fatal("token was not registered")
	}
	sh, ok := val.(*network.StreamHandler)
	if !ok || sh == nil {
		t.Fatal("registered stream is not a StreamHandler")
	}
	if sh.OperatorSession != "op-a" {
		t.Fatalf("stream owner = %q, want op-a", sh.OperatorSession)
	}

	// Another operator may not unregister the stream.
	if code := operatorPost(t, httpClient, port, "op-b", transport.OperatorUnregisterFTPStream, body); code != http.StatusForbidden {
		t.Fatalf("op-b unregister = %d, want 403", code)
	}
	if _, ok := network.FTPStreams.Load("token:" + token); !ok {
		t.Fatal("op-b removed op-a's stream")
	}

	// The owner can.
	if code := operatorPost(t, httpClient, port, "op-a", transport.OperatorUnregisterFTPStream, body); code != http.StatusOK {
		t.Fatalf("op-a unregister = %d, want 200", code)
	}
	if _, ok := network.FTPStreams.Load("token:" + token); ok {
		t.Fatal("op-a's stream was not removed")
	}
}

// TestOperatorAPIRequiresIdentity verifies an unidentified caller cannot
// register a stream.
func TestOperatorAPIRequiresIdentity(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)

	port, httpClient := startOperatorAPIServer(t)

	body := def.FTPStreamRequest{Token: "ftp-anon", FilePath: "/tmp/ftp-anon"}
	if code := operatorPost(t, httpClient, port, "", transport.OperatorRegisterFTPStream, body); code != http.StatusUnauthorized {
		t.Fatalf("anonymous register = %d, want 401", code)
	}
	if _, ok := network.FTPStreams.Load("token:ftp-anon"); ok {
		t.Fatal("unidentified caller registered a stream")
	}
}

// TestFTPRegistrationRequiresOnlineSession verifies a session header alone is
// not enough: the operator must have a live message tunnel.
func TestFTPRegistrationRequiresOnlineSession(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)

	port, httpClient := startOperatorAPIServer(t)

	body := def.FTPStreamRequest{Token: "ftp-offline", FilePath: "/tmp/ftp-offline"}
	if code := operatorPost(t, httpClient, port, "op-ghost", transport.OperatorRegisterFTPStream, body); code != http.StatusUnauthorized {
		t.Fatalf("offline session register = %d, want 401", code)
	}
}
