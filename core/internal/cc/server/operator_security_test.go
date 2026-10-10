package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestJobOwnerCannotBeReassigned verifies that one operator cannot redirect
// another operator's command output by reusing its job ID.
func TestJobOwnerCannotBeReassigned(t *testing.T) {
	const job = "sec-job-1"
	operatorJobOwners.Delete(job)
	t.Cleanup(func() { operatorJobOwners.Delete(job) })

	setJobOwner(job, "op-a")
	setJobOwner(job, "op-b")

	owner, ok := getJobOwner(job)
	if !ok || owner != "op-a" {
		t.Fatalf("job owner = %q (ok=%v), want op-a", owner, ok)
	}
}

// TestSignAgentRejectsNonUUID verifies the CA is not an arbitrary-content
// signing oracle: only a valid agent UUID is signed.
func TestSignAgentRejectsNonUUID(t *testing.T) {
	body, err := cbor.Marshal(def.SignRequest{Content: []byte("not-a-uuid")})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/operator/sign_agent", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("operator_session", "op-a")
	rec := httptest.NewRecorder()

	handleSignAgent(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-UUID sign request = %d, want 400", rec.Code)
	}
}

// TestForgetAgentDeniedWhenOwnedByAnother verifies an operator cannot delete an
// agent another operator is actively running.
func TestForgetAgentDeniedWhenOwnedByAnother(t *testing.T) {
	publishTestAgent(t, "uuid-forget-1", "forgettag1")
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	t.Cleanup(func() {
		MarkOperatorOffline("op-a")
		MarkOperatorOffline("op-b")
		deleteAgentLock("uuid-forget-1")
	})

	if acquired, _ := acquireAgentLock("uuid-forget-1", "op-a", operatorDisplayName("op-a")); !acquired {
		t.Fatal("op-a failed to claim the agent")
	}

	rec := httptest.NewRecorder()
	handleForgetAgent(rec, operatorHTTPRequest(t, "op-b", def.Operation{AgentTag: "uuid-forget-1"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("forget_agent by non-owner = %d, want 409", rec.Code)
	}
}

// TestValidateSocks5BindAddr verifies the pivot can only bind loopback or the
// C2's WireGuard address, never a public interface.
func TestValidateSocks5BindAddr(t *testing.T) {
	origServerIP := wireguard.WgServerIP
	wireguard.WgServerIP = "10.8.0.1"
	t.Cleanup(func() { wireguard.WgServerIP = origServerIP })

	for _, bad := range []string{"0.0.0.0", "1.2.3.4", "8.8.8.8", "::"} {
		if _, err := validateSocks5BindAddr(bad); err == nil {
			t.Errorf("bind %q must be rejected", bad)
		}
	}
	for _, good := range []string{"", "127.0.0.1", "localhost", "10.8.0.1"} {
		if _, err := validateSocks5BindAddr(good); err != nil {
			t.Errorf("bind %q must be allowed: %v", good, err)
		}
	}
}

// TestStopSocks5ProxyOwnership verifies one operator cannot tear down another
// operator's SOCKS5 pivot.
func TestStopSocks5ProxyOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	const port = 9999
	ls := &socks5Listener{port: port, owner: "op-a", ctx: ctx, cancel: cancel}
	socks5Proxies.mu.Lock()
	socks5Proxies.listeners[port] = ls
	socks5Proxies.mu.Unlock()
	t.Cleanup(func() {
		socks5Proxies.mu.Lock()
		delete(socks5Proxies.listeners, port)
		socks5Proxies.mu.Unlock()
	})

	if err := StopSocks5Proxy(port, "op-b"); err == nil {
		t.Fatal("op-b must not stop op-a's SOCKS5 pivot")
	}
	if err := StopSocks5Proxy(port, "op-a"); err != nil {
		t.Fatalf("op-a should stop its own pivot: %v", err)
	}
}
