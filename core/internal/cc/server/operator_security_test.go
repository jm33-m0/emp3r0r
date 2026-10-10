package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
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

// TestWWWRelayRoutesToAgentOwner verifies a WWW relay opened by an agent is
// served by the operator that owns the agent, not by whichever operator happens
// to be online first, and that it is refused when the choice is ambiguous.
func TestWWWRelayRoutesToAgentOwner(t *testing.T) {
	const agentUUID = "www-agent-1"
	publishTestAgent(t, agentUUID, "wwwtag1")
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	t.Cleanup(func() {
		MarkOperatorOffline("op-a")
		MarkOperatorOffline("op-b")
		deleteAgentLock(agentUUID)
	})

	// Two operators online and no owner: the agent must not be able to pick one.
	if _, err := wwwRelayOperatorFor(agentUUID); err == nil {
		t.Fatal("www relay with two operators and no owner must be refused")
	}

	if acquired, _ := acquireAgentLock(agentUUID, "op-a", operatorDisplayName("op-a")); !acquired {
		t.Fatal("op-a failed to claim the agent")
	}
	owner, err := wwwRelayOperatorFor(agentUUID)
	if err != nil || owner != "op-a" {
		t.Fatalf("www relay owner = %q (err=%v), want op-a", owner, err)
	}

	// When the owner disconnects, only one operator remains, so the
	// single-operator fallback applies instead of breaking the transfer.
	MarkOperatorOffline("op-a")
	owner, err = wwwRelayOperatorFor(agentUUID)
	if err != nil || owner != "op-b" {
		t.Fatalf("www relay sole-operator fallback = %q (err=%v), want op-b", owner, err)
	}
}

// TestUnregisterFTPStreamOwnerChecked verifies that unregistering an FTP stream
// requires owning its token and that an unknown token cannot be used to delete
// an unrelated registry entry by supplying its key as a file path.
func TestUnregisterFTPStreamOwnerChecked(t *testing.T) {
	const token = "ftp-token-sec"
	network.FTPStreams.Store("token:"+token, &network.StreamHandler{Token: token, OperatorSession: "op-a"})
	network.FTPStreams.Store("/tmp/victim", &network.StreamHandler{Token: "victim", OperatorSession: "op-a"})
	t.Cleanup(func() {
		network.FTPStreams.Delete("token:" + token)
		network.FTPStreams.Delete("/tmp/victim")
	})

	// op-b must not remove op-a's stream.
	rec := httptest.NewRecorder()
	handleUnregisterFTPStream(rec, operatorHTTPRequest(t, "op-b", def.FTPStreamRequest{Token: token, FilePath: "/tmp/whatever"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unregister by non-owner = %d, want 403", rec.Code)
	}
	if _, ok := network.FTPStreams.Load("token:" + token); !ok {
		t.Fatal("non-owner must not remove the token")
	}

	// An unknown token must not let the caller delete an arbitrary entry.
	rec = httptest.NewRecorder()
	handleUnregisterFTPStream(rec, operatorHTTPRequest(t, "op-b", def.FTPStreamRequest{Token: "does-not-exist", FilePath: "/tmp/victim"}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unregister of unknown token = %d, want 404", rec.Code)
	}
	if _, ok := network.FTPStreams.Load("/tmp/victim"); !ok {
		t.Fatal("an unknown token must not delete an unrelated entry")
	}

	// The owner removes its own stream.
	rec = httptest.NewRecorder()
	handleUnregisterFTPStream(rec, operatorHTTPRequest(t, "op-a", def.FTPStreamRequest{Token: token, FilePath: "/tmp/victim"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("unregister by owner = %d, want 200", rec.Code)
	}
	if _, ok := network.FTPStreams.Load("token:" + token); ok {
		t.Fatal("owner unregister must remove the token")
	}
}

// TestIdleConfigServerManagedInMultiOperator verifies that a single operator
// cannot weaken the server-wide idle policy once more than one operator is
// provisioned.
func TestIdleConfigServerManagedInMultiOperator(t *testing.T) {
	registerOperators([]OperatorConfig{
		{Name: "operator-1", IP: "10.44.1.2"},
		{Name: "operator-2", IP: "10.44.1.3"},
	})
	t.Cleanup(func() {
		operatorIndex.Delete("10.44.1.2")
		operatorIndex.Delete("10.44.1.3")
	})
	setOperatorIdleTimeout(123)
	t.Cleanup(func() { setOperatorIdleTimeout(0) })

	rec := httptest.NewRecorder()
	handleUpdateOperatorIdleConfig(rec, operatorHTTPRequest(t, "op-a", def.OperatorIdleConfig{OperatorIdleTimeout: 0}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("idle config in multi-operator = %d, want 403", rec.Code)
	}
	if got := currentOperatorIdleTimeout(); got != 123 {
		t.Fatalf("idle timeout changed to %d, want 123 (unchanged)", got)
	}
}

// TestSocks5ListFilteredByOperator verifies an operator only sees its own
// pivots, not the other operators'.
func TestSocks5ListFilteredByOperator(t *testing.T) {
	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	const portA, portB = 9991, 9992
	socks5Proxies.mu.Lock()
	socks5Proxies.listeners[portA] = &socks5Listener{port: portA, owner: "op-a", ctx: ctxA, cancel: cancelA}
	socks5Proxies.listeners[portB] = &socks5Listener{port: portB, owner: "op-b", ctx: ctxB, cancel: cancelB}
	socks5Proxies.mu.Unlock()
	t.Cleanup(func() {
		cancelA()
		cancelB()
		socks5Proxies.mu.Lock()
		delete(socks5Proxies.listeners, portA)
		delete(socks5Proxies.listeners, portB)
		socks5Proxies.mu.Unlock()
	})

	got := ListSocks5ProxiesForOperator("op-a")
	if len(got) != 1 || got[0].Port != portA {
		t.Fatalf("op-a pivot list = %+v, want only port %d", got, portA)
	}
}

// TestCheckinRateLimiterBounded verifies the per-UUID rate limiter caps its
// stored timestamps and sweeps stale UUIDs, so an agent cannot grow server
// memory by flooding check-ins.
func TestCheckinRateLimiterBounded(t *testing.T) {
	const uuid = "rate-limit-uuid"
	rotationRateLimiter.Delete(uuid)
	rotationLimiterLastPurge.Store(0)
	t.Cleanup(func() {
		rotationRateLimiter.Delete(uuid)
		rotationLimiterLastPurge.Store(0)
	})

	now := time.Now()
	allowed := 0
	for i := 0; i < 100; i++ {
		if recordCheckinAttempt(uuid, now) {
			allowed++
		}
	}
	if allowed != checkinRateLimitWindow {
		t.Fatalf("allowed = %d, want %d", allowed, checkinRateLimitWindow)
	}
	val, ok := rotationRateLimiter.Load(uuid)
	if !ok {
		t.Fatal("rate limiter entry missing")
	}
	if got := len(val.([]time.Time)); got > checkinRateLimitWindow+1 {
		t.Fatalf("stored timestamps = %d, want <= %d", got, checkinRateLimitWindow+1)
	}

	// A UUID silent past the window is swept.
	const stale = "rate-limit-stale"
	rotationRateLimiter.Store(stale, []time.Time{now.Add(-2 * time.Minute)})
	rotationLimiterLastPurge.Store(0)
	purgeStaleRotationEntries(now)
	if _, ok := rotationRateLimiter.Load(stale); ok {
		t.Fatal("stale rate-limiter entry was not purged")
	}
}
