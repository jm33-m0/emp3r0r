package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// operatorHTTPRequest builds a POST request carrying a CBOR body and an
// operator session header. The remote address is deliberately outside any
// provisioned WG subnet so identity falls back to the header, exactly like
// local mode and tests.
func operatorHTTPRequest(t *testing.T, session string, body any) *http.Request {
	t.Helper()
	raw, err := cbor.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/operator/set_active_agent", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.9:40000"
	if session != "" {
		req.Header.Set("operator_session", session)
	}
	return req
}

func publishTestAgent(t *testing.T, uuid, tag string) *def.Emp3r0rAgent {
	t.Helper()
	agent := &def.Emp3r0rAgent{UUID: uuid, Tag: tag, Name: "agent-" + tag}
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0}})
	t.Cleanup(func() { live.ForgetAgent(uuid) })
	return agent
}

// TestAgentLockSingleLiveOwner verifies that a second operator cannot take an
// agent while its owner is still connected.
func TestAgentLockSingleLiveOwner(t *testing.T) {
	const agentUUID = "lock-agent-1"
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	defer MarkOperatorOffline("op-a")
	defer MarkOperatorOffline("op-b")
	defer deleteAgentLock(agentUUID)

	if acquired, held := acquireAgentLock(agentUUID, "op-a", "operator-a"); !acquired {
		t.Fatalf("op-a failed to acquire a free agent: held by %q", held)
	}
	if acquired, held := acquireAgentLock(agentUUID, "op-b", "operator-b"); acquired {
		t.Fatal("op-b acquired an agent already held by a live operator")
	} else if held != "operator-a" {
		t.Fatalf("conflict reported owner %q, want operator-a", held)
	}
	if owner := agentLockOwner(agentUUID); owner != "operator-a" {
		t.Fatalf("agentLockOwner = %q, want operator-a", owner)
	}
}

// TestAgentLockReleasedOnOwnerSwitchOrDisconnect verifies the two release
// paths: an explicit operator release (target switch) and session teardown.
func TestAgentLockReleasedOnOwnerSwitchOrDisconnect(t *testing.T) {
	const agentUUID = "lock-agent-2"
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	defer MarkOperatorOffline("op-a")
	defer MarkOperatorOffline("op-b")
	defer deleteAgentLock(agentUUID)

	if acquired, _ := acquireAgentLock(agentUUID, "op-a", "operator-a"); !acquired {
		t.Fatal("op-a failed to acquire")
	}
	// Target switch: release all of op-a's locks.
	releaseAgentLocksForOperator("op-a")
	if owner := agentLockOwner(agentUUID); owner != "" {
		t.Fatalf("agent still held by %q after operator switch", owner)
	}
	if acquired, _ := acquireAgentLock(agentUUID, "op-b", "operator-b"); !acquired {
		t.Fatal("op-b could not acquire after op-a switched")
	}

	// Disconnect: op-b goes offline and its lock is no longer reclaimable by it.
	MarkOperatorOffline("op-b")
	if acquired, _ := acquireAgentLock(agentUUID, "op-a", "operator-a"); !acquired {
		t.Fatal("op-a could not reclaim an agent whose owner disconnected")
	}
}

// TestAgentLockRenewalKeepsSince verifies that re-acquiring by the same owner is
// a renewal, not a new conflict or a reset of the original claim time.
func TestAgentLockRenewalKeepsSince(t *testing.T) {
	const agentUUID = "lock-agent-3"
	MarkOperatorOnline("op-a")
	defer MarkOperatorOffline("op-a")
	defer deleteAgentLock(agentUUID)

	if acquired, _ := acquireAgentLock(agentUUID, "op-a", "operator-a"); !acquired {
		t.Fatal("first acquire failed")
	}
	first, ok := agentLocks.Load(agentUUID)
	if !ok {
		t.Fatal("lock not stored")
	}
	since := first.(*agentLock).Since

	if acquired, _ := acquireAgentLock(agentUUID, "op-a", "operator-a"); !acquired {
		t.Fatal("renewal by same owner failed")
	}
	renewed, ok := agentLocks.Load(agentUUID)
	if !ok {
		t.Fatal("lock missing after renewal")
	}
	if !renewed.(*agentLock).Since.Equal(since) {
		t.Fatalf("renewal reset Since: got %v, want %v", renewed.(*agentLock).Since, since)
	}
}

// TestSetActiveAgentConflictReturns409 exercises the real handler: operator A
// claims an agent, operator B is refused with a conflict, and B succeeds after A
// switches away.
func TestSetActiveAgentConflictReturns409(t *testing.T) {
	publishTestAgent(t, "uuid-target-1", "targettag1")
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	defer MarkOperatorOffline("op-a")
	defer MarkOperatorOffline("op-b")
	defer deleteAgentLock("uuid-target-1")

	// A claims the agent.
	recA := httptest.NewRecorder()
	handleSetActiveAgent(recA, operatorHTTPRequest(t, "op-a", def.Operation{AgentTag: "targettag1"}))
	if recA.Code != http.StatusOK {
		t.Fatalf("op-a set_active_agent = %d, body %q", recA.Code, recA.Body.String())
	}

	// B is refused while A holds it.
	recB := httptest.NewRecorder()
	handleSetActiveAgent(recB, operatorHTTPRequest(t, "op-b", def.Operation{AgentTag: "targettag1"}))
	if recB.Code != http.StatusConflict {
		t.Fatalf("op-b set_active_agent = %d, want 409 (body %q)", recB.Code, recB.Body.String())
	}

	// A switches away, then B can claim it.
	releaseAgentLocksForOperator("op-a")
	recB2 := httptest.NewRecorder()
	handleSetActiveAgent(recB2, operatorHTTPRequest(t, "op-b", def.Operation{AgentTag: "targettag1"}))
	if recB2.Code != http.StatusOK {
		t.Fatalf("op-b set_active_agent after switch = %d, body %q", recB2.Code, recB2.Body.String())
	}

	// The response advertises the new owner so the console can show it.
	var snapshot def.Emp3r0rAgent
	if err := cbor.Unmarshal(recB2.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode set_active_agent response: %v", err)
	}
	if snapshot.Owner != "op-b" {
		t.Fatalf("snapshot owner = %q, want op-b", snapshot.Owner)
	}
}

// TestOperatorIdentityPrefersWireGuardIP verifies that a provisioned WG peer is
// identified by its provisioned identity rather than the client header, and
// that unknown peers fall back to the header.
func TestOperatorIdentityPrefersWireGuardIP(t *testing.T) {
	configs := []OperatorConfig{
		{Name: "operator-1", IP: "10.44.0.2"},
		{Name: "operator-2", IP: "10.44.0.3"},
	}
	registerOperators(configs)
	defer operatorIndex.Delete("10.44.0.2")
	defer operatorIndex.Delete("10.44.0.3")

	if got := operatorIDFromRemote("10.44.0.2:5555"); got != "10.44.0.2" {
		t.Fatalf("operatorIDFromRemote = %q, want the provisioned IP", got)
	}
	if got := operatorRequestIdentity("10.44.0.3:5555", "spoofed"); got != "10.44.0.3" {
		t.Fatalf("operatorRequestIdentity = %q, want the provisioned IP to win over the header", got)
	}
	if got := operatorRequestIdentity("203.0.113.1:5555", "fallback"); got != "fallback" {
		t.Fatalf("operatorRequestIdentity fallback = %q, want fallback", got)
	}
	if got := operatorDisplayName("10.44.0.2"); got != "operator-1" {
		t.Fatalf("operatorDisplayName = %q, want operator-1", got)
	}
}

// TestFailedSwitchKeepsPreviousTarget verifies that a rejected target switch
// does not drop the operator's existing claim.
func TestFailedSwitchKeepsPreviousTarget(t *testing.T) {
	publishTestAgent(t, "uuid-switch-1", "switchtag1")
	publishTestAgent(t, "uuid-switch-2", "switchtag2")
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	defer MarkOperatorOffline("op-a")
	defer MarkOperatorOffline("op-b")
	defer deleteAgentLock("uuid-switch-1")
	defer deleteAgentLock("uuid-switch-2")

	// A claims agent 1, B claims agent 2.
	rec := httptest.NewRecorder()
	handleSetActiveAgent(rec, operatorHTTPRequest(t, "op-a", def.Operation{AgentTag: "switchtag1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("op-a could not claim agent 1: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handleSetActiveAgent(rec, operatorHTTPRequest(t, "op-b", def.Operation{AgentTag: "switchtag2"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("op-b could not claim agent 2: %d %s", rec.Code, rec.Body.String())
	}

	// A tries to steal agent 2 and is refused. A must still own agent 1.
	rec = httptest.NewRecorder()
	handleSetActiveAgent(rec, operatorHTTPRequest(t, "op-a", def.Operation{AgentTag: "switchtag2"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("op-a steal attempt = %d, want 409", rec.Code)
	}
	if owner := agentLockOwner("uuid-switch-1"); owner != "op-a" {
		t.Fatalf("agent 1 owner after failed switch = %q, want op-a", owner)
	}
	if owner := agentLockOwner("uuid-switch-2"); owner != "op-b" {
		t.Fatalf("agent 2 owner = %q, want op-b", owner)
	}
}

// TestSendCommandRefusedWhenLockedByOther verifies that commands, not just
// targeting, honour the owner lock.
func TestSendCommandRefusedWhenLockedByOther(t *testing.T) {
	publishTestAgent(t, "uuid-cmd-1", "cmdtag1")
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	defer MarkOperatorOffline("op-a")
	defer MarkOperatorOffline("op-b")
	defer deleteAgentLock("uuid-cmd-1")

	rec := httptest.NewRecorder()
	handleSetActiveAgent(rec, operatorHTTPRequest(t, "op-a", def.Operation{AgentTag: "cmdtag1"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("op-a claim failed: %d %s", rec.Code, rec.Body.String())
	}

	jobID := "job-locked"
	command := "id"
	rec = httptest.NewRecorder()
	handleSendCommand(rec, operatorHTTPRequest(t, "op-b", def.Operation{
		AgentTag: "cmdtag1",
		Action:   "command",
		Command:  &command,
		JobID:    &jobID,
	}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("op-b send_command = %d, want 409 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestOperatorHandlersRequireIdentity verifies that an unauthenticated operator
// request cannot target or command an agent.
func TestOperatorHandlersRequireIdentity(t *testing.T) {
	publishTestAgent(t, "uuid-noident", "noidenttag")

	rec := httptest.NewRecorder()
	handleSetActiveAgent(rec, operatorHTTPRequest(t, "", def.Operation{AgentTag: "noidenttag"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("set_active_agent without identity = %d, want 401", rec.Code)
	}

	jobID := "job-noident"
	command := "id"
	rec = httptest.NewRecorder()
	handleSendCommand(rec, operatorHTTPRequest(t, "", def.Operation{
		AgentTag: "noidenttag",
		Action:   "command",
		Command:  &command,
		JobID:    &jobID,
	}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("send_command without identity = %d, want 401", rec.Code)
	}
}
