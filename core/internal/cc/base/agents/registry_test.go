package agents

import (
	"net"
	"sync"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// newAgent builds a minimal agent for registry tests.
func newAgent(uuid, tag string) *def.Emp3r0rAgent {
	return &def.Emp3r0rAgent{UUID: uuid, Tag: tag, Hostname: tag + ".example"}
}

// clearRegistry gives each test a clean global registry and restores the active
// agent selection afterwards.
func clearRegistry(t *testing.T) {
	t.Helper()
	live.ClearAgents()
	prevActive := live.GetActiveAgent()
	live.SetActiveAgent(nil)
	t.Cleanup(func() {
		live.ClearAgents()
		live.SetActiveAgent(prevActive)
	})
}

// TestRegistrySingleLookupSurface is the regression test for the former split
// registries: AgentControlMap (server) and AgentList (operator) had to be
// probed separately, so a record present in only one of them could be visible
// to some lookups and invisible to others. Every lookup must now observe the
// same single registry record.
func TestRegistrySingleLookupSurface(t *testing.T) {
	clearRegistry(t)

	conn := &stubConn{}
	agent := newAgent("uuid-single", "tag-single")
	live.PublishAgent(&live.AgentRecord{
		Agent:   agent,
		Control: &live.AgentControl{Index: 4, Conn: conn},
		Label:   "prod",
	})

	if got := GetConnectedAgents(); len(got) != 1 || got[0].UUID != agent.UUID {
		t.Fatalf("GetConnectedAgents = %+v, want exactly the published agent", got)
	}
	if got := GetAgentByTag(agent.Tag); got == nil || got.UUID != agent.UUID {
		t.Fatalf("GetAgentByTag(%q) = %+v, want the published agent", agent.Tag, got)
	}
	if got := GetAgentByUUID(agent.UUID); got == nil || got.Tag != agent.Tag {
		t.Fatalf("GetAgentByUUID(%q) = %+v, want the published agent", agent.UUID, got)
	}
	if got := GetAgentByIndex(4); got == nil || got.UUID != agent.UUID {
		t.Fatalf("GetAgentByIndex(4) = %+v, want the published agent", got)
	}
	if !IsAgentExistByUUID(agent.UUID) || !IsAgentExistByTag(agent.Tag) || !IsAgentExist(agent) {
		t.Fatal("IsAgentExist* reported a published agent as missing")
	}
	if a, ctrl, found := RuntimeControlByUUID(agent.UUID); !found || a.UUID != agent.UUID || ctrl == nil {
		t.Fatalf("RuntimeControlByUUID(%q) = %v/%v/%v, want the published record", agent.UUID, a, ctrl, found)
	}
	if a, ctrl, found := RuntimeControlByConn(conn); !found || a.UUID != agent.UUID || ctrl == nil {
		t.Fatalf("RuntimeControlByConn = %v/%v/%v, want the published record", a, ctrl, found)
	}

	// Labels are part of the single record, so a refresh must preserve them.
	if rec, ok := live.LookupAgent(agent.UUID); !ok || rec.Label != "prod" {
		t.Fatalf("published label lost: %+v", rec)
	}
}

// TestRegistryUpsertDoesNotDuplicate pins the anti-drift fix: publishing a
// re-check-in for the same UUID must update the existing entry in place rather
// than leaving a stale, pointer-keyed duplicate behind.
func TestRegistryUpsertDoesNotDuplicate(t *testing.T) {
	clearRegistry(t)

	first := newAgent("uuid-upsert", "old-tag")
	live.PublishAgent(&live.AgentRecord{
		Agent:   first,
		Control: &live.AgentControl{Index: 7},
		Label:   "keep-me",
	})

	// Re-check-in publishes a new agent object (as the server does) with the
	// same UUID but refreshed metadata.
	second := newAgent("uuid-upsert", "new-tag")
	rec, _ := live.LookupAgent(second.UUID)
	live.PublishAgent(&live.AgentRecord{Agent: second, Control: rec.Control, Label: rec.Label})

	list := GetConnectedAgents()
	if len(list) != 1 {
		t.Fatalf("registry holds %d entries after re-check-in, want 1", len(list))
	}
	if list[0].Tag != "new-tag" {
		t.Fatalf("registry entry tag = %q, want refreshed %q", list[0].Tag, "new-tag")
	}
	if got := GetAgentByTag("old-tag"); got != nil {
		t.Fatalf("stale tag still resolves to %+v", got)
	}
	if got := GetAgentByIndex(7); got == nil || got.Tag != "new-tag" {
		t.Fatalf("control index lost across upsert: %+v", got)
	}
	if rec, ok := live.LookupAgent(second.UUID); !ok || rec.Label != "keep-me" {
		t.Fatalf("label lost across upsert: %+v", rec)
	}
}

// TestRegistryOperatorStyleRecord documents role semantics: an operator record
// has no live Control, so it is found by tag/UUID but has no index and cannot
// be sent to directly.
func TestRegistryOperatorStyleRecord(t *testing.T) {
	clearRegistry(t)

	agent := newAgent("uuid-operator", "op-tag")
	live.PublishAgent(&live.AgentRecord{Agent: agent}) // Control nil

	if got := GetAgentByTag(agent.Tag); got == nil || got.UUID != agent.UUID {
		t.Fatalf("GetAgentByTag on a control-less record = %+v, want the agent", got)
	}
	if got := GetAgentByIndex(0); got != nil {
		t.Fatalf("GetAgentByIndex on a control-less record = %+v, want nil", got)
	}
	if err := SendMessageToAgent(&def.MsgTunData{}, agent); err == nil {
		t.Fatal("SendMessageToAgent should fail for a control-less record")
	}
}

// TestAssignAgentIndexReusesFreedIndex checks index allocation against the
// single registry: the smallest unused index is reused after a disconnect.
func TestAssignAgentIndexReusesFreedIndex(t *testing.T) {
	clearRegistry(t)

	if got := AssignAgentIndex(); got != 0 {
		t.Fatalf("AssignAgentIndex on empty registry = %d, want 0", got)
	}

	live.PublishAgent(&live.AgentRecord{Agent: newAgent("a", "ta"), Control: &live.AgentControl{Index: 0}})
	live.PublishAgent(&live.AgentRecord{Agent: newAgent("b", "tb"), Control: &live.AgentControl{Index: 1}})
	if got := AssignAgentIndex(); got != 2 {
		t.Fatalf("AssignAgentIndex for 0,1 = %d, want 2", got)
	}

	live.ForgetAgent("a")
	if got := AssignAgentIndex(); got != 0 {
		t.Fatalf("AssignAgentIndex after freeing 0 = %d, want 0 (index reuse)", got)
	}
}

// TestMustGetActiveAgentReturnsFreshSnapshot verifies the operator's active
// agent is resolved from the single registry, and that refreshing the registry
// yields the refreshed snapshot rather than a stale pointer.
func TestMustGetActiveAgentReturnsFreshSnapshot(t *testing.T) {
	clearRegistry(t)

	live.PublishAgent(&live.AgentRecord{Agent: newAgent("uuid-active", "active-tag")})
	live.SetActiveAgent(GetAgentByTag("active-tag"))
	if live.GetActiveAgent() == nil {
		t.Fatal("test setup: active agent not found")
	}

	fresh := newAgent("uuid-active", "active-tag")
	fresh.Hostname = "refreshed.example"
	live.PublishAgent(&live.AgentRecord{Agent: fresh})

	got := MustGetActiveAgent()
	if got == nil || got.Hostname != "refreshed.example" {
		t.Fatalf("MustGetActiveAgent = %+v, want the refreshed registry snapshot", got)
	}
}

// stubConn is a net.Conn whose identity is what matters for RuntimeControlByConn.
type stubConn struct{ net.Conn }

func (s *stubConn) Close() error { return nil }

// TestActiveAgentConcurrentAccess is the regression test for the former plain
// *def.Emp3r0rAgent global: it was written on the agent-list refresher goroutine
// and read by REPL/completer/status-bar goroutines with no synchronization,
// which is a data race. Run with -race to catch a regression.
func TestActiveAgentConcurrentAccess(t *testing.T) {
	clearRegistry(t)

	const workers = 8
	const iterations = 2000
	var wg sync.WaitGroup

	// Writers flip the selection between two agents.
	for w := 0; w < workers; w++ {
		live.PublishAgent(&live.AgentRecord{Agent: newAgent("ra-a", "ra-tag-a")})
		live.PublishAgent(&live.AgentRecord{Agent: newAgent("ra-b", "ra-tag-b")})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if i%2 == 0 {
					live.SetActiveAgent(GetAgentByTag("ra-tag-a"))
				} else {
					live.SetActiveAgent(GetAgentByTag("ra-tag-b"))
				}
			}
		}()
	}

	// Readers observe the selection the way the REPL and status bar do.
	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if a := live.GetActiveAgent(); a != nil {
					_ = a.Tag
				}
				_ = MustGetActiveAgent()
			}
		}()
	}

	wg.Wait()
}
