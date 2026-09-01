package controllers

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestProcessAgentResponseQuietSuppression verifies that responses to
// completion invocations of !list_tokens / !list_sessions (sent with
// `--quiet` by the CC completers) still carry their data back to the
// CmdResults machinery but are not rendered in the operator console.
func TestProcessAgentResponseQuietSuppression(t *testing.T) {
	agent := &def.Emp3r0rAgent{Tag: "quiet-test", UUID: "quiet-test-uuid"}
	live.AgentControlMap.Store(agent, &live.AgentControl{})
	defer live.AgentControlMap.Delete(agent)

	msg := func(cmdSlice []string) *def.MsgTunData {
		return &def.MsgTunData{
			Tag:       "quiet-test",
			AgentUUID: "quiet-test-uuid",
			CmdSlice:  cmdSlice,
			Response:  []byte("Cached tokens (1):\nS-1-5-21-1234-5678  quiet-test\\user\n"),
			JobID:     "job-quiet-1",
		}
	}

	// Normal operator invocation: result must be shown.
	resp, err := ProcessAgentResponse(msg([]string{def.C2CmdListTokens}))
	if err != nil {
		t.Fatalf("ProcessAgentResponse(list_tokens): %v", err)
	}
	if !resp.ShouldShow {
		t.Fatalf("normal list_tokens response should be shown")
	}

	// Completion invocation: data still arrives but must not be rendered.
	resp, err = ProcessAgentResponse(msg([]string{def.C2CmdListTokens, "--quiet"}))
	if err != nil {
		t.Fatalf("ProcessAgentResponse(list_tokens --quiet): %v", err)
	}
	if resp.ShouldShow {
		t.Fatalf("--quiet list_tokens response must not be shown")
	}
	if resp.Output != "Cached tokens (1):\nS-1-5-21-1234-5678  quiet-test\\user\n" {
		t.Fatalf("quiet response must still carry the data for completion: %q", resp.Output)
	}

	// The same marker applies to list_sessions.
	resp, err = ProcessAgentResponse(msg([]string{def.C2CmdListSessions, "--quiet"}))
	if err != nil {
		t.Fatalf("ProcessAgentResponse(list_sessions --quiet): %v", err)
	}
	if resp.ShouldShow {
		t.Fatalf("--quiet list_sessions response must not be shown")
	}
}
