//go:build linux

package operator

import (
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
)

// TestRenderAgentTableWithoutTmux covers the MCP/headless refresher: there is
// no CommandPane, so the status-bar and window-title helpers must be skipped
// instead of dereferenced.
func TestRenderAgentTableWithoutTmux(t *testing.T) {
	prevPane := cli.CommandPane
	cli.CommandPane = nil
	t.Cleanup(func() {
		cli.CommandPane = prevPane
		live.ClearAgents()
		live.SetActiveAgent(nil)
	})

	target := &def.Emp3r0rAgent{Tag: "tag-1", UUID: "uuid-1", Name: "host"}
	live.ClearAgents()
	live.PublishAgent(&live.AgentRecord{Agent: target})
	live.SetActiveAgent(target)

	// Before the guard this panicked on cli.CommandPane.WindowID.
	RenderAgentTable([]*def.Emp3r0rAgent{target})
}

func TestFormatIdle(t *testing.T) {
	tests := []struct {
		name     string
		seconds  float64
		expected string
	}{
		{"negative", -5, "0s"},
		{"seconds", 42, "42s"},
		{"exact minute", 60, "1m"},
		{"minutes and seconds", 95, "1m35s"},
		{"exact hour", 3600, "1h"},
		{"hours and minutes", 3725, "1h2m"},
		{"exact day", 86400, "1d"},
		{"days and hours", 90000, "1d1h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIdle(tt.seconds)
			if got != tt.expected {
				t.Fatalf("formatIdle(%v) = %q, want %q", tt.seconds, got, tt.expected)
			}
		})
	}
}

func TestOperatorIdleTracking(t *testing.T) {
	// Clear any state left behind by other tests.
	lastCommandSent.Range(func(key, _ any) bool {
		lastCommandSent.Delete(key)
		return true
	})

	if _, ok := operatorIdleFor("no-such-agent"); ok {
		t.Fatal("expected no operator idle record for unknown agent")
	}

	markAgentCommandSent("test-agent")
	idle, ok := operatorIdleFor("test-agent")
	if !ok {
		t.Fatal("expected operator idle record after markAgentCommandSent")
	}
	if idle < 0 || idle > 5*time.Second {
		t.Fatalf("operator idle out of range: %v", idle)
	}
}
