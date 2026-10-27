package server

import (
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestAgentOfflineGraceIsPerAgent(t *testing.T) {
	tests := []struct {
		name  string
		agent *def.Emp3r0rAgent
		want  time.Duration
		keep  bool
	}{
		{
			name:  "agent without a deadline is removed immediately",
			agent: &def.Emp3r0rAgent{UUID: "a"},
		},
		{
			name:  "first agent uses its own deadline",
			agent: &def.Emp3r0rAgent{UUID: "b", OfflineGrace: 10},
			want:  10 * time.Second,
			keep:  true,
		},
		{
			name:  "second agent uses a different deadline",
			agent: &def.Emp3r0rAgent{UUID: "c", OfflineGrace: 120},
			want:  120 * time.Second,
			keep:  true,
		},
		{
			name:  "excessive value is bounded for safety",
			agent: &def.Emp3r0rAgent{UUID: "d", OfflineGrace: 7 * 24 * 3600},
			want:  maxAgentOfflineGrace,
			keep:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, keep := agentOfflineGrace(tc.agent)
			if keep != tc.keep {
				t.Fatalf("keep = %v, want %v", keep, tc.keep)
			}
			if got != tc.want {
				t.Fatalf("grace = %v, want %v", got, tc.want)
			}
		})
	}
}
