package builder

import (
	"slices"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestAgentBuildTagsFollowSelectedFeatures(t *testing.T) {
	cfg := &def.Config{
		IsP2PEnabled:  true,
		P2PTransport:  "kcp",
		C2ChannelMode: def.C2ChannelModeH2Conn,
		DoHServer:     "https://dns.example/dns-query",
		ECHServerName: "cover.example",
	}
	got := AgentBuildTags(cfg)
	for _, want := range []string{"with_mesh", "with_kcp", "with_h2conn", "with_doh", "with_ech"} {
		if !slices.Contains(got, want) {
			t.Fatalf("tags = %v, missing %s", got, want)
		}
	}
	if slices.Contains(AgentBuildTags(&def.Config{}), "with_mesh") {
		t.Fatal("empty config enabled mesh")
	}
}
