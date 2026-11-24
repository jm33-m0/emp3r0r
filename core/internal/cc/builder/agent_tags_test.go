package builder

import (
	"slices"
	"strings"
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

func TestNormalizeAgentTags(t *testing.T) {
	got, err := NormalizeAgentTags([]string{"with_mesh,with_kcp", " with_mesh ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"with_mesh", "with_kcp"}) {
		t.Fatalf("normalized tags = %v", got)
	}
	if _, err := NormalizeAgentTags([]string{"with_ech"}); err == nil {
		t.Fatal("with_ech without with_doh was accepted")
	}
	if _, err := NormalizeAgentTags([]string{"with_kcp"}); err == nil {
		t.Fatal("with_kcp without with_mesh was accepted")
	}
	if _, err := NormalizeAgentTags([]string{"with_nope"}); err == nil {
		t.Fatal("unknown tag was accepted")
	}
	if got, err := NormalizeAgentTags(nil); err != nil || got != nil {
		t.Fatalf("nil tags = %v, %v", got, err)
	}
	if got, err := NormalizeAgentTags([]string{}); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty tags = %v, %v", got, err)
	}
}

func TestAgentTagReferenceListsEveryTag(t *testing.T) {
	ref := AgentTagReference()
	for _, tag := range AllAgentTags() {
		if !strings.Contains(ref, tag) {
			t.Fatalf("reference missing %s:\n%s", tag, ref)
		}
	}
}

func TestValidateAgentTagsForConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  def.Config
		tags []string
		ok   bool
	}{
		{name: "derived set", cfg: def.Config{}, tags: nil, ok: true},
		{name: "extra tags", cfg: def.Config{}, tags: []string{"with_mesh"}, ok: true},
		{name: "quic missing", cfg: def.Config{C2ChannelMode: def.C2ChannelModeQUIC}, tags: []string{}, ok: false},
		{name: "quic present", cfg: def.Config{C2ChannelMode: def.C2ChannelModeQUIC}, tags: []string{"with_quic"}, ok: true},
		{name: "h2conn missing", cfg: def.Config{C2ChannelMode: def.C2ChannelModeH2Conn}, tags: []string{"with_quic"}, ok: false},
		{name: "tor missing", cfg: def.Config{C2ChannelMode: "tor"}, tags: []string{}, ok: false},
		{name: "p2p missing mesh", cfg: def.Config{IsP2PEnabled: true, P2PTransport: "mtls"}, tags: []string{}, ok: false},
		{name: "p2p kcp missing kcp", cfg: def.Config{IsP2PEnabled: true, P2PTransport: "kcp"}, tags: []string{"with_mesh"}, ok: false},
		{name: "p2p kcp present", cfg: def.Config{IsP2PEnabled: true, P2PTransport: "kcp"}, tags: []string{"with_mesh", "with_kcp"}, ok: true},
		{name: "doh missing", cfg: def.Config{DoHServer: "https://dns.example"}, tags: []string{}, ok: false},
		{name: "ech missing", cfg: def.Config{ECHServerName: "c2.example", DoHServer: "https://dns.example"}, tags: []string{"with_doh"}, ok: false},
		{name: "ech present", cfg: def.Config{ECHServerName: "c2.example", DoHServer: "https://dns.example"}, tags: []string{"with_doh", "with_ech"}, ok: true},
	}
	for _, tc := range cases {
		err := ValidateAgentTagsForConfig(tc.tags, &tc.cfg)
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
	}
}
