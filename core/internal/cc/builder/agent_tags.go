package builder

import (
	"slices"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// AgentBuildTags maps selected agent features to the opt-in build tags in
// core/build.py. The tags must remain in sync with the //go:build constraints.
func AgentBuildTags(cfg *def.Config) []string {
	if cfg == nil {
		return nil
	}
	var tags []string
	add := func(tag string) {
		if tag != "" && !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
	}
	if cfg.IsP2PEnabled {
		add("with_mesh")
		if strings.EqualFold(strings.TrimSpace(cfg.P2PTransport), "kcp") {
			add("with_kcp")
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.C2ChannelMode)) {
	case def.C2ChannelModeH2Conn:
		add("with_h2conn")
	case def.C2ChannelModeQUIC:
		add("with_quic")
	case "tor":
		add("with_transport_tor")
	}
	if strings.TrimSpace(cfg.DoHServer) != "" {
		add("with_doh")
	}
	if strings.TrimSpace(cfg.ECHServerName) != "" {
		add("with_doh")
		add("with_ech")
	}
	return tags
}
