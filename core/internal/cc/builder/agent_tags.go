package builder

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// AgentTagDoc describes one opt-in Go agent build tag. The names and text must
// stay in sync with core/build.py so the console, MCP, and detection loop all
// offer the same surface.
type AgentTagDoc struct {
	Name        string
	Description string
}

// AgentTagCatalog is ordered the way build.py lists the tags.
var AgentTagCatalog = []AgentTagDoc{
	{Name: "with_mesh", Description: "P2P mesh and memberlist gossip (peer discovery/routing)"},
	{Name: "with_kcp", Description: "KCP P2P mesh transport and the xtaci kcp-go stack"},
	{Name: "with_h2conn", Description: "HTTP/2 duplex (h2conn) C2 channel"},
	{Name: "with_quic", Description: "QUIC C2 transport and the quic-go stack"},
	{Name: "with_utls", Description: "uTLS TLS fingerprinting (otherwise crypto/tls)"},
	{Name: "with_doh", Description: "DNS-over-HTTPS resolver (otherwise the OS resolver)"},
	{Name: "with_ech", Description: "ECH (Encrypted Client Hello) for C2 TLS; requires with_doh"},
	{Name: "with_netlink", Description: "netlink route/neighbour enumeration (procfs fallback)"},
	{Name: "with_uring", Description: "io_uring file-transfer acceleration (sync fallback)"},
	{Name: "with_transport_tor", Description: "Tor custom transport (agent dialer; needs a bridge)"},
}

// AllAgentTags returns the available tag names in catalog order.
func AllAgentTags() []string {
	tags := make([]string, 0, len(AgentTagCatalog))
	for _, doc := range AgentTagCatalog {
		tags = append(tags, doc.Name)
	}
	return tags
}

// AgentTagDescription returns the help text for one tag.
func AgentTagDescription(name string) string {
	for _, doc := range AgentTagCatalog {
		if doc.Name == name {
			return doc.Description
		}
	}
	return ""
}

// NormalizeAgentTags validates an exact tag set. Comma- and whitespace-
// separated tokens are accepted so a shell-completion value or one string from
// an MCP caller works the same as a repeated flag. Duplicates are removed and
// input order is preserved.
func NormalizeAgentTags(tags []string) ([]string, error) {
	if tags == nil {
		return nil, nil
	}
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		for _, name := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if AgentTagDescription(name) == "" {
				return nil, fmt.Errorf("unknown Go agent build tag %q (available: %s)", name, strings.Join(AllAgentTags(), ", "))
			}
			if slices.Contains(out, name) {
				continue
			}
			out = append(out, name)
		}
	}
	if slices.Contains(out, "with_ech") && !slices.Contains(out, "with_doh") {
		return nil, fmt.Errorf("with_ech requires with_doh")
	}
	if slices.Contains(out, "with_kcp") && !slices.Contains(out, "with_mesh") {
		return nil, fmt.Errorf("with_kcp requires with_mesh")
	}
	return out, nil
}

// ValidateAgentTagsForConfig checks that an explicit tag set can still use the
// transport selected in cfg. Extra tags are allowed; a missing transport tag is
// not, because the generated agent would compile without the dialer the C2
// configuration asks for.
func ValidateAgentTagsForConfig(tags []string, cfg *def.Config) error {
	if tags == nil || cfg == nil {
		return nil
	}
	has := func(name string) bool { return slices.Contains(tags, name) }
	if has("with_kcp") && !has("with_mesh") {
		return fmt.Errorf("with_kcp requires with_mesh")
	}
	if cfg.IsP2PEnabled {
		if !has("with_mesh") {
			return fmt.Errorf("P2P is enabled but the tag set is missing with_mesh")
		}
		if strings.EqualFold(strings.TrimSpace(cfg.P2PTransport), "kcp") && !has("with_kcp") {
			return fmt.Errorf("P2P transport kcp is enabled but the tag set is missing with_kcp")
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.C2ChannelMode)) {
	case def.C2ChannelModeH2Conn:
		if !has("with_h2conn") {
			return fmt.Errorf("C2 channel mode h2conn requires with_h2conn")
		}
	case def.C2ChannelModeQUIC:
		if !has("with_quic") {
			return fmt.Errorf("C2 channel mode quic requires with_quic")
		}
	case "tor":
		if !has("with_transport_tor") {
			return fmt.Errorf("C2 channel mode tor requires with_transport_tor")
		}
	}
	if strings.TrimSpace(cfg.DoHServer) != "" && !has("with_doh") {
		return fmt.Errorf("a DoH server is configured but the tag set is missing with_doh")
	}
	if strings.TrimSpace(cfg.ECHServerName) != "" {
		if !has("with_doh") {
			return fmt.Errorf("ECH is configured but the tag set is missing with_doh")
		}
		if !has("with_ech") {
			return fmt.Errorf("ECH is configured but the tag set is missing with_ech")
		}
	}
	return nil
}

// AgentTagReference renders the same tag reference build.py prints for
// --list-agent-tags. Callers write it verbatim to the console.
func AgentTagReference() string {
	var b strings.Builder
	b.WriteString("Go agent feature tags (pass an exact set with --agent-tags):\n")
	width := 0
	for _, doc := range AgentTagCatalog {
		width = max(width, len(doc.Name))
	}
	for _, doc := range AgentTagCatalog {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, doc.Name, doc.Description)
	}
	b.WriteString("\n--agent-slim builds: (no optional features)\n")
	b.WriteString("all available tags: " + strings.Join(AllAgentTags(), " ") + "\n")
	return b.String()
}

// AgentBuildTags maps selected agent features to the opt-in build tags in
// core/build.py. The tags must remain in sync with the //go:build constraints.
// An explicit AgentConfig.BuildTags set replaces this derivation.
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
