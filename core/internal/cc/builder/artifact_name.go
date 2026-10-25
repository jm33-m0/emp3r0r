package builder

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// Generated artifacts get a deterministic, feature-describing name instead of a
// timestamp. The name is also the only place an operator can tell two payloads
// built with different configs apart at a glance, so it carries every config
// value that changes the agent's behaviour. Values are lower-cased and reduced
// to a conservative filename alphabet so a hostname, URL or SMB pipe name can
// never make the output unwritable on Windows.
const maxArtifactTokenLen = 64

// artifactToken sanitizes one config value for use as a filename component.
func artifactToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastSep := false
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.':
			b.WriteRune(r)
			lastSep = false
		case b.Len() > 0 && !lastSep:
			b.WriteByte('-')
			lastSep = true
		}
	}
	out := strings.Trim(b.String(), "-.")
	if len(out) > maxArtifactTokenLen {
		out = strings.TrimRight(out[:maxArtifactTokenLen], "-.")
	}
	return out
}

// artifactHost extracts the host (and, when present, port) from a URL or bare
// address. Only the host is used: proxy credentials and URL paths must never
// leak into an artifact name.
func artifactHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parse := value
	if !strings.Contains(parse, "://") {
		parse = "//" + parse
	}
	if u, err := url.Parse(parse); err == nil && u.Host != "" {
		return artifactToken(u.Host)
	}
	return artifactToken(value)
}

// artifactScheme returns a URL scheme for a value such as
// "socks5://127.0.0.1:9050", or "" when the value has no scheme. It lets the
// artifact name say "proxy-socks5" without embedding the proxy host.
func artifactScheme(value string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return artifactToken(u.Scheme)
}

func artifactValue(prefix, value string) string {
	if value = artifactHost(value); value == "" {
		return ""
	}
	return prefix + "-" + value
}

// artifactShortID is a random suffix that keeps repeated builds of the same
// config distinct. The agent UUID is already cryptographically random; when a
// direct builder call has none, generate one instead of dropping the suffix.
func artifactShortID(agentUUID string) string {
	id := strings.ToLower(strings.TrimSpace(agentUUID))
	id = strings.ReplaceAll(id, "-", "")
	if id == "" {
		id = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	if len(id) > 8 {
		id = id[:8]
	}
	return artifactToken(id)
}

func artifactJoin(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.Trim(part, "_-"); part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "_")
}

// payloadKind is the filename token for a Go payload type.
func payloadKind(payloadType string) string {
	switch payloadType {
	case PayloadTypeLinuxSO:
		return "so"
	case PayloadTypeWindowsDLL:
		return "dll"
	default:
		return "exe"
	}
}

// payloadExtension is the artifact suffix for a Go payload type.
func payloadExtension(payloadType string) string {
	switch payloadType {
	case PayloadTypeWindowsExecutable:
		return ".exe"
	case PayloadTypeWindowsDLL:
		return ".dll"
	case PayloadTypeLinuxSO:
		return ".so"
	default:
		return ""
	}
}

// agentMeshToken summarises the routing role and peer transport.
func agentMeshToken(cfg *def.Config) string {
	if cfg == nil || !cfg.IsP2PEnabled {
		return "standalone"
	}
	role := "silent-node"
	if cfg.IsDirectC2Enabled {
		role = "gateway"
	}
	if peerTransport := artifactToken(cfg.P2PTransport); peerTransport != "" {
		return role + "-" + peerTransport
	}
	return role
}

// agentFeatureTokens lists the optional C2 features that change how the agent
// behaves. The order is fixed so the same config always produces the same name.
func agentFeatureTokens(cfg *def.Config) []string {
	if cfg == nil {
		return nil
	}
	tokens := make([]string, 0, 16)
	if cfg.UseKCP {
		tokens = append(tokens, "kcp")
	}
	if cfg.EnableNCSI {
		tokens = append(tokens, "ncsi")
	}
	if cfg.IsRunByStager {
		tokens = append(tokens, "stager")
	}
	if cfg.IsP2PEnabled && cfg.PersistentRouter {
		tokens = append(tokens, "persistent-router")
	}
	if cfg.QUICStandardKey {
		tokens = append(tokens, "quic-standard")
	}
	for _, feature := range []struct {
		name  string
		value string
	}{
		{"doh", cfg.DoHServer},
		{"ech", cfg.ECHServerName},
		{"cdn", cfg.CDNProxy},
	} {
		if token := artifactValue(feature.name, feature.value); token != "" {
			tokens = append(tokens, token)
		} else if strings.TrimSpace(feature.value) != "" {
			tokens = append(tokens, feature.name)
		}
	}
	if strings.TrimSpace(cfg.C2TransportProxy) != "" {
		if scheme := artifactScheme(cfg.C2TransportProxy); scheme != "" {
			tokens = append(tokens, "proxy-"+scheme)
		} else {
			tokens = append(tokens, "proxy")
		}
	}
	if cfg.C2ChannelMode == def.C2ChannelModePlainHTTP {
		if cfg.PollInterval > 0 {
			tokens = append(tokens, fmt.Sprintf("poll-%d", cfg.PollInterval))
		}
		if cfg.Jitter > 0 {
			tokens = append(tokens, fmt.Sprintf("jitter-%d", cfg.Jitter))
		}
	}
	if cfg.IsP2PEnabled {
		if port := artifactToken(cfg.P2PRelayPort); port != "" {
			tokens = append(tokens, "relay-"+port)
		}
		if port := artifactToken(cfg.MeshGossipPort); port != "" {
			tokens = append(tokens, "gossip-"+port)
		}
		if len(cfg.InitialPeers) > 0 {
			tokens = append(tokens, fmt.Sprintf("peers-%d", len(cfg.InitialPeers)))
		}
	}
	return tokens
}

// artifactAddressHasPort reports whether a URL or address already carries a
// port, so the endpoint tokens do not repeat it.
func artifactAddressHasPort(value string) bool {
	parse := strings.TrimSpace(value)
	if parse == "" {
		return false
	}
	if !strings.Contains(parse, "://") {
		parse = "//" + parse
	}
	u, err := url.Parse(parse)
	return err == nil && u.Port() != ""
}

// c2EndpointTokens carries the address and the port the selected channel
// actually dials. The channel and value order make labels unnecessary.
func c2EndpointTokens(cfg *def.Config) []string {
	if cfg == nil {
		return nil
	}
	var tokens []string
	if cc := artifactHost(cfg.CCAddress); cc != "" {
		tokens = append(tokens, cc)
	}
	port := cfg.CCHTTPPort
	switch cfg.C2ChannelMode {
	case def.C2ChannelModeH2Conn, def.C2ChannelModeQUIC:
		port = cfg.CCH2Port
	}
	if port = artifactToken(port); port != "" && !artifactAddressHasPort(cfg.CCAddress) {
		tokens = append(tokens, port)
	}
	return tokens
}

// agentArtifactName builds the Go agent output name:
//
//	agent_<os>_<arch>_<kind>_<channel>_<mesh>_<features>_<host>_<port>_<id>.<ext>
func agentArtifactName(cfg AgentBuildConfig, runtimeConfig *def.Config) string {
	channel := def.C2ChannelModeDefault
	if runtimeConfig != nil && runtimeConfig.C2ChannelMode != "" {
		channel = runtimeConfig.C2ChannelMode
	}
	parts := []string{
		"agent",
		PayloadGOOS(cfg.PayloadType),
		cfg.Arch,
		payloadKind(cfg.PayloadType),
		artifactToken(channel),
		agentMeshToken(runtimeConfig),
	}
	parts = append(parts, agentFeatureTokens(runtimeConfig)...)
	parts = append(parts, c2EndpointTokens(runtimeConfig)...)
	parts = append(parts, artifactShortID(cfg.AgentUUID))
	return artifactJoin(parts...) + payloadExtension(cfg.PayloadType)
}

// cAgentEffectiveProviders fills in the values the C agent Makefile would use
// when a field was left empty, so the filename describes the artifact that is
// actually built rather than the operator's sparse flag set.
func cAgentEffectiveProviders(p CAgentProviders) CAgentProviders {
	if p.Arch == "" {
		p.Arch = CAgentArches[0]
	}
	if p.Libc == "" {
		p.Libc = CAgentLibcs[0]
	}
	if p.Format == "" {
		p.Format = CAgentFormats[0]
	}
	if p.Crypto == "" {
		p.Crypto = CAgentCryptoProviders[0]
	}
	if p.Gzip == "" {
		p.Gzip = CAgentGzipProviders[0]
	}
	if p.Transport == "" {
		p.Transport = CAgentTransportProviders[0]
	}
	if p.Dynload == "" {
		if p.Libc == "musl" {
			p.Dynload = "public"
		} else {
			p.Dynload = CAgentDynloadModes[0]
		}
	}
	if p.Glibc == "" {
		if p.Dynload == "public" {
			p.Glibc = "2.34"
		} else {
			p.Glibc = CAgentGlibcVersions[0]
		}
	}
	return p
}

// cAgentArtifactName builds the C agent output name:
//
//	c_agent_linux_<arch>_<format>_<libc>_<transport>_<crypto>_
//	<gzip>_<dynload>_<endpoint>_<id>.<ext>
func cAgentArtifactName(providers CAgentProviders, runtimeConfig *def.Config, agentUUID string) string {
	p := cAgentEffectiveProviders(providers)
	libcToken := "musl"
	if p.Libc != "musl" {
		libcToken = "glibc-" + p.Glibc
	}
	parts := []string{
		"c_agent",
		"linux",
		p.Arch,
		p.Format,
		artifactToken(libcToken),
		artifactToken(p.Transport),
		artifactToken(p.Crypto),
		artifactToken(p.Gzip),
		artifactToken(p.Dynload),
	}
	if runtimeConfig != nil {
		if token := artifactValue("doh", runtimeConfig.DoHServer); token != "" {
			parts = append(parts, token)
		} else if strings.TrimSpace(runtimeConfig.DoHServer) != "" {
			parts = append(parts, "doh")
		}
		parts = append(parts, c2EndpointTokens(runtimeConfig)...)
	}
	parts = append(parts, artifactShortID(agentUUID))
	ext := ""
	switch p.Format {
	case "so":
		ext = ".so"
	case "shellcode":
		ext = ".bin"
	}
	return artifactJoin(parts...) + ext
}
