package builder

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// BoolProvider renders a boolean switch as the Makefile's 0/1 provider.
func BoolProvider(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// ValidateCAgentPollTiming rejects a beacon profile that would make the sleep
// cycle non-random or nonsensical.
func ValidateCAgentPollTiming(interval, jitter int) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if jitter < 0 || jitter > 100 {
		return fmt.Errorf("jitter must be between 0 and 100")
	}
	return nil
}

// CAgentStagerMode reports whether the selected artifact is the one embedded
// by stager_linux. A standalone shellcode deployment simply finds no mask and
// falls back to a normal sleep.
func CAgentStagerMode(format string) bool {
	return format == "shellcode"
}

// CAgentDynloadForLibc follows the selected libc when the operator did not pick
// a dynload mode. The operator default targets glibc, but musl only exports the
// public dl* names, so an unset mode becomes public for a musl build rather
// than failing validation on the glibc default.
func CAgentDynloadForLibc(libc, dynload string, dynloadSet bool) string {
	if libc == "musl" && !dynloadSet {
		return "public"
	}
	return dynload
}

// CAgentEndpoint describes the URL baked into the C agent. An explicit URL
// carries its own scheme and port; a bare host uses the plain HTTP port, and a
// custom channel mode carries its own address form.
func CAgentEndpoint(cc, httpPort, channelMode string) string {
	cc = strings.TrimSuffix(cc, "/")
	if !def.IsBuiltinC2ChannelMode(channelMode) {
		return cc
	}
	if strings.Contains(cc, "://") {
		return cc
	}
	return fmt.Sprintf("http://%s:%s", cc, httpPort)
}

// ResolveCAgentTransport applies the channel/transport pairing rules shared by
// the console and MCP generators. It returns the provider to build with.
func ResolveCAgentTransport(channelMode, transport string, transportSet, allowCustom bool) (string, error) {
	if channelMode == "" {
		channelMode = def.C2ChannelModeDefault
	}
	if !def.IsBuiltinC2ChannelMode(channelMode) {
		if !allowCustom {
			return "", fmt.Errorf("invalid c2-channel-mode %q: add --allow-custom-transport", channelMode)
		}
		switch {
		case !transportSet || transport == "":
			return channelMode, nil
		case transport != channelMode:
			return "", fmt.Errorf("custom channel mode %q requires --transport %q", channelMode, channelMode)
		}
		return transport, nil
	}
	if !transportSet || transport == "" {
		transport = CAgentTransportProviders[0]
	}
	switch transport {
	case "libcurl", "http_raw", "libssl":
		return transport, nil
	default:
		return "", fmt.Errorf("transport %q is a custom provider: select --c2-channel-mode %q", transport, transport)
	}
}

// DescribeGoAgentTransport describes the endpoint baked into a generated Go
// agent, including the port that channel actually dials.
func DescribeGoAgentTransport() string {
	mode := live.RuntimeConfig.C2ChannelMode
	if mode == "" {
		mode = def.C2ChannelModeDefault
	}
	addr := strings.TrimSuffix(live.RuntimeConfig.CCAddress, "/")
	explicitURL := strings.Contains(addr, "://")

	var endpoint string
	switch {
	case explicitURL:
		endpoint = addr
	case mode == def.C2ChannelModePlainHTTP:
		endpoint = fmt.Sprintf("http://%s:%s", addr, live.RuntimeConfig.CCHTTPPort)
	case mode == def.C2ChannelModeQUIC:
		endpoint = fmt.Sprintf("%s:%s/UDP", addr, live.RuntimeConfig.CCH2Port)
	default:
		endpoint = fmt.Sprintf("https://%s:%s", addr, live.RuntimeConfig.CCH2Port)
	}

	return fmt.Sprintf("channel=%s endpoint=%s", mode, endpoint)
}
