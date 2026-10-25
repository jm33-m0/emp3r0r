package operator

import (
	"fmt"

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
		Run:     CmdGenerateCAgent,
	}

	cmd.Flags().StringP("type", "t", builder.CAgentLibcs[0], fmt.Sprintf("C library variant, available: %v", builder.CAgentLibcs))
	cmd.Flags().StringP("arch", "a", builder.CAgentArches[0], fmt.Sprintf("Target architecture, available: %v", builder.CAgentArches))
	cmd.Flags().String("cc", defaultC2Address(), "C2 server address (Required)")
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
		"cc":            carapace.ActionValues(),
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
