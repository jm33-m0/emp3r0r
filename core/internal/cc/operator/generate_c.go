package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// CmdGenerateCAgent builds the native C agent (aquila). It is reached through
// `generate --type aquila` rather than a separate command, so the C agent shares
// the Go generator's config flags and only adds the provider selection below.
func CmdGenerateCAgent(cmd *cobra.Command) {
	opts := builder.AgentConfig{
		CCAddress:     getStringOptPtr(cmd, "cc"),
		CCHTTPPort:    getStringOptPtr(cmd, "cc-http-port"),
		C2ChannelMode: getStringOptPtr(cmd, "c2-channel-mode"),
	}
	libc := flagString(cmd, "libc")
	dynload := cAgentDynloadForLibc(libc, flagString(cmd, "dynload"), cmd.Flags().Changed("dynload"))
	providers := builder.CAgentProviders{
		Crypto:    flagString(cmd, "crypto"),
		Gzip:      flagString(cmd, "gzip"),
		HTTP:      flagString(cmd, "http"),
		Transport: flagString(cmd, "transport"),
		Dynload:   dynload,
		Glibc:     flagString(cmd, "glibc-version"),
		Libc:      libc,
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
