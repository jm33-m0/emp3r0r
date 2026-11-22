package operator

import (
	"fmt"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// generationMu serializes background builds so two generators cannot mutate
// the shared runtime config and module state concurrently.
var generationMu sync.Mutex

// CmdGenerateAgent builds a Go agent from console flags.
func CmdGenerateAgent(cmd *cobra.Command, args []string) {
	payloadType, _ := cmd.Flags().GetString("type")
	archChoice, _ := cmd.Flags().GetString("arch")

	if !builder.IsArchValid(payloadType, archChoice) {
		logging.Errorf("Invalid arch choice")
		return
	}

	p2p, _ := cmd.Flags().GetBool("p2p")
	directC2, _ := cmd.Flags().GetBool("direct-c2")
	persistentRouter, _ := cmd.Flags().GetBool("persistent-router")
	ncsi, _ := cmd.Flags().GetBool("NCSI")
	quicStandardKey, _ := cmd.Flags().GetBool("quic-standard-key")
	isStager, _ := cmd.Flags().GetBool("stager")
	operatorIdleTimeout, _ := cmd.Flags().GetInt("operator-idle-timeout")
	allowCustomTransport, _ := cmd.Flags().GetBool("allow-custom-transport")
	transportOptions, err := parseTransportOptions(cmd)
	if err != nil {
		logging.Errorf("Invalid transport option: %v", err)
		return
	}

	opts := builder.AgentConfig{
		CCAddress:            getStringOptPtr(cmd, "cc"),
		C2TransportProxy:     getStringOptPtr(cmd, "proxy"),
		DoHServer:            getStringOptPtr(cmd, "doh"),
		ECHServerName:        getStringOptPtr(cmd, "ech"),
		C2ChannelMode:        getStringOptPtr(cmd, "c2-channel-mode"),
		AllowCustomTransport: allowCustomTransport,
		TransportOptions:     transportOptions,
		QUICStandardKey:      quicStandardKey,
		InitialPeers:         getStringSliceOptPtr(cmd, "peers"),
		P2PTransport:         getStringOptPtr(cmd, "p2p-transport"),
		P2PRelayPort:         getStringOptPtr(cmd, "p2p-relay-port"),
		MeshGossipPort:       getStringOptPtr(cmd, "mesh-gossip-port"),
		CCHTTPPort:           getStringOptPtr(cmd, "cc-http-port"),
		PollInterval:         getIntOptPtr(cmd, "interval"),
		Jitter:               getIntOptPtr(cmd, "jitter"),
		OperatorIdleTimeout:  &operatorIdleTimeout,
		IsP2PEnabled:         p2p,
		IsDirectC2:           directC2,
		PersistentRouter:     persistentRouter,
		IsNCSIEnabled:        ncsi,
		IsStager:             isStager,
	}

	logging.Infof("Generating agent in the background; output follows")
	go func() {
		generationMu.Lock()
		defer generationMu.Unlock()

		if err := client.UpdateOperatorIdleConfig(operatorIdleTimeout); err != nil {
			logging.Warningf("Failed to update operator idle timeout on C2: %v", err)
		}

		res, err := builder.GenerateAgentWorkflow(opts, payloadType, archChoice, client.SignAgent)
		if err != nil {
			logging.Errorf("Failed to generate agent: %v", err)
			return
		}

		result := res.BuildResult
		logging.Infof("Generated agent UUID: %s", util.AgentRef(result.AgentUUID))
		logging.Debugf("Config payload: %d bytes", result.ConfigSize)
		logging.Successf("Generated %s (%d bytes) from %s and %s",
			result.OutputFile, util.FileSize(result.OutputFile), result.StubFile, live.EmpConfigFile)
		logging.Infof("Agent transport: %s", builder.DescribeGoAgentTransport())

		if live.RuntimeConfig.IsP2PEnabled {
			logging.Successf("P2P Mesh Configured for Agent:")
			logging.Infof("  P2P Transport:    %s", live.RuntimeConfig.P2PTransport)
			if transport.TransportUsesNetworkPort(live.RuntimeConfig.P2PTransport) {
				logging.Infof("  P2P Relay Port:   %s", live.RuntimeConfig.P2PRelayPort)
			} else {
				// SMB named pipes open no port: the value only salts the pipe name,
				// which every peer derives from the shared password and its value.
				logging.Infof("  P2P Relay ID:     %s (no network port; derives the pipe name)", live.RuntimeConfig.P2PRelayPort)
			}
			logging.Infof("  Mesh Gossip Port: %s", live.RuntimeConfig.MeshGossipPort)
			logging.Infof("  Bootstrap peers:  --peers <agent_ip>:%s", live.RuntimeConfig.MeshGossipPort)
			logging.Infof("  Routing uses each peer's advertised transport when this agent can dial it")
		}

		if payloadType == builder.PayloadTypeLinuxSO {
			logging.Infof("Linux shellcode is not generated automatically; run the malasada module with %s as input", result.OutputFile)
		} else if payloadType == builder.PayloadTypeWindowsExecutable || payloadType == builder.PayloadTypeWindowsDLL {
			logging.Infof("Windows shellcode is not generated automatically; run the donut module with %s as input", result.OutputFile)
		}
	}()
}

// parseTransportOptions converts repeated --transport-option key=value flags
// into the map embedded in the agent configuration. Values may contain '='.
func parseTransportOptions(cmd *cobra.Command) (map[string]string, error) {
	raw, _ := cmd.Flags().GetStringSlice("transport-option")
	if len(raw) == 0 {
		return nil, nil
	}
	options := make(map[string]string, len(raw))
	for _, item := range raw {
		key, value, ok := strings.Cut(item, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("expected key=value, got %q", item)
		}
		if _, exists := options[key]; exists {
			return nil, fmt.Errorf("duplicate option %q", key)
		}
		options[key] = value
	}
	return options, nil
}

func getStringOptPtr(cmd *cobra.Command, name string) *string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetString(name)
		return &val
	}
	return nil
}

func getIntOptPtr(cmd *cobra.Command, name string) *int {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetInt(name)
		return &val
	}
	return nil
}

func getStringSliceOptPtr(cmd *cobra.Command, name string) *[]string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetStringSlice(name)
		return &val
	}
	return nil
}
