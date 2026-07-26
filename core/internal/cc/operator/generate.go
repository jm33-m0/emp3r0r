package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdGenerateAgent generates agent binary (UI command layer)
func CmdGenerateAgent(cmd *cobra.Command, args []string) {
	// Parse flags (UI layer)
	payloadType, _ := cmd.Flags().GetString("type")
	archChoice, _ := cmd.Flags().GetString("arch")

	if !builder.IsArchValid(payloadType, archChoice) {
		logging.Errorf("Invalid arch choice")
		return
	}

	// Gather config from flags. Bool flags default to false when omitted.
	p2p, _ := cmd.Flags().GetBool("p2p")
	directC2, _ := cmd.Flags().GetBool("direct-c2")
	persistentRouter, _ := cmd.Flags().GetBool("persistent-router")
	ncsi, _ := cmd.Flags().GetBool("NCSI")
	kcp, _ := cmd.Flags().GetBool("kcp")
	isStager, _ := cmd.Flags().GetBool("stager")

	opts := builder.AgentConfig{
		CCAddress:        getStringOptPtr(cmd, "cc"),
		CDNProxy:         getStringOptPtr(cmd, "cdn"),
		C2TransportProxy: getStringOptPtr(cmd, "proxy"),
		DoHServer:        getStringOptPtr(cmd, "doh"),
		C2ChannelMode:    getStringOptPtr(cmd, "c2-channel-mode"),
		InitialPeers:     getStringSliceOptPtr(cmd, "peers"),
		P2PTransport:     getStringOptPtr(cmd, "p2p-transport"),
		P2PRelayPort:     getStringOptPtr(cmd, "p2p-relay-port"),
		MeshGossipPort:   getStringOptPtr(cmd, "mesh-gossip-port"),
		CCHTTPPort:       getStringOptPtr(cmd, "cc-http-port"),
		PollInterval:     getIntOptPtr(cmd, "interval"),
		Jitter:           getIntOptPtr(cmd, "jitter"),
		IsP2PEnabled:     p2p,
		IsDirectC2:       directC2,
		PersistentRouter: persistentRouter,
		IsNCSIEnabled:    ncsi,
		UseKCP:           kcp,
		IsStager:         isStager,
	}

	// Invoke core agent generation business logic outside operator package and controller package
	res, err := builder.GenerateAgentWorkflow(opts, payloadType, archChoice, client.SignAgent)
	if err != nil {
		logging.Errorf("Failed to generate agent: %v", err)
		return
	}

	result := res.BuildResult
	logging.Infof("Generated agent UUID: %s", result.AgentUUID)
	logging.Debugf("Config payload: %d bytes", result.ConfigSize)
	logging.Successf("Generated %s from %s and %s", result.OutputFile, result.StubFile, live.EmpConfigFile)

	if live.RuntimeConfig.IsP2PEnabled {
		logging.Successf("P2P Mesh Configured for Agent:")
		logging.Infof("  P2P Relay Port:  %s", live.RuntimeConfig.P2PRelayPort)
		logging.Infof("  Mesh Gossip Port: %s", live.RuntimeConfig.MeshGossipPort)
		logging.Infof("  To use this agent as a bootstrap peer for other agents, specify: --peers <agent_ip>:%s", live.RuntimeConfig.MeshGossipPort)
	}

	if res.ShellcodeErr != nil {
		logging.Warningf("%v", res.ShellcodeErr)
	} else if res.ShellcodeFile != "" {
		logging.Infof("Converted %s into shellcode at %s", result.OutputFile, res.ShellcodeFile)
		if payloadType == builder.PayloadTypeLinuxSO {
			logging.Infof("Look into stager module to deliver this shellcode")
		}
	}
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
