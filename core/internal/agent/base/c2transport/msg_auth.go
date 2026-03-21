package c2transport

import (
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// sendMsgAuthEnvelope sends a CBOR-encoded MsgAuth envelope over the given writer.
// This is the FIRST thing sent over every new connection, before any other CBOR frames.
// The server reads this first frame to route the connection and verify identity.
func sendMsgAuthEnvelope(w io.Writer, capabilities []string, streamID string) error {
	cfg := common.RuntimeConfig
	if cfg == nil {
		return fmt.Errorf("runtime config not initialized")
	}
	if cfg.AgentUUID == "" {
		return fmt.Errorf("missing agent UUID")
	}

	nonce := util.RandStr(16)
	now := time.Now().Unix()
	canonical := transport.CanonicalAuthString(cfg.AgentUUID, now, nonce, capabilities)
	sig, err := agentutils.SignWithAgentKey([]byte(canonical))
	if err != nil {
		return fmt.Errorf("sign MsgAuth: %w", err)
	}

	msg := def.MsgAuth{
		Type:          def.MsgAuthType,
		AgentUUID:     cfg.AgentUUID,
		IdentityToken: cfg.AgentUUIDSig,
		Nonce:         nonce,
		Timestamp:     now,
		AgentProof:    base64.URLEncoding.EncodeToString(sig),
		Capabilities:  capabilities,
		StreamID:      streamID,
	}
	return cbor.NewEncoder(w).Encode(msg)
}
