package transport

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

const (
	// ReplayWindowSeconds defines the allowed clock skew / replay window.
	ReplayWindowSeconds = 60
)

// CanonicalAuthString builds the payload-auth canonical string.
// It is independent from wrapper details like method/path/header.
func CanonicalAuthString(agentUUID string, timestamp int64, nonce, route string) string {
	return strings.Join([]string{
		agentUUID,
		strconv.FormatInt(timestamp, 10),
		nonce,
		route,
	}, "\n")
}

// VerifyMsgAuth validates payload-carried auth claims against CA trust and local policy.
func VerifyMsgAuth(auth *def.MsgAuth) error {
	if auth == nil {
		return fmt.Errorf("nil MsgAuth")
	}
	if auth.Type != def.MsgAuthType {
		return fmt.Errorf("unexpected MsgAuth type %q", auth.Type)
	}
	if auth.Route == "" {
		return fmt.Errorf("missing route")
	}
	if auth.AgentUUID == "" {
		return fmt.Errorf("empty AgentUUID")
	}
	if len(auth.IdentityToken) == 0 {
		return fmt.Errorf("missing CA identity token")
	}
	if auth.Nonce == "" {
		return fmt.Errorf("missing nonce")
	}
	if auth.Timestamp <= 0 {
		return fmt.Errorf("invalid timestamp")
	}
	now := time.Now().Unix()
	if now-auth.Timestamp > ReplayWindowSeconds || auth.Timestamp-now > ReplayWindowSeconds {
		return fmt.Errorf("timestamp outside replay window")
	}

	ok, err := VerifySignatureWithCA([]byte(auth.AgentUUID), auth.IdentityToken)
	if err != nil {
		return fmt.Errorf("CA token verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("CA token verification failed")
	}

	// AgentProof is a signature using the agent's pinned public key (TOFU).
	// VerifyMsgAuth only handles CA-level trust (IdentityToken).
	// Proof verification is done by the protocol dispatcher which has access to the pinned key.
	return nil
}
