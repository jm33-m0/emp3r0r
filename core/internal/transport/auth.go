package transport

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

const (
	// ReplayWindowSeconds defines the allowed clock skew / replay window.
	ReplayWindowSeconds = 60
	// OperatorClaimMaxTTLSeconds bounds accepted operator stream claim validity.
	OperatorClaimMaxTTLSeconds = 300
)

// CanonicalAuthString builds the payload-auth canonical string.
// It is independent from wrapper details like method/path/header.
func CanonicalAuthString(agentUUID string, timestamp int64, nonce string, capabilities []string) string {
	caps := append([]string(nil), capabilities...)
	sort.Strings(caps)
	parts := []string{
		agentUUID,
		strconv.FormatInt(timestamp, 10),
		nonce,
		strings.Join(caps, ","),
	}
	return strings.Join(parts, "\n")
}

// VerifyMsgAuth validates payload-carried auth claims against CA trust and local policy.
func VerifyMsgAuth(auth *def.MsgAuth) error {
	if auth == nil {
		return fmt.Errorf("nil MsgAuth")
	}
	if auth.Type != def.MsgAuthType {
		return fmt.Errorf("unexpected MsgAuth type %q", auth.Type)
	}
	if auth.AgentUUID == "" {
		return fmt.Errorf("empty AgentUUID")
	}
	if auth.IdentityToken == "" {
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

	caSig, err := base64.URLEncoding.DecodeString(auth.IdentityToken)
	if err != nil {
		return fmt.Errorf("decode identity token: %w", err)
	}
	ok, err := VerifySignatureWithCA([]byte(auth.AgentUUID), caSig)
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

// CanonicalOperatorStreamClaimString builds the payload-auth canonical string
// for operator stream registration claims.
func CanonicalOperatorStreamClaimString(claim *def.OperatorStreamClaim) string {
	if claim == nil {
		return ""
	}
	parts := []string{
		claim.OperatorSession,
		claim.StreamID,
		claim.Capability,
		strconv.FormatInt(claim.IssuedAt, 10),
		strconv.FormatInt(claim.ExpiresAt, 10),
		claim.Nonce,
	}
	return strings.Join(parts, "\n")
}

// VerifyOperatorStreamClaim validates a signed operator claim against the
// expected stream metadata and signer public key.
func VerifyOperatorStreamClaim(
	claim *def.OperatorStreamClaim,
	expectedSession string,
	expectedStreamID string,
	expectedCapability string,
	operatorPubPEM []byte,
) error {
	if claim == nil {
		return fmt.Errorf("missing operator stream claim")
	}
	if claim.OperatorSession == "" || claim.StreamID == "" || claim.Capability == "" || claim.Nonce == "" {
		return fmt.Errorf("claim has empty required fields")
	}
	if len(claim.Signature) == 0 {
		return fmt.Errorf("missing claim signature")
	}
	if expectedSession == "" || expectedStreamID == "" || expectedCapability == "" {
		return fmt.Errorf("invalid expected claim context")
	}
	if claim.OperatorSession != expectedSession {
		return fmt.Errorf("claim operator session mismatch")
	}
	if claim.StreamID != expectedStreamID {
		return fmt.Errorf("claim stream id mismatch")
	}
	if claim.Capability != expectedCapability {
		return fmt.Errorf("claim capability mismatch")
	}

	now := time.Now().Unix()
	if claim.IssuedAt <= 0 || claim.ExpiresAt <= 0 || claim.ExpiresAt <= claim.IssuedAt {
		return fmt.Errorf("invalid claim timestamps")
	}
	if claim.ExpiresAt-now > OperatorClaimMaxTTLSeconds {
		return fmt.Errorf("claim ttl exceeds limit")
	}
	if claim.IssuedAt-now > ReplayWindowSeconds || now-claim.ExpiresAt > ReplayWindowSeconds {
		return fmt.Errorf("claim outside replay window")
	}

	canonical := CanonicalOperatorStreamClaimString(claim)
	ok, err := VerifySignatureWithPEM(operatorPubPEM, []byte(canonical), claim.Signature)
	if err != nil {
		return fmt.Errorf("claim signature verification error: %w", err)
	}
	if !ok {
		return fmt.Errorf("claim signature verification failed")
	}
	return nil
}
