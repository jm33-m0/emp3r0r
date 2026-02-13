package transport

import "strings"

const (
	// Auth headers used for lightweight request authentication.
	HeaderClientID          = "X-Client-Id"
	HeaderClientSignature   = "X-Request-Signature"
	HeaderClientCASignature = "X-CA-Signature"
	HeaderRequestNonce      = "X-Request-Nonce"
	HeaderRequestTimestamp  = "X-Request-Timestamp"

	// ReplayWindowSeconds defines the allowed clock skew / replay window.
	ReplayWindowSeconds = 60
)

// CanonicalRequestString builds the canonical string that the agent signs.
// Order is fixed to avoid ambiguity across transports.
func CanonicalRequestString(method, path, rawQuery, timestamp, nonce string) string {
	parts := []string{
		strings.ToUpper(method),
		path,
		rawQuery,
		timestamp,
		nonce,
	}
	return strings.Join(parts, "\n")
}
