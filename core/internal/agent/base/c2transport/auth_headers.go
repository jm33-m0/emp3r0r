package c2transport

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// buildAuthHeaders constructs signed headers for agent -> C2 HTTP/H2 requests.
func buildAuthHeaders(method string, target *url.URL) (http.Header, error) {
	cfg := common.RuntimeConfig
	if cfg == nil {
		return nil, fmt.Errorf("runtime config not initialized")
	}
	if cfg.AgentUUID == "" || cfg.AgentUUIDSig == "" {
		return nil, fmt.Errorf("missing agent identity or CA signature")
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := util.RandStr(16)
	canonical := transport.CanonicalRequestString(method, target.Path, target.RawQuery, ts, nonce)

	sig, err := agentutils.SignWithAgentKey([]byte(canonical))
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	headers := make(http.Header)
	headers.Set(transport.HeaderClientID, cfg.AgentUUID)
	headers.Set(transport.HeaderClientCASignature, cfg.AgentUUIDSig)
	headers.Set(transport.HeaderRequestTimestamp, ts)
	headers.Set(transport.HeaderRequestNonce, nonce)
	headers.Set(transport.HeaderClientSignature, base64.URLEncoding.EncodeToString(sig))
	return headers, nil
}
