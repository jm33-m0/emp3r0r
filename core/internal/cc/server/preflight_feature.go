package server

import (
	"net/http"
	"net/url"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
)

// registerPreflightFeature wires preflight as an independent HTTP feature.
// It is transport-agnostic and can be attached to any HTTP-facing server.
// It returns the path it registered, or "" if preflight is disabled or its URL
// is unusable, so callers can avoid registering a conflicting catch-all.
func registerPreflightFeature(mux *http.ServeMux) string {
	if !live.RuntimeConfig.PreflightEnabled || live.RuntimeConfig.PreflightURL == "" {
		return ""
	}

	u, err := url.Parse(live.RuntimeConfig.PreflightURL)
	if err != nil {
		logging.Warningf("registerPreflightFeature: invalid preflight URL %q: %v", live.RuntimeConfig.PreflightURL, err)
		return ""
	}
	if u.Path == "" || u.Path == "/" {
		// A bare host would register "" and panic; a root preflight endpoint
		// collides with the h2/plain-HTTP catch-all. Skip either way.
		logging.Warningf("registerPreflightFeature: refusing to register preflight at %q", u.Path)
		return ""
	}

	logging.Infof("Registering preflight endpoint at %s", u.Path)
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, req *http.Request) {
		if !allowClientRequest(req) {
			logging.Warningf("Preflight: rate limit exceeded for %s", req.RemoteAddr)
			transport.WriteBareStatus(w, http.StatusTooManyRequests)
			return
		}

		if req.Method != live.RuntimeConfig.PreflightMethod {
			transport.WriteBareStatus(w, http.StatusMethodNotAllowed)
			return
		}

		body := make([]byte, 0)
		if req.Body != nil {
			buf := make([]byte, 4096)
			n, readErr := req.Body.Read(buf)
			if readErr != nil && readErr.Error() != "EOF" {
				transport.WriteBareStatus(w, http.StatusBadRequest)
				return
			}
			body = buf[:n]
		}

		hasOperators := false
		OPERATORS.Range(func(_, _ any) bool {
			hasOperators = true
			return false
		})

		respData, processErr := preflight.ProcessRequest(body, hasOperators)
		if processErr != nil {
			logging.Warningf("Preflight failed: %v", processErr)
			transport.WriteBareStatus(w, http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)
	})

	return u.Path
}
