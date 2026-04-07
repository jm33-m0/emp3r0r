package server

import (
	"net/http"
	"net/url"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
)

// registerPreflightFeature wires preflight as an independent HTTP feature.
// It is transport-agnostic and can be attached to any HTTP-facing server.
func registerPreflightFeature(mux *http.ServeMux) {
	if !live.RuntimeConfig.PreflightEnabled || live.RuntimeConfig.PreflightURL == "" {
		return
	}

	u, err := url.Parse(live.RuntimeConfig.PreflightURL)
	if err != nil {
		logging.Warningf("registerPreflightFeature: invalid preflight URL %q: %v", live.RuntimeConfig.PreflightURL, err)
		return
	}

	logging.Infof("Registering preflight endpoint at %s", u.Path)
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != live.RuntimeConfig.PreflightMethod {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		body := make([]byte, 0)
		if req.Body != nil {
			buf := make([]byte, 4096)
			n, readErr := req.Body.Read(buf)
			if readErr != nil && readErr.Error() != "EOF" {
				http.Error(w, "Read error", http.StatusBadRequest)
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
			http.Error(w, "Preflight failed", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)
	})
}
