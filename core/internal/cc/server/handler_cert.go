package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// maxEnsureCertHosts bounds one operator request so a hostile operator cannot
// grow the certificate SAN list without limit.
const maxEnsureCertHosts = 32

// handleEnsureCert adds host names to the C2 TLS certificate and publishes the
// new certificate for subsequent TLS/QUIC handshakes. Existing connections keep
// their negotiated certificate.
func handleEnsureCert(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleEnsureCert panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()

	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
		return
	}
	certReq, err := DecodeCBORBody[def.EnsureCertRequest](wrt, req)
	if err != nil {
		return
	}
	hosts := normalizeCertHosts(certReq.Hosts)
	if len(hosts) == 0 {
		http.Error(wrt, "no valid hosts", http.StatusBadRequest)
		return
	}

	if err := config.GenC2Certs(strings.Join(hosts, " ")); err != nil {
		logging.Errorf("handleEnsureCert: %v", err)
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
		return
	}
	auditOperatorAction(operatorID, "update_cert", "", strings.Join(hosts, ","))

	certs, err := readC2Certs()
	if err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := cbor.Marshal(certs)
	if err != nil {
		http.Error(wrt, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	wrt.Header().Set("Content-Type", "application/cbor")
	wrt.WriteHeader(http.StatusOK)
	_, _ = wrt.Write(data)
}

func normalizeCertHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || len(out) >= maxEnsureCertHosts {
			continue
		}
		if !netutil.ValidateHostName(host) {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func readC2Certs() (map[string][]byte, error) {
	caData, err := os.ReadFile(transport.CaCrtFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	serverCrtData, err := os.ReadFile(transport.ServerCrtFile)
	if err != nil {
		return nil, fmt.Errorf("read server cert: %w", err)
	}
	return map[string][]byte{
		"ca_crt":     caData,
		"server_crt": serverCrtData,
	}, nil
}
