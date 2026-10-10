package server

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// OperatorConfig is one provisioned operator: its WireGuard identity plus the
// human-readable name shown to other operators. It is persisted in
// wg_config.json so a restart keeps the same operator identities.
type OperatorConfig struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// operatorIndex maps a provisioned operator's WireGuard IP to its config. The
// WG IP is the operator's stable identity: the server sees it as the mTLS peer
// address and the operator knows it from --operator-wg-ip, so both sides agree
// without extra handshake state. It is written once at startup and read-only
// afterwards.
var operatorIndex sync.Map // WG IP -> *OperatorConfig

// registerOperators publishes the provisioned operator identities. It is called
// once, after the WireGuard config has been loaded or generated.
func registerOperators(configs []OperatorConfig) {
	for i := range configs {
		cfg := &configs[i]
		if cfg.Name == "" {
			cfg.Name = fmt.Sprintf("operator-%d", i+1)
		}
		if cfg.IP != "" {
			operatorIndex.Store(cfg.IP, cfg)
		}
	}
}

// operatorByIP returns the provisioned operator that owns ip, or nil.
func operatorByIP(ip string) *OperatorConfig {
	if ip == "" {
		return nil
	}
	v, ok := operatorIndex.Load(ip)
	if !ok {
		return nil
	}
	cfg, ok := v.(*OperatorConfig)
	if !ok || cfg == nil {
		return nil
	}
	return cfg
}

// operatorDisplayName returns the display name for a WireGuard IP, falling back
// to the IP itself so logs and the agent list always have something to show.
func operatorDisplayName(ip string) string {
	if cfg := operatorByIP(ip); cfg != nil {
		return cfg.Name
	}
	return ip
}

// operatorIDFromRemote derives the operator identity from a request's remote
// address. The operator mTLS listener is bound to the userspace WireGuard
// stack, so the peer IP is the operator's provisioned WG IP.
func operatorIDFromRemote(remoteAddr string) string {
	ip := remoteHost(remoteAddr)
	if cfg := operatorByIP(ip); cfg != nil {
		return cfg.IP
	}
	return ""
}

// operatorRequestIdentity resolves the stable operator identity for a request:
// the provisioned WG IP when the peer is one. The client-supplied session header
// is trusted only from the local host (single-host/local mode and embedders) so
// a network peer can never claim another operator's identity by setting it.
func operatorRequestIdentity(remoteAddr, sessionHeader string) string {
	if id := operatorIDFromRemote(remoteAddr); id != "" {
		return id
	}
	if isLoopbackIP(remoteHost(remoteAddr)) {
		return strings.TrimSpace(sessionHeader)
	}
	return ""
}

// remoteHost strips the port from a remote address.
func remoteHost(remoteAddr string) string {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// isLoopbackIP reports whether host is a local address.
func isLoopbackIP(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
