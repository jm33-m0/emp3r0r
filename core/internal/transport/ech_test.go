//go:build !no_doh && !no_ech

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Real ECH-publishing endpoints used by the integration tests. The ECHConfigList
// lives in the domain's DNS HTTPS RR; these are public test domains that
// advertise ECH behind Cloudflare/other ECH-capable edges.
var echRealDomains = []string{"crypto.cloudflare.com", "tls-ech.dev"}

const (
	echRealDoH        = "https://1.1.1.1/dns-query"
	echNoConfigDomain = "example.com"
)

// TestFetchECHConfigListRealDomain fetches the ECHConfigList for real domains
// from a real DoH resolver and checks the decoded list and TTL.
func TestFetchECHConfigListRealDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("real-network integration test")
	}
	for _, domain := range echRealDomains {
		t.Run(domain, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			list, ttl, err := fetchECHConfigList(ctx, echRealDoH, domain)
			if err != nil {
				t.Fatalf("fetch real ECH config for %s: %v", domain, err)
			}
			if len(list) == 0 {
				t.Fatalf("%s returned an empty ECHConfigList", domain)
			}
			if ttl <= 0 {
				t.Fatalf("%s returned TTL %s, want a positive DNS TTL", domain, ttl)
			}
			t.Logf("%s: %d-byte ECHConfigList, ttl %s", domain, len(list), ttl)
		})
	}
}

// TestFetchECHConfigListNoECHDomain verifies a domain without an ECH parameter
// in its HTTPS RR is rejected rather than yielding an empty config.
func TestFetchECHConfigListNoECHDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("real-network integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := fetchECHConfigList(ctx, echRealDoH, echNoConfigDomain); err == nil {
		t.Fatalf("%s unexpectedly produced an ECHConfigList", echNoConfigDomain)
	}
}

// TestECHStateMachineAndErrorPath covers the internal state the dialers consume:
// disabled ECH is a no-op, a configured-but-unfetchable config reports ok=true
// with an error, and a server retry list is cached and preferred.
func TestECHStateMachineAndErrorPath(t *testing.T) {
	t.Cleanup(func() { SetECHConfig("", "") })

	SetECHConfig("", "")
	if list, ok, err := echConfigList(context.Background()); ok || err != nil || list != nil {
		t.Fatalf("disabled ECH = (list=%q ok=%v err=%v), want (nil false nil)", list, ok, err)
	}

	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer failSrv.Close()
	SetECHConfig("c2.example.com", failSrv.URL)
	if list, ok, err := echConfigList(context.Background()); !ok || err == nil || list != nil {
		t.Fatalf("configured ECH with failing resolver = (list=%d ok=%v err=%v), want ok=true err!=nil", len(list), ok, err)
	}

	retry := []byte("server-provided-retry-ech-config")
	recordECHRetry(retry)
	if list, ok, err := echConfigList(context.Background()); !ok || err != nil || string(list) != string(retry) {
		t.Fatalf("cached retry list = (list=%q ok=%v err=%v), want the retry list", list, ok, err)
	}
	if !ECHEnabled() {
		t.Fatal("ECHEnabled should be true after SetECHConfig")
	}
	SetECHConfig("", "")
	if ECHEnabled() {
		t.Fatal("ECHEnabled should be false for an empty query name")
	}
}
