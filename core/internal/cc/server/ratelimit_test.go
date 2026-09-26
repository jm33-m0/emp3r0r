package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestRateLimiterDirect(t *testing.T) {
	// Backup and restore limiters
	origGlobal := globalLimiter
	origIp := ipLimiter
	defer func() {
		globalLimiter = origGlobal
		ipLimiter = origIp
	}()

	// Configure small rate limits for testing
	globalLimiter = rate.NewLimiter(rate.Limit(5), 5)
	ipLimiter = &ipRateLimiter{}

	// Test IP rate limiter retrieval
	lim := ipLimiter.getLimiter("1.2.3.4")
	if lim == nil {
		t.Fatalf("getLimiter returned nil")
	}

	// Exhaust global limiter
	for i := 0; i < 5; i++ {
		if !globalLimiter.Allow() {
			t.Errorf("global limiter rejected request %d early", i)
		}
	}
	if globalLimiter.Allow() {
		t.Errorf("expected global limiter to block after 5 requests")
	}

	// Test per-IP rate limiter
	lim2 := ipLimiter.getLimiter("5.6.7.8")
	// By default, our per-IP limiter has limit 10, burst 20
	// Let's check that it allows up to its burst
	for i := 0; i < 20; i++ {
		if !lim2.Allow() {
			t.Errorf("IP limiter rejected request %d early", i)
		}
	}
	if lim2.Allow() {
		t.Errorf("expected IP limiter to block after 20 requests")
	}
}

// TestPreflightRateLimited verifies the preflight endpoint shares the same
// per-IP and global limiters as the C2 transport handlers.
func TestPreflightRateLimited(t *testing.T) {
	origGlobal := globalLimiter
	origIP := ipLimiter
	origEnabled := live.RuntimeConfig.PreflightEnabled
	origURL := live.RuntimeConfig.PreflightURL
	origMethod := live.RuntimeConfig.PreflightMethod
	t.Cleanup(func() {
		globalLimiter = origGlobal
		ipLimiter = origIP
		live.RuntimeConfig.PreflightEnabled = origEnabled
		live.RuntimeConfig.PreflightURL = origURL
		live.RuntimeConfig.PreflightMethod = origMethod
	})

	// Consume the only global token so the request is rejected before any
	// preflight crypto runs.
	globalLimiter = rate.NewLimiter(rate.Limit(1), 1)
	globalLimiter.Allow()
	ipLimiter = &ipRateLimiter{}
	live.RuntimeConfig.PreflightEnabled = true
	live.RuntimeConfig.PreflightURL = "http://example.com/preflight"
	live.RuntimeConfig.PreflightMethod = http.MethodPost

	mux := http.NewServeMux()
	registerPreflightFeature(mux)

	req := httptest.NewRequest(http.MethodPost, "/preflight", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("preflight endpoint should be rate limited, got %d", rec.Code)
	}
}
