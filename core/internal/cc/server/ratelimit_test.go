package server

import (
	"testing"

	"golang.org/x/time/rate"
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
