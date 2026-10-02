package main

import (
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestInitialCheckinDelay verifies the first check-in jitter scales with the
// configured beacon profile: the default profile keeps the historical 3-10s
// spread, an effectively zero jitter window skips the delay, and an oversized
// profile is capped so a long poll interval cannot delay first contact for
// minutes.
func TestInitialCheckinDelay(t *testing.T) {
	cases := []struct {
		name       string
		config     *def.Config
		wantZero   bool
		wantMin    time.Duration
		wantMax    time.Duration
		iterations int
	}{
		{
			name:     "nil config skips",
			config:   nil,
			wantZero: true,
		},
		{
			name:     "zero poll interval skips",
			config:   &def.Config{PollInterval: 0, Jitter: 20},
			wantZero: true,
		},
		{
			name:     "zero jitter skips",
			config:   &def.Config{PollInterval: 60, Jitter: 0},
			wantZero: true,
		},
		{
			name:     "e2e style tiny jitter skips",
			config:   &def.Config{PollInterval: 60, Jitter: 1},
			wantZero: true,
		},
		{
			name:       "default profile keeps the historical window",
			config:     &def.Config{PollInterval: 60, Jitter: 20},
			wantMin:    3 * time.Second,
			wantMax:    10 * time.Second,
			iterations: 50,
		},
		{
			name:       "long interval is capped",
			config:     &def.Config{PollInterval: 300, Jitter: 50},
			wantMin:    3 * time.Second,
			wantMax:    10 * time.Second,
			iterations: 50,
		},
		{
			name:       "small window keeps a floor of its own size",
			config:     &def.Config{PollInterval: 10, Jitter: 20},
			wantMin:    2 * time.Second,
			wantMax:    2 * time.Second,
			iterations: 20,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantZero {
				if got := initialCheckinDelay(tc.config); got != 0 {
					t.Fatalf("initialCheckinDelay() = %v, want 0", got)
				}
				return
			}
			for i := 0; i < tc.iterations; i++ {
				got := initialCheckinDelay(tc.config)
				if got < tc.wantMin || got > tc.wantMax {
					t.Fatalf("initialCheckinDelay() = %v, want within [%v, %v]", got, tc.wantMin, tc.wantMax)
				}
			}
		})
	}
}
