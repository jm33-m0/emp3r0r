package main

import (
	"testing"
	"time"
)

// TestC2BackoffDoublingAndCap exercises the real backoff state machine via an
// injected no-op sleeper: takeC2Backoff doubles the interval and clamps at
// c2BackoffMax, resetC2Backoff restores the initial value, and growth from the
// initial value reaches the cap within a sane number of doublings.
func TestC2BackoffDoublingAndCap(t *testing.T) {
	origBackoff := c2Backoff
	origSleep := c2BackoffSleep
	c2BackoffSleep = func(time.Duration) {} // no-op sleeper
	defer func() {
		c2Backoff = origBackoff
		c2BackoffSleep = origSleep
	}()

	// Doubling from the initial value must reach the cap in ~8 steps (5s->10m).
	steps := 0
	b := c2BackoffInitial
	for b < c2BackoffMax && steps < 100 {
		steps++
		b *= 2
	}
	if b < c2BackoffMax {
		t.Fatalf("backoff never reached the cap after %d doublings (b=%v)", steps, b)
	}
	if steps > 12 {
		t.Fatalf("backoff needed %d doublings to reach cap, want <= 12", steps)
	}

	// Real doubling: 1ms -> 2ms.
	c2Backoff = time.Millisecond
	takeC2Backoff()
	if c2Backoff != 2*time.Millisecond {
		t.Fatalf("takeC2Backoff did not double: got %v want 2ms", c2Backoff)
	}

	// Cap: near the max, doubling must clamp to c2BackoffMax.
	c2Backoff = c2BackoffMax - time.Millisecond
	takeC2Backoff()
	if c2Backoff != c2BackoffMax {
		t.Fatalf("takeC2Backoff did not cap at max: got %v want %v", c2Backoff, c2BackoffMax)
	}

	// Reset restores the initial value.
	resetC2Backoff()
	if c2Backoff != c2BackoffInitial {
		t.Fatalf("resetC2Backoff set %v, want initial %v", c2Backoff, c2BackoffInitial)
	}
}
