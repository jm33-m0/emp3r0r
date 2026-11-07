package mcp

import (
	"sync"
	"time"
)

// Limiter is a token bucket for mutating actions. It bounds a model that
// retries a blocked action in a tight loop. A nil Limiter allows everything.
type Limiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	perSec float64
	last   time.Time
}

// NewLimiter returns a limiter for perMinute actions with the given burst. A
// perMinute of zero disables the limiter.
func NewLimiter(perMinute, burst int) *Limiter {
	if perMinute <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 5
	}
	return &Limiter{
		tokens: float64(burst),
		burst:  float64(burst),
		perSec: float64(perMinute) / 60,
		last:   time.Now(),
	}
}

// Allow consumes one token. It returns false and the wait until the next token
// when the bucket is empty.
func (l *Limiter) Allow() (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * l.perSec
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens < 1 {
		wait := time.Duration((1-l.tokens)/l.perSec*float64(time.Second)) + time.Millisecond
		return false, wait
	}
	l.tokens--
	return true, 0
}
