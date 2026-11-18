package detection

import (
	"context"
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// progressLoop emits a heartbeat so a long model session does not look stuck.
// It reads only atomics, so it cannot race the loop's mutable dossier state.
func (e *evolver) progressLoop(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(defaultProgressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			e.logClass(logging.ClassProgress, "%s", e.progressSummary())
		}
	}
}

// progressSummary renders the heartbeat fields, including the token-cost
// estimate. It is separate so the display can be tested without a ticker.
func (e *evolver) progressSummary() string {
	execution := "pending"
	if value := e.lastExecution.Load(); value != nil {
		execution = headerOrNone(value.(string))
	}
	agent := "none"
	if value := e.lastAgent.Load(); value != nil {
		agent = headerOrNone(value.(string))
	}
	reason := "none"
	if value := e.lastReason.Load(); value != nil {
		reason = headerOrNone(value.(string))
	}
	usage := e.usage.snapshot(e.cfg.Pricing)
	return fmt.Sprintf(
		"[progress] elapsed=%s cycles=%d/%d tools=%d sessions=%d in=%d out=%d cache_read=%d cache_write=%d cost=%s reason=%s last_execution=%s agent=%s",
		time.Since(e.started).Round(time.Second), e.cyclesDone.Load(), e.cfg.Iterations,
		e.toolCalls.Load(), e.sessions.Load(), usage.Input, usage.Output,
		usage.CacheRead, usage.CacheWrite, costLabel(usage),
		reason, execution, agent)
}
