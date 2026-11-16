package detection

import (
	"context"
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
			execution := "pending"
			if value := e.lastExecution.Load(); value != nil {
				execution = headerOrNone(value.(string))
			}
			agent := "none"
			if value := e.lastAgent.Load(); value != nil {
				agent = headerOrNone(value.(string))
			}
			e.logClass(logging.ClassProgress,
				"[progress] elapsed=%s cycles=%d/%d tools=%d sessions=%d last_execution=%s agent=%s",
				time.Since(e.started).Round(time.Second), e.cyclesDone.Load(), e.cfg.Iterations,
				e.toolCalls.Load(), e.sessions.Load(), execution, agent)
		}
	}
}
