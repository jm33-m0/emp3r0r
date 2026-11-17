package detection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	// maxWorkerTokens covers reasoning plus the required answer. A reasoning
	// model that spends its whole per-turn budget thinking would otherwise
	// return a truncated turn, which the loop cannot distinguish from a
	// deliberate empty answer.
	maxWorkerTokens = 32768
	// maxEmptyTurns bounds in-session recovery from a model that keeps
	// returning no text and no tool call.
	maxEmptyTurns = 2
	// maxSessionRestarts bounds retries of one worker step after deadlines or
	// provider failures. The loop then reports an infrastructure failure
	// instead of starting another indistinguishable session.
	maxSessionRestarts = 4
)

var (
	// errWorkerEmpty marks a worker step that produced no usable answer after
	// in-session recovery. The coordinator treats it as infrastructure, not as
	// a failed hypothesis.
	errWorkerEmpty = errors.New("model worker returned no answer")
	// errSessionRestarts marks a worker step that could not complete after its
	// retry budget.
	errSessionRestarts = errors.New("model session did not complete")
	// errCycleInfrastructure marks a cycle that failed before producing a
	// detection result because the host (not the hypothesis) was unavailable.
	errCycleInfrastructure = errors.New("host cycle failed before a detection result")
)

// workerResult is the terminal state of one model turn.
type workerResult struct {
	text   string
	reason harness.TerminalReason
	turns  int
	usage  llm.Usage
	err    error
}

func (r workerResult) empty() bool {
	return strings.TrimSpace(r.text) == ""
}

// workerSession owns one agentcore session for one logical worker step. The
// session keeps its conversation across deadline retries, so a forced answer
// continues from the evidence already read instead of re-reading the dossier
// from scratch. The caller closes it when the step is decided.
type workerSession struct {
	c    *coordinator
	role evolveRole
	sess *agentcore.Session
}

func (c *coordinator) newWorkerSession(role evolveRole) *workerSession {
	opts := agentcore.Options{
		Provider:               c.provider,
		SystemPrompt:           []string{roleSystemPrompt(role)},
		Tools:                  c.e.toolsFor(role),
		PermissionMode:         permission.ModeDontAsk,
		Hooks:                  c.e.hooksFor(role),
		WorkingDir:             c.e.cfg.ModuleDir,
		MaxTurns:               c.turns(role),
		MaxTokens:              maxWorkerTokens,
		EscalateMaxTokens:      true,
		DisableBackgroundTasks: true,
		Compaction:             &compaction.Config{ContextWindow: 200000, MaxOutputTokens: maxWorkerTokens, KeepRecent: 8},
		Settlement:             c.settlementFor(role),
		OnWarn:                 func(line string) { c.e.logf(logging.ClassWarning, "%s: %s", role.label(), line) },
	}
	if timeout := c.sessionTimeout(role); timeout > 0 {
		// MaxDuration is checked at the turn boundary and triggers the
		// settlement prompt. The watchdog remains the mid-stream stop.
		opts.MaxDuration = timeout
	}
	if store := c.transcriptStore(); store != nil {
		opts.Transcript = store
	}
	return &workerSession{c: c, role: role, sess: agentcore.NewSession(opts)}
}

func (ws *workerSession) close() {
	_ = ws.sess.Close()
}

// run executes one prompt and retries the same session when it is cut by a
// deadline, provider error, or empty turn. Deadline and empty retries continue
// the conversation; they never create a fresh session.
func (ws *workerSession) run(ctx context.Context, prompt string, resume func(reason string) string) (workerResult, error) {
	c := ws.c
	sessionTimeout := c.sessionTimeout(ws.role)
	hardSession := ws.role == rolePlanner
	if hardSession && c.e.cfg.PlannerTimeout > 0 {
		sessionTimeout = c.e.cfg.PlannerTimeout
	}
	idleTimeout := c.idleTimeout(ws.role)
	emptyTurns := 0
	restarts := 0
	for attempt := 0; ; attempt++ {
		c.e.sessions.Add(1)
		sessionCtx, cancel := context.WithCancel(ctx)
		c.e.setSessionCancel(cancel)
		var sessionExpired, idleExpired atomic.Bool
		c.e.deadlineHit.Store(false)
		started := time.Now()
		c.e.lastToolCall.Store(started.UnixNano())
		watchdogDone := make(chan struct{})
		go c.watchdog(sessionCtx, cancel, watchdogDone, hardSession, sessionTimeout, idleTimeout, started, &sessionExpired, &idleExpired)
		result, err := ws.prompt(sessionCtx, prompt)
		close(watchdogDone)
		cancel()
		c.e.recordWorkerUsage(result)
		c.e.logClass(logging.ClassLine, "%s session ended: reason=%s turns=%d in=%d out=%d",
			ws.role.label(), headerOrNone(string(result.reason)), result.turns,
			result.usage.InputTokens, result.usage.OutputTokens)

		if c.e.sessionStopped() {
			return result, nil
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		var halted string
		switch {
		case sessionExpired.Load():
			halted = "session"
			c.e.logClass(logging.ClassWarning,
				"%s: decision window elapsed after %s; forcing the required output", ws.role.label(), sessionTimeout)
		case idleExpired.Load():
			halted = "idle"
			c.e.logClass(logging.ClassWarning, "%s: session made no tool call for %s", ws.role.label(), idleTimeout)
		}
		if halted != "" {
			restarts++
			if restarts > maxSessionRestarts {
				return result, fmt.Errorf("%w: %s stopped %d times (%s)", errSessionRestarts, ws.role.label(), restarts, halted)
			}
			prompt = resume(halted)
			continue
		}

		if err == nil && !result.empty() && result.err == nil {
			return result, nil
		}
		if err == nil {
			err = result.err
		}
		if err != nil {
			if ws.role == roleDebugger && attempt >= 2 {
				return result, fmt.Errorf("debugger session failed: %w", err)
			}
			restarts++
			if restarts > maxSessionRestarts {
				return result, fmt.Errorf("%w: %v", errSessionRestarts, err)
			}
			if !c.e.recover(ctx, attempt, ws.role.label()+" session", err) {
				return result, ctx.Err()
			}
			prompt = resume("provider")
			continue
		}

		emptyTurns++
		if emptyTurns > maxEmptyTurns {
			return result, fmt.Errorf("%w: %s returned %s with no text and no tool call",
				errWorkerEmpty, ws.role.label(), headerOrNone(string(result.reason)))
		}
		c.e.logClass(logging.ClassWarning,
			"%s: empty model turn (%s); asking for the required output", ws.role.label(), headerOrNone(string(result.reason)))
		prompt = resume("empty")
	}
}

// prompt runs one model turn and captures the terminal state. A terminal event
// is delivered even when the context is cancelled, so the conversation is
// retained for the next attempt.
func (ws *workerSession) prompt(ctx context.Context, input string) (workerResult, error) {
	var out workerResult
	var terminal bool
	var streamErr error
	for event, err := range ws.sess.Prompt(ctx, input) {
		if err != nil {
			streamErr = err
			break
		}
		switch event.Kind {
		case harness.KindUsage:
			if event.Usage != nil {
				out.usage = *event.Usage
			}
		case harness.KindResult:
			if event.Terminal != nil {
				out.text = event.Terminal.Text
				out.reason = event.Terminal.Reason
				out.turns = event.Terminal.Turns
				out.usage = event.Terminal.Usage
				out.err = event.Terminal.Err
				terminal = true
			}
		}
	}
	if !terminal {
		if streamErr != nil {
			return out, fmt.Errorf("model session ended without a terminal event: %w", streamErr)
		}
		return out, fmt.Errorf("model session ended without a terminal event")
	}
	return out, streamErr
}

// runSession is the single-step helper used by tests and by callers that do
// not need to continue a session after a parse error.
func (c *coordinator) runSession(ctx context.Context, role evolveRole, prompt string, resume func(reason string) string) (string, error) {
	ws := c.newWorkerSession(role)
	defer ws.close()
	result, err := ws.run(ctx, prompt, resume)
	return result.text, err
}

// settlementFor forces the worker contract when MaxTurns or MaxDuration is
// reached. The read-only tools are hidden so the model must answer with the
// action or JSON it already has.
func (c *coordinator) settlementFor(role evolveRole) *harness.Settlement {
	switch role {
	case rolePlanner:
		return &harness.Settlement{
			Prompt:   "The planner budget is exhausted. Return exactly one planner JSON object now: action=test, action=debug only when the brief says the debugger is available, or action=stop. Do not call tools.",
			MaxTurns: 2, DisabledTools: readOnlyToolNames(),
		}
	case roleEditor:
		return &harness.Settlement{
			Prompt:   "The editor budget is exhausted. Apply the remaining edit with EditSource now and call DetectionCycle exactly once. If you cannot, return the result JSON. Do not read more files.",
			MaxTurns: 2, DisabledTools: readOnlyToolNames(),
		}
	case roleDebugger:
		return &harness.Settlement{
			Prompt:   "The debugger budget is exhausted. Return exactly one debugger JSON object now with the cause, evidence, guest actions, and whether the agent is online.",
			MaxTurns: 2, DisabledTools: []string{"GuestSSH", "AgentStatus", "RunModule", "CleanupAgent"},
		}
	}
	return nil
}

// transcriptStore persists every worker session so a failed or empty turn can
// be inspected after the fact. The store lives under the detection root, which
// is already private to the operator.
func (c *coordinator) transcriptStore() *transcript.Store {
	root := strings.TrimSpace(c.e.cfg.StoreRoot)
	if root == "" {
		return nil
	}
	name := sanitizeName(c.e.cfg.LoopID)
	if name == "" {
		name = "loop"
	}
	dir := filepath.Join(root, "transcripts", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.e.logClass(logging.ClassWarning, "create transcript directory: %v", err)
		return nil
	}
	return transcript.NewStore(dir)
}

// recordWorkerUsage folds one terminal usage into the loop counters used by
// the progress heartbeat and the worker audit row.
func (e *evolver) recordWorkerUsage(result workerResult) {
	if result.usage.InputTokens > 0 {
		e.tokensIn.Add(int64(result.usage.InputTokens))
	}
	if result.usage.OutputTokens > 0 {
		e.tokensOut.Add(int64(result.usage.OutputTokens))
	}
	if result.reason != "" {
		e.lastReason.Store(string(result.reason))
	}
}

// readOnlyToolNames lists the tools that do not change source, artifacts, or
// the guest. The editor and planner lose these at the settlement boundary.
func readOnlyToolNames() []string {
	return []string{
		"SourceList", "SourceRead", "SourceSearch", "TelemetryQuery",
		"InspectFeedback", "Payloads", "ComparePayloads", "GitHistory",
		"KnowledgeSearch", "KnowledgeRead", "KnowledgeStats", "KnowledgeList",
		"AgentStatus",
	}
}

// isInfrastructureFailure reports a worker failure that says nothing about the
// hypothesis: an empty turn, a provider error, or a session that could not be
// restarted. These are retried with backoff instead of ending the loop.
func isInfrastructureFailure(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errWorkerEmpty) ||
		errors.Is(err, errSessionRestarts) ||
		errors.Is(err, errCycleInfrastructure) ||
		errors.Is(err, ErrSandboxUnreachable) ||
		errors.Is(err, context.DeadlineExceeded)
}
