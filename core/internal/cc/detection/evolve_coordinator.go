package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	maxEditorFailures   = 3
	maxDebuggerSessions = 4
	maxWorkerTokens     = 16384
)

// coordinator owns the role sequencing and the structural decisions. The
// workers only reason over their own tool sets.
type coordinator struct {
	e        *evolver
	provider llm.Provider
	model    string

	baselineJSON   json.RawMessage
	executionState string
	knowledgeState string

	plannerNote      string
	lastEditorError  string
	lastDiagnosis    *debugDiagnosis
	debugged         map[int64]bool
	editorFailures   int
	debuggerSessions int
	plans            int
	currentPlan      plannerPlan
}

func newCoordinator(e *evolver, provider llm.Provider, model string, baselineJSON json.RawMessage, executionState, knowledgeState string) *coordinator {
	return &coordinator{
		e: e, provider: provider, model: model,
		baselineJSON: baselineJSON, executionState: executionState,
		knowledgeState: knowledgeState, debugged: make(map[int64]bool),
	}
}

func (c *coordinator) run(ctx context.Context) (map[string]any, error) {
	if err := c.afterBaseline(ctx); err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.plans++
		if c.plans > c.e.cfg.Iterations*4+10 {
			return c.editorFailureFinal(fmt.Errorf("the coordinator exceeded its planning budget")), nil
		}
		plan, err := c.plan(ctx)
		if err != nil {
			return nil, err
		}
		switch plan.Action {
		case "stop":
			final := plan.Final
			if final == nil {
				final = map[string]any{}
			}
			if _, ok := final["summary"]; !ok {
				final["summary"] = "the planner stopped the loop"
			}
			c.e.lastAnswer = final
			if c.e.usedCycles() < c.e.cfg.Iterations && c.e.needsMoreWork(ctx) {
				c.e.logClass(logging.ClassWarning, "planner stopped with work remaining; resuming")
				c.plannerNote = "real verdicts or actionable high/medium findings remain; continue the loop"
				c.editorFailures = 0
				if !c.e.backoff(ctx, c.editorFailures, "the plan stopped while work remains") {
					return nil, ctx.Err()
				}
				continue
			}
			return final, nil
		case "test":
			if c.e.executionBlocked {
				c.plannerNote = "execution is blocked; return action=stop with the final JSON, or action=debug when the guest can explain why the payload never ran"
				continue
			}
			if c.e.usedCycles() >= c.e.cfg.Iterations {
				c.plannerNote = "the cycle budget is exhausted; return action=stop with the final JSON"
				continue
			}
			before := c.e.iter
			if err := c.edit(ctx, plan); err != nil {
				c.lastEditorError = err.Error()
				c.editorFailures++
				c.e.logClass(logging.ClassWarning, "editor worker: %v", err)
				if c.e.guest != nil && strings.Contains(strings.ToLower(err.Error()), "did not execute") {
					// The sandbox did not start the artifact: this is a guest
					// execution fault, not a detection result. Diagnose it
					// before asking for another build.
					if diag, diagErr := c.debug(ctx, "the sandbox did not execute the artifact: "+clip(err.Error(), 300), c.e.last); diagErr != nil {
						c.e.logClass(logging.ClassWarning, "debugger worker: %v", diagErr)
					} else if diag != nil {
						c.lastDiagnosis = diag
					}
				}
				if c.editorFailures >= maxEditorFailures {
					return c.editorFailureFinal(err), nil
				}
				continue
			}
			if c.e.iter == before {
				c.lastEditorError = "the editor returned without a completed DetectionCycle"
				c.editorFailures++
				if c.editorFailures >= maxEditorFailures {
					return c.editorFailureFinal(fmt.Errorf("%s", c.lastEditorError)), nil
				}
				continue
			}
			c.lastEditorError = ""
			c.editorFailures = 0
			if err := c.afterCycle(ctx, c.e.last); err != nil {
				return nil, err
			}
		case "debug":
			if c.e.guest == nil {
				c.plannerNote = "the guest debugger is not configured; return action=stop or action=test"
				continue
			}
			if _, err := c.debug(ctx, "planner request: "+clip(plan.DebugFocus, 300), c.e.last); err != nil {
				c.e.logClass(logging.ClassWarning, "debugger worker: %v", err)
				c.plannerNote = "the debugger could not complete: " + clip(err.Error(), 300)
			}
		}
	}
}

func (c *coordinator) editorFailureFinal(err error) map[string]any {
	summary := "the editor worker could not complete a cycle"
	residual := []string{"editor failure: " + clip(err.Error(), 1000)}
	final := map[string]any{
		"summary": summary, "edits": []any{}, "residual": residual,
		"parse_error": "the editor worker stopped before a completed cycle",
	}
	c.e.lastAnswer = final
	c.e.logClass(logging.ClassError, "stopping after repeated editor failures: %v", err)
	return final
}

func (c *coordinator) afterBaseline(ctx context.Context) error {
	last := c.e.last
	if last == nil || last.LoopID != c.e.cfg.LoopID {
		return nil
	}
	return c.afterCycle(ctx, last)
}

func (c *coordinator) afterCycle(ctx context.Context, cycle *Cycle) error {
	defer func() {
		c.executionState = c.e.executionHint()
		c.e.lastCycleAt.Store(time.Now().UnixNano())
	}()
	if cycle == nil {
		return nil
	}
	var summary cycleSummary
	if err := json.Unmarshal([]byte(cycle.Summary), &summary); err != nil {
		c.e.logClass(logging.ClassWarning, "decode cycle %d summary: %v", cycle.Iteration, err)
		summary.Execution = cycle.Execution
	}
	gate := c.e.recordExecution(cycle, summary)
	if gate != gateRestore && gate != gateBlocked {
		return nil
	}
	restore := gate == gateRestore
	if c.e.guest == nil {
		if restore {
			c.e.logClass(logging.ClassWarning, "cycle %d did not execute; restoring payload %s",
				cycle.Iteration, shortPayloadKey(c.e.lastExecuting.PayloadKey))
			c.e.restoreExecutingState(ctx)
		}
		return nil
	}
	if cycle.ID != 0 && c.debugged[cycle.ID] {
		if restore {
			c.e.restoreExecutingState(ctx)
		}
		return nil
	}
	if cycle.ID != 0 {
		c.debugged[cycle.ID] = true
	}
	diag, err := c.debug(ctx, fmt.Sprintf("execution=%s on cycle %d", headerOrNone(summary.Execution), cycle.Iteration), cycle)
	if err != nil {
		c.e.logClass(logging.ClassWarning, "debugger worker: %v", err)
		if restore {
			c.e.restoreExecutingState(ctx)
		}
		return nil
	}
	if diag != nil && c.e.lastExecutionVerified(cycle) {
		return nil
	}
	if restore {
		c.e.logClass(logging.ClassWarning, "cycle %d did not execute; restoring payload %s",
			cycle.Iteration, shortPayloadKey(c.e.lastExecuting.PayloadKey))
		c.e.restoreExecutingState(ctx)
	}
	return nil
}

func (e *evolver) lastExecutionVerified(cycle *Cycle) bool {
	return cycle != nil && cycle.Execution == executionVerified && e.lastExecuting == cycle
}

// plan asks the coordinator worker for the next move. A plan that is not
// JSON is repaired while budget remains; when the budget is gone the loop
// reports the failure instead of looping forever.
func (c *coordinator) plan(ctx context.Context) (plannerPlan, error) {
	prompt := c.plannerBrief()
	for attempt := 0; ; attempt++ {
		text, err := c.runSession(ctx, rolePlanner, prompt, c.plannerResume)
		if err != nil {
			return plannerPlan{}, err
		}
		plan, parseErr := parsePlannerPlan(text)
		c.recordWorker(ctx, rolePlanner, prompt, text, parseErr)
		if parseErr == nil {
			c.e.logClass(logging.ClassCycle, "planner: action=%s mechanism=%s", plan.Action, headerOrNone(plan.Mechanism))
			return plan, nil
		}
		c.e.logClass(logging.ClassWarning, "planner answer was not a valid plan: %v", parseErr)
		if c.e.usedCycles() >= c.e.cfg.Iterations || c.e.executionBlocked {
			return plannerPlan{Action: "stop", Final: c.planFailureFinal(text, parseErr)}, nil
		}
		if !c.e.backoff(ctx, attempt, "invalid planner answer") {
			return plannerPlan{}, ctx.Err()
		}
		prompt = c.plannerBrief() + "\n\nYour previous answer was not the required JSON object: " + parseErr.Error() + ". Return one JSON object now."
	}
}

func (c *coordinator) planFailureFinal(text string, err error) map[string]any {
	summary := strings.TrimSpace(text)
	if summary == "" {
		summary = "the planner did not return a plan"
	}
	final := map[string]any{
		"summary":     clip(summary, 4000),
		"edits":       []any{},
		"residual":    []string{"the planner did not return the required JSON object: " + clip(err.Error(), 1000)},
		"parse_error": "the planner did not return the required JSON object",
	}
	c.e.lastAnswer = final
	return final
}

func (c *coordinator) edit(ctx context.Context, plan plannerPlan) error {
	c.currentPlan = plan
	c.e.sessionCycles.Store(0)
	c.e.actionRequired.Store(false)
	// The planner may have used part of the previous window; give the editor a
	// full cycle deadline for the build and detonation.
	c.e.lastCycleAt.Store(time.Now().UnixNano())
	prompt := c.editorBrief(plan)
	text, err := c.runSession(ctx, roleEditor, prompt, c.editorResume)
	if err != nil {
		c.recordWorker(ctx, roleEditor, prompt, text, err)
		return err
	}
	c.recordWorker(ctx, roleEditor, prompt, text, nil)
	c.e.logClass(logging.ClassAnswer, "%s", clip(text, 6000))
	if c.e.sessionCycles.Load() == 0 {
		return fmt.Errorf("the editor returned without running DetectionCycle")
	}
	return nil
}

func (c *coordinator) debug(ctx context.Context, trigger string, cycle *Cycle) (*debugDiagnosis, error) {
	if c.debuggerSessions >= maxDebuggerSessions {
		return nil, fmt.Errorf("debugger session limit reached (%d)", maxDebuggerSessions)
	}
	if c.e.guest == nil {
		return nil, fmt.Errorf("guest SSH is not configured")
	}
	c.debuggerSessions++
	exclusion := "not verified"
	status, exclusionErr := c.e.guest.EnsureExclusion(ctx)
	if exclusionErr != nil {
		exclusion = "verification failed: " + clip(exclusionErr.Error(), 400)
	} else {
		exclusion = fmt.Sprintf("%s present (added=%v)", status.Path, status.Added)
		c.e.audit("guest_exclusion", c.e.guestAddr(), fmt.Sprintf("path=%s added=%v", status.Path, status.Added))
	}
	c.e.logClass(logging.ClassLine, "guest debug exclusion: %s", exclusion)
	prompt := c.debuggerBrief(ctx, trigger, cycle) + "\nGuest exclusion: " + exclusion
	text, err := c.runSession(ctx, roleDebugger, prompt, c.debuggerResume)
	if err != nil {
		c.recordWorker(ctx, roleDebugger, prompt, text, err)
		return nil, err
	}
	diag, parseErr := parseDebugDiagnosis(text)
	c.recordWorker(ctx, roleDebugger, prompt, text, parseErr)
	if parseErr != nil {
		return nil, parseErr
	}
	c.lastDiagnosis = &diag
	c.e.logClass(logging.ClassCycle, "debugger: cause=%s source_fix=%v online=%v",
		clip(diag.Cause, 200), diag.SourceFixRequired, diag.AgentOnlineAfter)
	if c.confirmOnline(ctx) {
		c.recoverCycle(ctx, cycle, diag)
		return &diag, nil
	}
	return &diag, nil
}

func (c *coordinator) confirmOnline(ctx context.Context) bool {
	if c.e.cfg.Verify == nil || strings.TrimSpace(c.e.expectedAgentUUID) == "" {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, PayloadVerifyTimeout)
	defer cancel()
	status, err := c.e.cfg.Verify.AgentStatus(checkCtx, c.e.expectedAgentUUID)
	if err != nil || status == nil || !status.Online {
		return false
	}
	c.e.agentSeenOnline.Store(true)
	return true
}

func (c *coordinator) recoverCycle(ctx context.Context, cycle *Cycle, diag debugDiagnosis) {
	if cycle == nil {
		return
	}
	online := true
	var summary cycleSummary
	_ = json.Unmarshal([]byte(cycle.Summary), &summary)
	summary.Execution = executionVerified
	summary.AgentOnline = &online
	summary.RecoveredBy = "guest-debugger"
	summary.DebuggerCause = diag.Cause
	summary.GuestActions = diag.GuestActions
	if encoded, err := json.Marshal(summary); err == nil {
		cycle.Summary = string(encoded)
	}
	cycle.Execution = executionVerified
	cycle.AgentOnline = &online
	c.e.lastExecuting = cycle
	c.e.executionBlocked = false
	c.e.actionRequired.Store(false)
	c.e.lastExecution.Store(executionVerified)
	for i := range c.e.cycles {
		if c.e.cycles[i].ID == cycle.ID {
			c.e.cycles[i] = *cycle
		}
	}
	if cycle.ID != 0 {
		if err := c.e.db.UpdateCycleRecovery(ctx, cycle.ID, executionVerified, &online, cycle.Summary); err != nil {
			c.e.logClass(logging.ClassError, "record debugger recovery: %v", err)
		}
	}
	c.e.logClass(logging.ClassCycle, "debugger recovered cycle %d: %s", cycle.Iteration, clip(diag.Cause, 200))
}

// runSession runs one worker with the role's tools, hooks, turn cap, and
// timeouts. Planner and editor sessions are also bounded by the cycle
// deadline, so a stalled worker cannot delay the next detonation forever.
func (c *coordinator) runSession(ctx context.Context, role evolveRole, prompt string, resume func(reason string) string) (string, error) {
	maxTurns := c.turns(role)
	sessionTimeout := c.sessionTimeout(role)
	hardSession := role == rolePlanner
	if hardSession && c.e.cfg.PlannerTimeout > 0 {
		sessionTimeout = c.e.cfg.PlannerTimeout
	}
	idleTimeout := c.idleTimeout(role)
	sessionStart := time.Now()
	cycleTimeout := c.e.cfg.CycleTimeout
	if cycleTimeout <= 0 {
		cycleTimeout = defaultCycleTimeout
	}
	enforceCycle := role != roleDebugger
	for attempt := 0; ; attempt++ {
		c.e.sessions.Add(1)
		sessionCtx, sessionCancel := context.WithCancel(ctx)
		var sessionExpired, idleExpired, cycleExpired atomic.Bool
		c.e.deadlineHit.Store(false)
		sessionStart = time.Now()
		c.e.lastToolCall.Store(time.Now().UnixNano())
		watchdogDone := make(chan struct{})
		go c.watchdog(sessionCtx, sessionCancel, watchdogDone, enforceCycle, hardSession, role == roleEditor, sessionTimeout, idleTimeout, cycleTimeout, sessionStart, &sessionExpired, &idleExpired, &cycleExpired)
		text, err := agentcore.Run(sessionCtx, agentcore.Options{
			Provider:               c.provider,
			SystemPrompt:           []string{roleSystemPrompt(role)},
			Tools:                  c.e.toolsFor(role),
			PermissionMode:         permission.ModeDontAsk,
			Hooks:                  c.e.hooksFor(role),
			WorkingDir:             c.e.cfg.ModuleDir,
			MaxTurns:               maxTurns,
			MaxTokens:              maxWorkerTokens,
			DisableBackgroundTasks: true,
			Compaction:             &compaction.Config{ContextWindow: 200000, MaxOutputTokens: maxWorkerTokens, KeepRecent: 8},
			OnWarn:                 func(line string) { c.e.logf(logging.ClassWarning, "%s: %s", role.label(), line) },
		}, prompt)
		close(watchdogDone)
		sessionCancel()
		if err == nil {
			return text, nil
		}
		if ctx.Err() != nil {
			return text, ctx.Err()
		}
		if role == roleDebugger && attempt >= 2 {
			return text, fmt.Errorf("debugger session failed: %w", err)
		}
		if enforceCycle && cycleExpired.Load() {
			c.e.actionRequired.Store(role == roleEditor)
			c.e.logClass(logging.ClassWarning,
				"%s: no cycle completed within %s; stopping the session and requiring a retry", role.label(), cycleTimeout)
			c.e.lastCycleAt.Store(time.Now().UnixNano())
			prompt = resume("cycle")
			continue
		}
		if sessionExpired.Load() {
			switch role {
			case rolePlanner:
				c.e.logClass(logging.ClassWarning,
					"planner decision window expired after %s; forcing a plan", sessionTimeout)
			case roleEditor:
				c.e.logClass(logging.ClassWarning,
					"editor decision window expired after %s; forcing an edit and cycle", sessionTimeout)
			default:
				c.e.logClass(logging.ClassError,
					"%s: session exceeded the %s wall-clock limit; restarting", role.label(), sessionTimeout)
			}
			prompt = resume("session")
			continue
		}
		if idleExpired.Load() {
			c.e.logClass(logging.ClassWarning, "%s: session made no tool call for %s", role.label(), idleTimeout)
			prompt = resume("idle")
			continue
		}
		if c.e.executionBlocked && role == roleEditor {
			return text, fmt.Errorf("execution is blocked: no dynamic payload checked in and no executing baseline exists")
		}
		if !c.e.recover(ctx, attempt, role.label()+" session", err) {
			return text, ctx.Err()
		}
		prompt = resume("provider")
	}
}

func (c *coordinator) watchdog(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}, enforceCycle, hardSession, resetOnCycle bool, sessionTimeout, idleTimeout, cycleTimeout time.Duration, started time.Time, sessionExpired, idleExpired, cycleExpired *atomic.Bool) {
	sessionWindowStart := func() time.Time {
		start := started
		if resetOnCycle {
			if last := time.Unix(0, c.e.lastCycleAt.Load()); last.After(start) {
				start = last
			}
		}
		return start
	}
	tick := idleTimeout / 4
	if tick > time.Minute {
		tick = time.Minute
	}
	if tick < time.Second {
		tick = time.Second
	}
	next := func() time.Duration {
		wait := tick
		if enforceCycle && c.e.activeCycles.Load() == 0 && c.e.activeTools.Load() == 0 {
			wait = min(wait, cycleTimeout-time.Since(time.Unix(0, c.e.lastCycleAt.Load())))
		}
		if c.e.activeTools.Load() == 0 {
			wait = min(wait, idleTimeout-time.Since(time.Unix(0, c.e.lastToolCall.Load())))
			wait = min(wait, sessionTimeout-time.Since(sessionWindowStart()))
		}
		if wait < 10*time.Millisecond {
			wait = 10 * time.Millisecond
		}
		return wait
	}
	timer := time.NewTimer(next())
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c.e.toolGate.Lock()
		tools := c.e.activeTools.Load()
		cycles := c.e.activeCycles.Load()
		idleFor := time.Since(time.Unix(0, c.e.lastToolCall.Load()))
		cycleFor := time.Since(time.Unix(0, c.e.lastCycleAt.Load()))
		if hardSession && time.Since(started) >= sessionTimeout {
			c.e.deadlineHit.Store(true)
			sessionExpired.Store(true)
			cancel()
			c.e.toolGate.Unlock()
			return
		}
		if enforceCycle && cycles == 0 && tools == 0 && cycleFor >= cycleTimeout {
			c.e.deadlineHit.Store(true)
			cycleExpired.Store(true)
			cancel()
			c.e.toolGate.Unlock()
			return
		}
		if tools == 0 && idleFor >= idleTimeout {
			c.e.deadlineHit.Store(true)
			idleExpired.Store(true)
			cancel()
			c.e.toolGate.Unlock()
			return
		}
		if tools == 0 && time.Since(sessionWindowStart()) >= sessionTimeout {
			c.e.deadlineHit.Store(true)
			sessionExpired.Store(true)
			cancel()
			c.e.toolGate.Unlock()
			return
		}
		c.e.toolGate.Unlock()
		timer.Reset(next())
	}
}

func (c *coordinator) turns(role evolveRole) int {
	switch role {
	case rolePlanner:
		if c.e.cfg.PlannerTurns > 0 {
			return c.e.cfg.PlannerTurns
		}
	case roleEditor:
		if c.e.cfg.EditorTurns > 0 {
			return c.e.cfg.EditorTurns
		}
	case roleDebugger:
		if c.e.cfg.DebuggerTurns > 0 {
			return c.e.cfg.DebuggerTurns
		}
	}
	return c.e.cfg.Turns
}

func (c *coordinator) sessionTimeout(role evolveRole) time.Duration {
	switch role {
	case roleDebugger:
		if c.e.cfg.DebuggerTimeout > 0 {
			return c.e.cfg.DebuggerTimeout
		}
		if c.e.cfg.CycleTimeout > 0 {
			return c.e.cfg.CycleTimeout
		}
		return defaultCycleTimeout
	case roleEditor:
		if c.e.cfg.EditorTimeout > 0 {
			return c.e.cfg.EditorTimeout
		}
		return defaultEditorTimeout
	}
	if c.e.cfg.SessionTimeout > 0 {
		return c.e.cfg.SessionTimeout
	}
	return defaultSessionTimeout
}

func (c *coordinator) idleTimeout(role evolveRole) time.Duration {
	if role == roleDebugger {
		return c.sessionTimeout(role)
	}
	if c.e.cfg.ToolIdleTimeout > 0 {
		return c.e.cfg.ToolIdleTimeout
	}
	return defaultToolIdleTimeout
}

func (c *coordinator) modelFor(role evolveRole) string {
	if model := strings.TrimSpace(c.e.cfg.WorkerModels[string(role)]); model != "" {
		return model
	}
	return c.model
}

func (c *coordinator) recordWorker(ctx context.Context, role evolveRole, prompt, output string, err error) {
	if c.e.db == nil {
		return
	}
	status := "ok"
	detail := ""
	if err != nil {
		status = "error"
		detail = err.Error()
	}
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if saveErr := c.e.db.SaveWorker(saveCtx, WorkerRun{
		LoopID: c.e.cfg.LoopID, Iteration: c.e.iter, Role: string(role),
		Model: c.modelFor(role), Prompt: prompt, Output: output, Status: status, Error: detail,
	}); saveErr != nil {
		c.e.logClass(logging.ClassWarning, "record %s worker: %v", role.label(), saveErr)
	}
}

func (c *coordinator) plannerResume(reason string) string {
	switch reason {
	case "cycle":
		return c.plannerBrief() + "\n\nNo cycle completed within the cycle deadline and the cycle was stopped. Return exactly one JSON plan now; the editor will apply edits and call DetectionCycle."
	case "session":
		return c.plannerBrief() + "\n\nThe planner decision window expired. Return exactly one JSON plan now; the editor will inspect and edit source."
	case "idle":
		return c.plannerBrief() + "\n\nThe previous planner session made no tool call. Return one plan or action=stop now."
	default:
		return c.plannerBrief() + "\n\nThe previous planner session failed. Return exactly one JSON plan now."
	}
}

func (c *coordinator) editorResume(reason string) string {
	switch reason {
	case "cycle":
		return c.editorBrief(c.currentPlan) + "\n\nNo cycle completed within the cycle deadline and the session was stopped. Apply the remaining edits with EditSource now, then retry with DetectionCycle. Do not keep reading."
	case "session":
		if c.e.sessionCycles.Load() >= 1 {
			return c.editorBrief(c.currentPlan) + "\n\nThe editor decision window expired after a completed cycle. Return the result JSON now; the planner will choose the next hypothesis."
		}
		return c.editorBrief(c.currentPlan) + "\n\nThe editor decision window expired. Apply the edit now with EditSource and call DetectionCycle. Do not keep reading."
	case "idle":
		return c.editorBrief(c.currentPlan) + "\n\nThe previous editor session made no tool call. Apply the edit or call DetectionCycle now."
	default:
		return c.editorBrief(c.currentPlan) + "\n\nThe previous editor session failed. Continue from the source state and run the cycle."
	}
}

func (c *coordinator) debuggerResume(reason string) string {
	return c.debuggerBrief(context.Background(), "retry after "+reason, c.e.last) +
		"\n\nThe previous debugger session failed or stalled. Report the cause you have and return the JSON object."
}

func (c *coordinator) plannerBrief() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Loop ID: %s\nBase loop ID: %s\nAttempt: %d (%s)\n", c.e.cfg.LoopID, c.e.baseLoopID, c.e.attempt, attemptLabel(c.e.attempt))
	fmt.Fprintf(&b, "Module: %s\nModule source: %s\nGoal: %s\n", c.e.cfg.Module, c.e.cfg.ModuleDir, headerOrNone(c.e.cfg.Goal))
	fmt.Fprintf(&b, "Agent C2: %s\nExpected agent UUID: %s\nAgent type: %s\n", headerOrNone(c.e.cfg.AgentCC), headerOrNone(c.e.expectedAgentUUID), headerOrNone(c.e.cfg.AgentType))
	fmt.Fprintf(&b, "Active shellcode: %s\nActive producer: %s\nSource roots: %s\n", c.e.shellcode, headerOrNone(c.e.activeProducer), c.e.roots.describe())
	fmt.Fprintf(&b, "Cycle budget: %d total; %d used; %d remain\nStages: %s\n",
		c.e.cfg.Iterations, c.e.usedCycles(), max(0, c.e.cfg.Iterations-c.e.usedCycles()), strings.Join(stageNames(c.e.cfg.Stages), ", "))
	fmt.Fprintf(&b, "Baseline: %s\nBaseline failure: %s\n", string(c.baselineJSON), headerOrNone(c.e.baselineFailure))
	fmt.Fprintf(&b, "Execution gate: %s\nKnowledge cache: %s\n", c.executionState, c.knowledgeState)
	if c.e.guest == nil {
		b.WriteString("Guest debugger: disabled (no --guest-ssh); execution=offline cannot be diagnosed inside the VM.\n")
	} else {
		b.WriteString("Guest debugger: available over GuestSSH.\n")
	}
	if c.e.cfg.Verify == nil {
		b.WriteString("C2 verification: disabled; execution is unverified.\n")
	}
	b.WriteString("\nDossier:\n")
	b.WriteString(c.e.dossier())
	if c.lastEditorError != "" {
		fmt.Fprintf(&b, "\nLast editor error: %s\n", clip(c.lastEditorError, 1200))
	}
	if c.lastDiagnosis != nil {
		fmt.Fprintf(&b, "\nLast debugger diagnosis: cause=%s source_fix=%v online_after=%v\n",
			clip(c.lastDiagnosis.Cause, 600), c.lastDiagnosis.SourceFixRequired, c.lastDiagnosis.AgentOnlineAfter)
		for i, item := range c.lastDiagnosis.Evidence {
			if i >= 6 {
				break
			}
			fmt.Fprintf(&b, "  evidence: %s\n", clip(sanitizeLine(item), 300))
		}
		if c.lastDiagnosis.EditorBrief != "" {
			fmt.Fprintf(&b, "  editor brief: %s\n", clip(c.lastDiagnosis.EditorBrief, 800))
		}
		if len(c.lastDiagnosis.GuestActions) > 0 {
			fmt.Fprintf(&b, "  guest actions: %s\n", clip(strings.Join(limitStrings(c.lastDiagnosis.GuestActions, 8), "; "), 800))
			b.WriteString("The debugger changed the guest; the last cycle is debug-assisted, not a clean detection baseline. Plan a fresh cycle.\n")
		}
	}
	if c.plannerNote != "" {
		fmt.Fprintf(&b, "\nCoordinator note: %s\n", c.plannerNote)
		c.plannerNote = ""
	}
	prompts := c.e.takeOperatorPrompts()
	if len(prompts) > 0 {
		b.WriteString("\n")
		b.WriteString(FormatOperatorPrompts(prompts))
	}
	b.WriteString("\nReturn one planner JSON object now.")
	return b.String()
}

func (c *coordinator) editorBrief(plan plannerPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Execute this plan as the editor worker.\nLoop ID: %s (attempt %d)\n", c.e.cfg.LoopID, c.e.attempt)
	if plan.Action != "" {
		fmt.Fprintf(&b, "Plan: action=%s mechanism=%s\nPrediction: %s\nReason: %s\n",
			plan.Action, headerOrNone(plan.Mechanism), headerOrNone(plan.Prediction), headerOrNone(plan.Reason))
		if plan.EditorBrief != "" {
			fmt.Fprintf(&b, "Editor brief: %s\n", plan.EditorBrief)
		}
	} else {
		b.WriteString("Plan: continue the current hypothesis from the dossier.\n")
	}
	fmt.Fprintf(&b, "Cycle budget: %d total; %d used; %d remain\n", c.e.cfg.Iterations, c.e.usedCycles(), max(0, c.e.cfg.Iterations-c.e.usedCycles()))
	fmt.Fprintf(&b, "Execution gate: %s\n", c.e.executionHint())
	if c.e.baselineFailure != "" {
		fmt.Fprintf(&b, "Baseline failure: %s\n", c.e.baselineFailure)
	}
	if c.lastDiagnosis != nil {
		fmt.Fprintf(&b, "Debugger diagnosis: cause=%s source_fix=%v\n", clip(c.lastDiagnosis.Cause, 600), c.lastDiagnosis.SourceFixRequired)
		if c.lastDiagnosis.EditorBrief != "" {
			fmt.Fprintf(&b, "Debugger editor brief: %s\n", clip(c.lastDiagnosis.EditorBrief, 1000))
		}
	}
	fmt.Fprintf(&b, "\nDossier:\n%s\n", c.e.dossier())
	if direction := c.e.directionHint(); direction != "" {
		fmt.Fprintf(&b, "\n%s\n", direction)
	}
	if c.e.cfg.BuildAgent == nil {
		b.WriteString("\nGenerateAgent is disabled for this run; reuse the supplied shellcode or edit and rebuild an existing producer.\n")
	}
	if !c.e.verifyEnabled() {
		b.WriteString("\nC2 verification is disabled; execution is unverified.\n")
	}
	b.WriteString("\nApply every edit the change needs, then call DetectionCycle exactly once. End with the required JSON object.")
	return b.String()
}

func (c *coordinator) debuggerBrief(ctx context.Context, trigger string, cycle *Cycle) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trigger: %s\nLoop ID: %s (attempt %d)\n", trigger, c.e.cfg.LoopID, c.e.attempt)
	fmt.Fprintf(&b, "Expected agent UUID: %s\nAgent C2: %s\n", headerOrNone(c.e.expectedAgentUUID), headerOrNone(c.e.cfg.AgentCC))
	fmt.Fprintf(&b, "Module: %s\nActive shellcode: %s\nProducer: %s\n", c.e.cfg.Module, c.e.shellcode, headerOrNone(c.e.activeProducer))
	if c.e.cfg.Guest != nil {
		fmt.Fprintf(&b, "Guest: %s port %d user %s; staging/exclusion: %s\n",
			c.e.cfg.Guest.Host, c.e.cfg.Guest.Port, c.e.cfg.Guest.User, c.e.cfg.Guest.ExcludePath)
	}
	if cycle != nil {
		fmt.Fprintf(&b, "Cycle %d: execution=%s payload=%s run=%s trace=%d network=%d\n",
			cycle.Iteration, headerOrNone(cycle.Execution), headerOrNone(cycle.PayloadKey),
			headerOrNone(cycle.RunID), cycle.TraceID, cycle.NetworkEvents)
		fmt.Fprintf(&b, "Cycle summary: %s\n", clip(cycle.Summary, 6000))
		if payload, err := c.e.db.PayloadByKey(ctx, cycle.PayloadKey); err == nil {
			fmt.Fprintf(&b, "Artifact: %s\n", headerOrNone(payload.ArtifactPath))
		}
		if build, ok, err := c.e.db.BuildForIteration(ctx, c.e.cfg.LoopID, cycle.Iteration); err == nil && ok {
			fmt.Fprintf(&b, "Build log tail: %s\n", strings.Join(lastLines(build.Log, 20), "\n"))
		}
	}
	if c.e.baselineFailure != "" {
		fmt.Fprintf(&b, "Baseline failure: %s\n", c.e.baselineFailure)
	}
	fmt.Fprintf(&b, "\nDossier:\n%s\n", c.e.dossier())
	b.WriteString("\nStart with GuestSSH action=ensure_exclusion, then inspect the guest. Return the debugger JSON object.")
	return b.String()
}
