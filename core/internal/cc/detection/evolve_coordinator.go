package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	maxEditorFailures = 3
	// maxBuildRetries bounds editor retries after a broken build. The host
	// restores the last executing source before each retry, so it must not
	// spend the editor's hypothesis budget on a source tree it can repair.
	maxBuildRetries = 2
	// maxInfraFailures bounds consecutive empty/provider failures. They are
	// not hypothesis failures, so they do not end the loop on the first one.
	maxInfraFailures = 3
	// maxPlanRetries bounds parse repair inside one planner session.
	maxPlanRetries = 2
	// maxForcedResumes bounds how many times a stopping planner is sent back
	// because actionable findings remain.
	maxForcedResumes = 2
	// maxRejectedPlans bounds consecutive plans that ask for an action the
	// host cannot run (for example a debugger with no sessions left).
	maxRejectedPlans = 2
)

// coordinator owns the role sequencing and the structural decisions. The
// workers only reason over their own tool sets.
type coordinator struct {
	e        *evolver
	provider llm.Provider
	model    string

	baselineJSON   json.RawMessage
	knowledgeState string

	plannerNote      string
	knowledgeBrief   string
	lastEditorError  string
	lastDiagnosis    *debugDiagnosis
	debugged         sync.Map
	editorFailures   int
	buildRetries     int
	editorNote       string
	infraFailures    int
	rejectedPlans    int
	stopResumes      int
	debuggerSessions int
	plans            int
	currentPlan      plannerPlan
	pendingPlan      *plannerPlan
	forcedFixes      int
	finalDebugDone   bool
}

func newCoordinator(e *evolver, provider llm.Provider, model string, baselineJSON json.RawMessage, knowledgeState string) *coordinator {
	return &coordinator{
		e: e, provider: provider, model: model,
		baselineJSON:   baselineJSON,
		knowledgeState: knowledgeState,
	}
}

// refreshKnowledge retrieves a bounded set of reference documents for the
// current finding and mechanism. The host does the search so a model with a
// small read budget still starts from relevant techniques instead of guessing.
func (c *coordinator) refreshKnowledge(ctx context.Context, mechanism string) {
	c.knowledgeBrief = ""
	query := c.e.knowledgeQuery(mechanism)
	if query == "" {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	hits := c.e.searchKnowledge(qctx, query, "", 3)
	if len(hits) == 0 {
		return
	}
	var b strings.Builder
	for _, hit := range hits {
		fmt.Fprintf(&b, "- %s [%s]: %s\n",
			sanitizeLine(hit.Title), sanitizeLine(hit.DocRef), clip(sanitizeLine(hit.Snippet), 300))
	}
	c.knowledgeBrief = b.String()
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
			final := c.failureFinal("the coordinator exceeded its planning budget", fmt.Errorf("the planner repeated or produced plans without completing a cycle"))
			if c.lastEditorError != "" {
				appendFinalResidual(final, "last editor error: "+clip(c.lastEditorError, 600))
			}
			c.finalDiagnosis(ctx, final)
			return final, nil
		}
		var (
			plan plannerPlan
			err  error
		)
		if c.pendingPlan != nil {
			plan = *c.pendingPlan
			c.pendingPlan = nil
		} else {
			plan, err = c.plan(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if !isInfrastructureFailure(err) {
					return nil, err
				}
				c.infraFailures++
				c.e.logClass(logging.ClassWarning, "planner infrastructure failure: %v", err)
				if c.infraFailures >= maxInfraFailures {
					return c.failureFinal("the planner worker could not produce a plan", err), nil
				}
				c.plannerNote = "The previous planner session ended without a plan: " + clip(err.Error(), 400)
				if !c.e.backoff(ctx, c.infraFailures, "planner infrastructure failure") {
					return nil, ctx.Err()
				}
				continue
			}
			c.infraFailures = 0
			c.buildRetries = 0
			c.editorNote = ""
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
			if c.debuggerPolicy() != debuggerPolicyFinal {
				if forced, ok := c.forceExecutionFix(); ok {
					c.e.logClass(logging.ClassWarning, "planner stopped with an unresolved source-level execution fault; forcing the debugger's fix cycle")
					c.pendingPlan = &forced
					c.stopResumes = 0
					continue
				}
			}
			if c.e.usedCycles() < c.e.cfg.Iterations && c.e.needsMoreWork(ctx) {
				if c.stopResumes >= maxForcedResumes {
					c.e.logClass(logging.ClassWarning, "planner stopped again with work remaining; accepting the stop")
					c.finalDiagnosis(ctx, final)
					return final, nil
				}
				c.stopResumes++
				c.e.logClass(logging.ClassWarning, "planner stopped with work remaining; resuming")
				c.plannerNote = "real verdicts or actionable high/medium findings remain; continue the loop"
				c.editorFailures = 0
				if !c.e.backoff(ctx, c.editorFailures, "the plan stopped while work remains") {
					return nil, ctx.Err()
				}
				continue
			}
			c.finalDiagnosis(ctx, final)
			return final, nil
		case "test":
			if c.e.usedCycles() >= c.e.cfg.Iterations {
				c.plannerNote = "the cycle budget is exhausted; return action=stop with the final JSON"
				continue
			}
			if c.producerSwapUnavailable(plan.Mechanism) {
				c.rejectedPlans++
				c.plannerNote = fmt.Sprintf("mechanism=producer-swap is unavailable: configured producers are %s and no producer other than the active %s is configured. Choose mechanism=producer to edit the active producer, or another available mechanism; do not ask the editor to swap in a producer the loop does not have.",
					strings.Join(c.e.producerNames(), ", "), headerOrNone(c.e.activeProducer))
				c.e.logClass(logging.ClassWarning, "planner chose producer-swap without a configured alternative")
				if c.rejectedPlans >= maxRejectedPlans {
					final := c.coordinatorStopFinal("the planner chose producer-swap with no configured alternative producer")
					c.finalDiagnosis(ctx, final)
					return final, nil
				}
				continue
			}
			if c.repeatedNonImprovingMechanism(plan.Mechanism) {
				c.rejectedPlans++
				c.plannerNote = fmt.Sprintf("The last two cycles used mechanism %q without a high-finding, static-signature, or verdict improvement. Choose a different mechanism or producer-swap, or action=stop.", plan.Mechanism)
				c.e.logClass(logging.ClassWarning, "planner repeated mechanism %q without progress", plan.Mechanism)
				if c.rejectedPlans >= maxRejectedPlans {
					final := c.coordinatorStopFinal("the planner repeated a non-improving mechanism twice: " + plan.Mechanism)
					c.finalDiagnosis(ctx, final)
					return final, nil
				}
				continue
			}
			before := c.e.iter
			if err := c.edit(ctx, plan); err != nil {
				c.lastEditorError = err.Error()
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if errors.Is(err, errBuildFailed) && c.buildRetries < maxBuildRetries {
					c.buildRetries++
					c.editorFailures = 0
					c.editorNote = "The previous edit failed to build. The host restored the last executing source. Reapply a change that compiles, or choose a different fix; never resubmit DetectionCycle against a broken tree."
					c.e.logClass(logging.ClassWarning,
						"editor build failed (%d/%d); restored source, retrying the same plan",
						c.buildRetries, maxBuildRetries)
					c.pendingPlan = &plan
					continue
				}
				if isInfrastructureFailure(err) {
					c.infraFailures++
					c.e.logClass(logging.ClassWarning, "editor infrastructure failure: %v", err)
					if c.infraFailures >= maxInfraFailures {
						return c.editorFailureFinal(err), nil
					}
					if !c.e.backoff(ctx, c.infraFailures, "editor infrastructure failure") {
						return nil, ctx.Err()
					}
					// The hypothesis is still valid; retry the same plan after
					// the host recovers instead of spending a planner session.
					c.pendingPlan = &plan
					continue
				}
				c.editorFailures++
				c.e.logClass(logging.ClassWarning, "editor worker: %v", err)
				if c.editorFailures >= maxEditorFailures {
					return c.editorFailureFinal(err), nil
				}
				continue
			}
			if c.e.iter == before {
				c.lastEditorError = "the editor returned without a completed DetectionCycle"
				c.editorFailures++
				c.e.logClass(logging.ClassWarning, "editor worker: %s", c.lastEditorError)
				if c.editorFailures >= maxEditorFailures {
					return c.editorFailureFinal(fmt.Errorf("%s", c.lastEditorError)), nil
				}
				continue
			}
			c.lastEditorError = ""
			c.editorFailures = 0
			c.buildRetries = 0
			c.editorNote = ""
			c.infraFailures = 0
			c.rejectedPlans = 0
			if err := c.afterCycle(ctx, c.e.last); err != nil {
				return nil, err
			}
		case "debug":
			if !c.debuggerAvailable() {
				reason := c.debuggerUnavailableReason()
				c.plannerNote = "The debugger is unavailable: " + reason + ". Do not choose action=debug; choose action=test with a concrete fix, or action=stop."
				c.e.logClass(logging.ClassWarning, "planner requested an unavailable debugger: %s", reason)
				c.rejectedPlans++
				if c.rejectedPlans >= maxRejectedPlans {
					final := c.coordinatorStopFinal("the planner requested an unavailable debugger twice: " + reason)
					c.finalDiagnosis(ctx, final)
					return final, nil
				}
				continue
			}
			if _, err := c.debug(ctx, debugRequest{Trigger: "planner request: " + clip(plan.DebugFocus, 300), Cycle: c.e.last}); err != nil {
				c.e.logClass(logging.ClassWarning, "debugger worker: %v", err)
				c.plannerNote = "The debugger could not complete: " + clip(err.Error(), 300) + ". Choose action=test with a concrete fix, or action=stop."
				c.rejectedPlans++
				if c.rejectedPlans >= maxRejectedPlans {
					return c.coordinatorStopFinal("the debugger could not complete: " + clip(err.Error(), 400)), nil
				}
				continue
			}
			c.rejectedPlans = 0
		}
	}
}

func (c *coordinator) editorFailureFinal(err error) map[string]any {
	return c.failureFinal("the editor worker could not complete a cycle", err)
}

// failureFinal reports the worker that actually stopped the loop. The final
// answer must name the coordinator, planner, or editor failure instead of
// blaming the editor for every path.
func (c *coordinator) failureFinal(summary string, err error) map[string]any {
	detail := "the loop stopped before a completed cycle"
	if err != nil {
		detail = err.Error()
	}
	final := map[string]any{
		"summary": summary, "edits": []any{},
		"residual":    []string{summary + ": " + clip(detail, 1000)},
		"parse_error": summary,
	}
	c.e.lastAnswer = final
	c.e.logClass(logging.ClassError, "%s: %s", summary, clip(detail, 400))
	return final
}

// forceExecutionFix turns a debugger-identified source-level execution fault
// into one editor cycle. A planner stop must not leave the payload unable to
// check in; the fix is bounded so a broken diagnosis cannot loop forever.
func (c *coordinator) forceExecutionFix() (plannerPlan, bool) {
	if c.forcedFixes >= 2 || c.e.usedCycles() >= c.e.cfg.Iterations {
		return plannerPlan{}, false
	}
	if c.e.last == nil || c.e.last.Execution != executionOffline {
		return plannerPlan{}, false
	}
	diag := c.lastDiagnosis
	if diag == nil || !diag.SourceFixRequired {
		return plannerPlan{}, false
	}
	brief := strings.TrimSpace(diag.EditorBrief)
	if brief == "" {
		brief = strings.TrimSpace(diag.Cause)
	}
	if brief == "" {
		return plannerPlan{}, false
	}
	c.forcedFixes++
	return plannerPlan{
		Action:      "test",
		Mechanism:   c.lastMechanism(),
		Prediction:  "the generated agent checks in after the debugger's execution fix",
		EditorBrief: brief,
		Reason:      "the guest debugger found a source-level execution fault; the host is forcing the fix before another stop",
	}, true
}

// lastMechanism keeps a forced fix on the loading path under test instead of
// inventing a new one.
func (c *coordinator) lastMechanism() string {
	cycles := c.e.recentCycles(1)
	if len(cycles) == 0 {
		return "other"
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycles[0].Summary), &summary) != nil || strings.TrimSpace(summary.Mechanism) == "" {
		return "other"
	}
	return summary.Mechanism
}

func (c *coordinator) coordinatorStopFinal(reason string) map[string]any {
	final := map[string]any{
		"summary":     "the coordinator stopped the loop: " + reason,
		"edits":       []any{},
		"residual":    []string{reason},
		"parse_error": "coordinator stopped the loop",
	}
	c.e.lastAnswer = final
	c.e.logClass(logging.ClassError, "%s", final["summary"])
	return final
}

// debuggerPolicy returns the normalized scheduling policy. An unset policy
// behaves like final so a caller that bypasses normalization cannot fall back
// to a guest pass after every cycle.
func (c *coordinator) debuggerPolicy() string {
	switch policy := strings.ToLower(strings.TrimSpace(c.e.cfg.DebuggerPolicy)); policy {
	case debuggerPolicyCycle, debuggerPolicyOff:
		return policy
	default:
		return debuggerPolicyFinal
	}
}

// producerSwapTarget names a configured producer the loop has not used. A
// swap needs a fresh agent artifact in the producer's expected format.
func (c *coordinator) producerSwapTarget() string {
	if c.e.cfg.BuildAgent == nil {
		return ""
	}
	for _, name := range []string{"crystal_pack", "donut"} {
		if _, ok := c.e.cfg.ProducerDirs[name]; ok && !strings.EqualFold(strings.TrimSpace(c.e.activeProducer), name) {
			return name
		}
	}
	return ""
}

// producerSwapUnavailable reports a plan that asks for a producer swap with no
// configured producer other than the active one. Reject it before the editor
// starts; the editor cannot install a producer the loop does not have.
func (c *coordinator) producerSwapUnavailable(mechanism string) bool {
	return strings.EqualFold(strings.TrimSpace(mechanism), "producer-swap") && c.producerSwapTarget() == ""
}

// repeatedNonImprovingMechanism enforces the planner rule that two cycles of
// the same mechanism without a finding or verdict improvement must be followed
// by a different mechanism. A non-executing cycle has no comparable result, so
// it also counts as no improvement.
func (c *coordinator) repeatedNonImprovingMechanism(candidate string) bool {
	cycles := c.e.recentCycles(2)
	if len(cycles) < 2 || strings.TrimSpace(candidate) == "" {
		return false
	}
	previous, last := cycles[0], cycles[1]
	var previousSummary, lastSummary cycleSummary
	if json.Unmarshal([]byte(previous.Summary), &previousSummary) != nil ||
		json.Unmarshal([]byte(last.Summary), &lastSummary) != nil {
		return false
	}
	if previousSummary.Mechanism == "" ||
		previousSummary.Mechanism != lastSummary.Mechanism ||
		lastSummary.Mechanism != candidate {
		return false
	}
	// A cycle with a coverage gap cannot demonstrate progress. Do not let it
	// reset the mechanism-repetition guard.
	if !coverageComplete(previousSummary) || !coverageComplete(lastSummary) {
		return true
	}
	if last.Verdicts < previous.Verdicts {
		return false
	}
	if previous.Execution == executionVerified && last.Execution == executionVerified &&
		findingsImproved(cycleFindingCounts(&previous), cycleFindingCounts(&last)) {
		return false
	}
	return true
}

// finalDiagnosis spends the deferred debugger pass on the last cycle when the
// loop stops without a verified execution. The diagnosis belongs to the final
// answer; it does not schedule another cycle.
func (c *coordinator) finalDiagnosis(ctx context.Context, final map[string]any) {
	if c.debuggerPolicy() != debuggerPolicyFinal || c.finalDebugDone {
		return
	}
	if c.e.guest == nil || c.debuggerRemaining() <= 0 {
		return
	}
	if c.e.last == nil || c.e.last.Execution == executionVerified || c.e.last.Execution == executionStatic {
		return
	}
	c.finalDebugDone = true
	diag, err := c.debug(ctx, debugRequest{
		Trigger: fmt.Sprintf("final stop: cycle %d did not execute in the monitored run", c.e.last.Iteration),
		Cycle:   c.e.last,
		Repeat:  true,
	})
	if err != nil {
		c.e.logClass(logging.ClassWarning, "final debugger pass: %v", err)
		appendFinalResidual(final, "final debugger failed: "+clip(err.Error(), 400))
		return
	}
	if diag == nil {
		return
	}
	final["debugger_diagnosis"] = diag
	appendFinalResidual(final, fmt.Sprintf("final debugger: %s (source_fix=%v, online_after=%v)",
		clip(diag.Cause, 500), diag.SourceFixRequired, diag.AgentOnlineAfter))
}

// appendFinalResidual adds one line to the planner's final answer without
// assuming the JSON array arrived as []any or []string.
func appendFinalResidual(final map[string]any, item string) {
	switch existing := final["residual"].(type) {
	case []any:
		final["residual"] = append(existing, item)
	case []string:
		values := make([]any, 0, len(existing)+1)
		for _, value := range existing {
			values = append(values, value)
		}
		final["residual"] = append(values, item)
	case nil:
		final["residual"] = []any{item}
	default:
		final["residual"] = []any{fmt.Sprintf("%v", existing), item}
	}
}

// debuggerBudget is the total debugger sessions available to this loop. One
// pass is allowed per cycle; the total follows the cycle budget.
func (c *coordinator) debuggerBudget() int {
	return max(4, c.e.cfg.Iterations)
}

func (c *coordinator) debuggerRemaining() int {
	return max(0, c.debuggerBudget()-c.debuggerSessions)
}

// debuggerAvailable reports whether a debug pass can run for the last cycle.
func (c *coordinator) debuggerAvailable() bool {
	return c.debuggerAvailableFor(c.e.last)
}

func (c *coordinator) debuggerAvailableFor(cycle *Cycle) bool {
	if c.e.guest == nil || c.debuggerRemaining() <= 0 {
		return false
	}
	if c.debuggerPolicy() != debuggerPolicyCycle {
		return false
	}
	if cycle != nil && cycle.ID != 0 {
		if _, seen := c.debugged.Load(cycle.ID); seen {
			return false
		}
	}
	return true
}

// debuggerUnavailableReason explains a refused debug plan so the planner can
// choose action=test or action=stop without guessing.
func (c *coordinator) debuggerUnavailableReason() string {
	return c.debuggerUnavailableFor(c.e.last)
}

func (c *coordinator) debuggerUnavailableFor(cycle *Cycle) string {
	if c.e.guest == nil {
		return "guest SSH is not configured"
	}
	if c.debuggerRemaining() <= 0 {
		return fmt.Sprintf("no sessions remain (%d/%d used)", c.debuggerSessions, c.debuggerBudget())
	}
	switch c.debuggerPolicy() {
	case debuggerPolicyOff:
		return "the debugger is disabled by --debugger-policy off"
	case debuggerPolicyFinal:
		return "the debugger runs once at the final stop (--debugger-policy final)"
	}
	if cycle != nil && cycle.ID != 0 {
		if _, seen := c.debugged.Load(cycle.ID); seen {
			return fmt.Sprintf("cycle %d was already debugged; use its diagnosis", cycle.Iteration)
		}
	}
	return "debugger is not available for the last cycle"
}

func (c *coordinator) afterBaseline(ctx context.Context) error {
	last := c.e.last
	if last == nil || last.LoopID != c.e.cfg.LoopID {
		return nil
	}
	return c.afterCycle(ctx, last)
}

func (c *coordinator) afterCycle(ctx context.Context, cycle *Cycle) error {
	if cycle == nil {
		return nil
	}
	var summary cycleSummary
	if err := json.Unmarshal([]byte(cycle.Summary), &summary); err != nil {
		c.e.logClass(logging.ClassWarning, "decode cycle %d summary: %v", cycle.Iteration, err)
		summary.Execution = cycle.Execution
	}
	gate := c.e.recordExecution(cycle, summary)
	c.e.recordTechniqueMemory(ctx, *cycle, summary, gate)
	if gate == gateExecuting {
		c.lastDiagnosis = nil
		c.forcedFixes = 0
	}
	if gate == gateBlocked {
		c.plannerNote = "Execution is blocked: the host could not establish a usable execution path. Return action=stop with the final JSON."
		return nil
	}
	if summary.Execution == executionVerified && !coverageComplete(summary) && gate != gateRegressed {
		c.plannerNote = fmt.Sprintf("Cycle %d executed but coverage is incomplete: %s. Its finding counts are not comparable and did not replace the finding baseline; fix the analyzer coverage or treat the residuals as unresolved.",
			cycle.Iteration, clip(strings.Join(summary.CoverageMissing, "; "), 600))
	}
	if gate == gateRegressed {
		baseline := c.e.regressionBaseline
		if baseline == nil {
			baseline = c.e.comparisonBaseline()
		}
		c.lastDiagnosis = nil
		c.e.restoreErr = nil
		retained := "no clean baseline exists"
		previous := findingCounts{}
		current := summaryFindingCounts(summary, cycle.Findings)
		if baseline != nil {
			retained = lastGoodRef(baseline)
			previous = cycleFindingCounts(baseline)
			c.e.logClass(logging.ClassWarning,
				"cycle %d regressed (verdicts %d -> %d, high %d -> %d, medium %d -> %d, static %d -> %d, total %d -> %d); source edits retained; finding baseline remains %s",
				cycle.Iteration, previous.Verdicts, current.Verdicts,
				previous.High, current.High, previous.Medium, current.Medium,
				previous.Static, current.Static, previous.Total, current.Total, retained)
		}
		quotedLoopID := strings.ReplaceAll(sanitizeLine(c.e.cfg.LoopID), "'", "''")
		c.plannerNote = fmt.Sprintf("Cycle %d regressed (verdicts %d -> %d, high findings %d -> %d, medium findings %d -> %d, static findings %d -> %d, total findings %d -> %d); the host kept the cycle's source edits and left the finding baseline at %s. A verdict is the primary objective: do not trade a removed verdict for a higher medium count, and do not accept a new verdict even when the weighted score improves. The edits are recorded in loop_edits, iteration %d, with their old/new text: keep the part that removed a finding and change only the part that raised the regressed count (SELECT file, reason, old, new FROM loop_edits WHERE loop_id = '%s' AND iteration = %d). Do not repeat the exact change.",
			cycle.Iteration, previous.Verdicts, current.Verdicts,
			previous.High, current.High, previous.Medium, current.Medium,
			previous.Static, current.Static, previous.Total, current.Total, retained,
			cycle.Iteration, quotedLoopID, cycle.Iteration)
		return nil
	}
	if gate != gateRestore {
		return nil
	}

	run := fmt.Sprintf("Cycle %d did not execute", cycle.Iteration)
	restore := c.e.lastExecuting != nil
	restored := "no executing baseline exists yet"
	if restore {
		restored = "the host restored " + lastGoodRef(c.e.lastExecuting)
	}
	restoreIfPossible := func() string {
		if !restore {
			return ""
		}
		if err := c.e.restoreExecutingState(ctx); err != nil {
			return " Restore incomplete: " + clip(err.Error(), 300)
		}
		return ""
	}
	if policy := c.debuggerPolicy(); policy != debuggerPolicyCycle {
		reason := "deferred to the final stop"
		if policy == debuggerPolicyOff {
			reason = "disabled"
		}
		c.e.logClass(logging.ClassWarning, "cycle %d did not execute; debugger pass %s", cycle.Iteration, reason)
		c.plannerNote = fmt.Sprintf("%s. The guest debugger is %s. %s. Fix why the generated agent never checked in before changing detection code, or choose action=stop; this cycle's finding counts are not a detection result.", run, reason, restored) + restoreIfPossible()
		return nil
	}
	if !c.debuggerAvailableFor(cycle) {
		unavailable := c.debuggerUnavailableFor(cycle)
		c.e.logClass(logging.ClassWarning, "cycle %d did not execute; no debugger pass: %s", cycle.Iteration, unavailable)
		c.plannerNote = fmt.Sprintf("%s and the debugger is unavailable (%s). %s. Continue with action=test: fix why the generated agent never checked in before changing detection code.", run, unavailable, restored) + restoreIfPossible()
		return nil
	}

	diag, err := c.debug(ctx, debugRequest{
		Trigger: fmt.Sprintf("execution=%s on cycle %d", headerOrNone(summary.Execution), cycle.Iteration),
		Cycle:   cycle,
	})
	if err != nil {
		c.e.logClass(logging.ClassWarning, "debugger worker: %v", err)
		c.plannerNote = fmt.Sprintf("%s and the debugger failed: %s. %s. Continue with action=test using the evidence in the dossier, or action=stop.", run, clip(err.Error(), 300), restored) + restoreIfPossible()
		return nil
	}
	if diag != nil {
		c.lastDiagnosis = diag
		c.plannerNote = fmt.Sprintf("%s. Debugger cause: %s; source_fix=%v; online_after=%v. A manual relaunch is not a detection baseline. Fix the execution cause before changing detection code; this cycle's finding counts are not a detection result.", run, clip(diag.Cause, 400), diag.SourceFixRequired, diag.AgentOnlineAfter)
	} else {
		c.plannerNote = fmt.Sprintf("%s. %s. Continue with action=test or action=stop.", run, restored)
	}
	c.plannerNote += restoreIfPossible()
	return nil
}

// plan asks the coordinator worker for the next move. Parse repair continues
// the same session, so the planner keeps the evidence it already read.
func (c *coordinator) plan(ctx context.Context) (plannerPlan, error) {
	c.refreshKnowledge(ctx, "")
	ws := c.newWorkerSession(rolePlanner)
	defer ws.close()
	prompt := c.plannerBrief()
	for attempt := 0; ; attempt++ {
		result, err := ws.run(ctx, prompt, c.plannerResume)
		c.recordWorkerResult(ctx, rolePlanner, prompt, result, err)
		if err != nil {
			return plannerPlan{}, err
		}
		plan, parseErr := parsePlannerPlan(result.text)
		if parseErr == nil {
			c.e.logClass(logging.ClassCycle, "planner: action=%s mechanism=%s", plan.Action, headerOrNone(plan.Mechanism))
			return plan, nil
		}
		c.e.logClass(logging.ClassWarning, "planner answer was not a valid plan: %v", parseErr)
		if attempt >= maxPlanRetries || c.e.usedCycles() >= c.e.cfg.Iterations {
			return plannerPlan{Action: "stop", Final: c.planFailureFinal(result.text, parseErr)}, nil
		}
		if !c.e.backoff(ctx, attempt, "invalid planner answer") {
			return plannerPlan{}, ctx.Err()
		}
		prompt = "Your previous answer was not the required planner JSON object: " + parseErr.Error() + ". Return exactly one JSON object now; do not call tools."
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
	c.refreshKnowledge(ctx, plan.Mechanism)
	c.e.plannedMechanism = plan.Mechanism
	defer func() { c.e.plannedMechanism = "" }()
	c.e.sessionCycles.Store(0)
	c.e.clearCycleError()
	prompt := c.editorBrief(plan)
	ws := c.newWorkerSession(roleEditor)
	defer ws.close()
	result, err := ws.run(ctx, prompt, c.editorResume)
	c.recordWorkerResult(ctx, roleEditor, prompt, result, err)
	if err != nil {
		return err
	}
	c.e.logClass(logging.ClassAnswer, "%s", clip(result.text, 6000))
	if c.e.sessionCycles.Load() == 0 {
		if cycleErr := c.e.takeCycleError(); cycleErr != nil {
			if errors.Is(cycleErr, ErrSandboxUnreachable) {
				return fmt.Errorf("%w: %v", errCycleInfrastructure, cycleErr)
			}
			return fmt.Errorf("the editor cycle failed: %w", cycleErr)
		}
		return fmt.Errorf("the editor returned without running DetectionCycle")
	}
	return nil
}

// debugRequest describes one debugger pass. Repeat allows the final
// verification pass to inspect the same cycle again after a successful fix.
type debugRequest struct {
	Trigger string
	Cycle   *Cycle
	Repeat  bool
}

func (c *coordinator) debug(ctx context.Context, req debugRequest) (*debugDiagnosis, error) {
	if c.e.guest == nil {
		return nil, fmt.Errorf("guest SSH is not configured")
	}
	if c.debuggerRemaining() <= 0 {
		return nil, fmt.Errorf("debugger session limit reached (%d/%d)", c.debuggerSessions, c.debuggerBudget())
	}
	if !req.Repeat && req.Cycle != nil && req.Cycle.ID != 0 {
		if _, seen := c.debugged.Load(req.Cycle.ID); seen {
			return nil, fmt.Errorf("cycle %d was already debugged; use its diagnosis", req.Cycle.Iteration)
		}
	}
	if req.Cycle != nil && req.Cycle.ID != 0 {
		c.debugged.Store(req.Cycle.ID, true)
	}
	c.debuggerSessions++
	var exclusion string
	status, exclusionErr := c.e.guest.EnsureExclusion(ctx)
	if exclusionErr != nil {
		exclusion = "staging preparation failed: " + clip(exclusionErr.Error(), 400)
	} else {
		exclusion = fmt.Sprintf("%s present (added=%v)", status.Path, status.Added)
		c.e.audit("guest_exclusion", c.e.guestAddr(), fmt.Sprintf("path=%s added=%v", status.Path, status.Added))
	}
	c.e.logClass(logging.ClassLine, "guest debug staging: %s", exclusion)
	prompt := c.debuggerBrief(ctx, req.Trigger, req.Cycle) + "\nGuest staging: " + exclusion
	ws := c.newWorkerSession(roleDebugger)
	defer ws.close()
	for attempt := 0; ; attempt++ {
		result, err := ws.run(ctx, prompt, c.debuggerResume)
		if err != nil {
			c.recordWorkerResult(ctx, roleDebugger, prompt, result, err)
			return nil, err
		}
		diag, parseErr := parseDebugDiagnosis(result.text)
		c.recordWorkerResult(ctx, roleDebugger, prompt, result, parseErr)
		if parseErr == nil {
			c.lastDiagnosis = &diag
			c.e.logClass(logging.ClassCycle, "debugger: cause=%s source_fix=%v online=%v",
				clip(diag.Cause, 200), diag.SourceFixRequired, diag.AgentOnlineAfter)
			if c.confirmOnline(ctx) {
				c.recoverCycle(ctx, req.Cycle, diag)
			}
			return &diag, nil
		}
		c.e.logClass(logging.ClassWarning, "debugger answer was not valid JSON: %v", parseErr)
		if attempt >= 1 {
			return nil, parseErr
		}
		prompt = "Your previous answer was not the required debugger JSON object: " + parseErr.Error() + ". Return exactly one JSON object now."
	}
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
	// A manual relaunch proves the payload can run, not that the monitored run
	// produced a comparable detection result. Keep the cycle offline so it
	// cannot become the finding baseline or the source later cycles restore to.
	summary.AgentOnline = &online
	summary.RecoveredBy = "guest-debugger"
	summary.DebuggerCause = diag.Cause
	summary.GuestActions = diag.GuestActions
	if encoded, err := json.Marshal(summary); err == nil {
		cycle.Summary = string(encoded)
	}
	cycle.AgentOnline = &online
	for i := range c.e.cycles {
		if c.e.cycles[i].ID == cycle.ID {
			c.e.cycles[i] = *cycle
		}
	}
	if cycle.ID != 0 {
		if err := c.e.db.UpdateCycleRecovery(ctx, cycle.ID, cycle.Execution, &online, cycle.Summary); err != nil {
			c.e.logClass(logging.ClassError, "record debugger recovery: %v", err)
		}
	}
	c.e.logClass(logging.ClassCycle,
		"debugger confirmed cycle %d runs after a manual relaunch; the cycle remains %s and is not a detection baseline: %s",
		cycle.Iteration, headerOrNone(cycle.Execution), clip(diag.Cause, 200))
}

func (c *coordinator) watchdog(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}, hardSession bool, sessionTimeout, idleTimeout time.Duration, started time.Time, sessionExpired, idleExpired *atomic.Bool) {
	tick := idleTimeout / 4
	if tick > time.Minute {
		tick = time.Minute
	}
	if tick < time.Second {
		tick = time.Second
	}
	next := func() time.Duration {
		wait := tick
		if c.e.activeTools.Load() == 0 {
			wait = min(wait, idleTimeout-time.Since(time.Unix(0, c.e.lastToolCall.Load())))
			wait = min(wait, sessionTimeout-time.Since(started))
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
		idleFor := time.Since(time.Unix(0, c.e.lastToolCall.Load()))
		if hardSession && time.Since(started) >= sessionTimeout {
			c.e.deadlineHit.Store(true)
			sessionExpired.Store(true)
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
		if tools == 0 && time.Since(started) >= sessionTimeout {
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

func limitCalls(n int, unlimited string) string {
	if n > 0 {
		return fmt.Sprintf("%d calls", n)
	}
	return unlimited
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

func (c *coordinator) recordWorkerResult(ctx context.Context, role evolveRole, prompt string, result workerResult, err error) {
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
		Model: c.modelFor(role), Prompt: prompt, Output: result.text, Status: status, Error: detail,
		Reason: string(result.reason), Turns: result.turns,
		TokensIn: result.usage.InputTokens, TokensOut: result.usage.OutputTokens,
	}); saveErr != nil {
		c.e.logClass(logging.ClassWarning, "record %s worker: %v", role.label(), saveErr)
	}
}

func (c *coordinator) plannerResume(reason string) string {
	switch reason {
	case "session":
		return "The planner decision window expired. Return exactly one JSON plan now; do not call more tools."
	case "idle":
		return "The previous planner turn made no tool call. Return one plan now, or action=stop with the final JSON."
	case "empty":
		return "Your last turn produced no content and no tool call. Return exactly one planner JSON object now: action=test, action=debug only when the brief says the debugger is available, or action=stop."
	default:
		return "The previous model call failed. Continue from the evidence in this session and return exactly one JSON plan now."
	}
}

func (c *coordinator) editorResume(reason string) string {
	switch reason {
	case "session":
		if c.e.sessionCycles.Load() >= 1 {
			return "The editor decision window expired after a completed cycle. Return the result JSON now."
		}
		return "The editor decision window expired. Apply the edit with EditSource now, then call DetectionCycle exactly once. Do not read more files."
	case "idle":
		return "The previous editor turn made no tool call. Apply the edit or call DetectionCycle now."
	case "empty":
		return "Your last turn produced no content. Apply the remaining edit with EditSource and call DetectionCycle exactly once; if the change is already applied, call DetectionCycle now."
	default:
		return "The previous model call failed. Continue from the current source state, finish the edit, and call DetectionCycle."
	}
}

func (c *coordinator) debuggerResume(reason string) string {
	switch reason {
	case "empty":
		return "Your last turn produced no content. Return exactly one debugger JSON object now with the cause, evidence, and guest actions you already have."
	case "session":
		return "The debugger window elapsed. Return exactly one debugger JSON object now."
	case "idle":
		return "The previous debugger turn made no tool call. Return the debugger JSON object now."
	default:
		return "The previous model call failed. Continue from the evidence you gathered and return exactly one debugger JSON object now."
	}
}

func (c *coordinator) plannerBrief() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Loop ID: %s\nBase loop ID: %s\nAttempt: %d (%s)\n", c.e.cfg.LoopID, c.e.baseLoopID, c.e.attempt, attemptLabel(c.e.attempt))
	fmt.Fprintf(&b, "Module: %s\nModule source: %s\nGoal: %s\n", c.e.cfg.Module, c.e.cfg.ModuleDir, headerOrNone(c.e.cfg.Goal))
	fmt.Fprintf(&b, "Agent C2: %s\nExpected agent UUID: %s\nAgent type: %s\n", headerOrNone(c.e.cfg.AgentCC), headerOrNone(c.e.expectedAgentUUID), headerOrNone(c.e.cfg.AgentType))
	fmt.Fprintf(&b, "Active shellcode: %s\nActive producer: %s\nSource roots: %s\n", c.e.shellcode, headerOrNone(c.e.activeProducer), c.e.roots.describe())
	if agentSource := c.e.agentSourceBrief(); agentSource != "" {
		b.WriteString(agentSource + "\n")
	}
	fmt.Fprintf(&b, "Build options: %s\nProducer options (%s): %s\n",
		formatBuildOptions(c.e.buildOptionsSnapshot()), headerOrNone(c.e.activeProducer),
		formatBuildOptions(c.e.activeProducerOptions()))
	if choices := c.e.buildOptionChoiceBrief(); choices != "" {
		fmt.Fprintf(&b, "Build option choices: %s\n", choices)
	}
	if backlog := c.e.hygieneLines(); len(backlog) > 0 {
		b.WriteString("Static hygiene backlog (stable; fix deterministic items before dynamic tuning):\n")
		for _, item := range backlog {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}
	if target := c.producerSwapTarget(); target != "" {
		fmt.Fprintf(&b, "Producer swap: %s is configured and not active; %s. A source edit of the active producer is mechanism=producer, not a swap.\n",
			target, c.e.producerSwapHelp(target))
	} else {
		fmt.Fprintf(&b, "Producer swap: unavailable; configured producers are %s. No producer other than the active %s is configured, so mechanism=producer-swap cannot execute. Use mechanism=producer for a source edit of the active producer, or another available mechanism.\n",
			strings.Join(c.e.producerNames(), ", "), headerOrNone(c.e.activeProducer))
	}
	fmt.Fprintf(&b, "Cycle budget: %d total; %d used; %d remain\nStages: %s\n",
		c.e.cfg.Iterations, c.e.usedCycles(), max(0, c.e.cfg.Iterations-c.e.usedCycles()), strings.Join(stageNames(c.e.cfg.Stages), ", "))
	fmt.Fprintf(&b, "Baseline: %s\nBaseline failure: %s\n", string(c.baselineJSON), headerOrNone(c.e.baselineFailure))
	fmt.Fprintf(&b, "Execution gate: %s\nKnowledge cache: %s\n", c.e.executionHint(), c.knowledgeState)
	if hint := c.e.highRegressionHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.failureLayerHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.coverageHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.dynamicRegionHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if memory := c.e.loopMemoryBrief(); memory != "" {
		b.WriteString(memory + "\n")
	}
	b.WriteString("\n" + c.e.mechanismCatalogBrief())
	if c.knowledgeBrief != "" {
		fmt.Fprintf(&b, "\nRetrieved knowledge (host-side; read a summary before searching):\n%s", c.knowledgeBrief)
	}
	switch {
	case c.e.guest == nil:
		b.WriteString("Guest debugger: disabled (no --guest-ssh); execution=offline cannot be diagnosed inside the VM.\n")
	case c.debuggerPolicy() == debuggerPolicyOff:
		b.WriteString("Guest debugger: disabled by --debugger-policy off; do not choose action=debug.\n")
	case c.debuggerPolicy() == debuggerPolicyFinal:
		fmt.Fprintf(&b, "Guest debugger: deferred to the final stop (%d of %d sessions remain); do not choose action=debug in this cycle.\n",
			c.debuggerRemaining(), c.debuggerBudget())
	case c.debuggerRemaining() <= 0:
		fmt.Fprintf(&b, "Guest debugger: unavailable (%d of %d sessions used); do not choose action=debug.\n",
			c.debuggerSessions, c.debuggerBudget())
	default:
		fmt.Fprintf(&b, "Guest debugger: available (%d of %d sessions remain).\n",
			c.debuggerRemaining(), c.debuggerBudget())
	}
	if cycle := c.e.last; cycle != nil && cycle.ID != 0 {
		if _, seen := c.debugged.Load(cycle.ID); seen {
			fmt.Fprintf(&b, "Cycle %d was already debugged; use its diagnosis instead of requesting debug again.\n", cycle.Iteration)
		}
	}
	if c.e.restoreErr != nil {
		fmt.Fprintf(&b, "Incomplete restore: %s\n", clip(c.e.restoreErr.Error(), 400))
	}
	fmt.Fprintf(&b, "Host limits: %s read-only; %d planner turns; %s decision window. The host blocks read-only calls at the budget and requires the planner JSON at the window; do not count calls yourself.\n", limitCalls(c.e.cfg.PlannerReadBudget, "no read-only cap"), c.turns(rolePlanner), c.e.cfg.PlannerTimeout)
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
	if agentSource := c.e.agentSourceBrief(); agentSource != "" {
		b.WriteString(agentSource + "\n")
	}
	fmt.Fprintf(&b, "Build options: %s\nProducer options (%s): %s\n",
		formatBuildOptions(c.e.buildOptionsSnapshot()), headerOrNone(c.e.activeProducer),
		formatBuildOptions(c.e.activeProducerOptions()))
	if backlog := c.e.hygieneLines(); len(backlog) > 0 {
		b.WriteString("Static hygiene backlog (fix with EditSource; pe/checksum and pe/sections are build/source fixes, not BuildOptions):\n")
		for _, item := range backlog {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.e.activeProducer), "crystal_pack") {
		b.WriteString("Crystal-Kit: crystal_pack PICO; the agent must be windows_dll. loader.spec binds _DLL_/_MASK_/_PICO_/_DLLARGS_; do not edit postex-loader or build.sh to work around a loader-side exit. If a producer build fails because an earlier edit left postex-loader incomplete, restore or repair that file before running DetectionCycle. Diagnose loader -> PICO -> agent check-in in that order.\n")
	}
	if c.editorNote != "" {
		fmt.Fprintf(&b, "\nHost note: %s\n", c.editorNote)
	}
	if hint := c.e.highRegressionHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.failureLayerHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.coverageHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if hint := c.e.dynamicRegionHint(); hint != "" {
		b.WriteString(hint + "\n")
	}
	if memory := c.e.loopMemoryBrief(); memory != "" {
		b.WriteString(memory + "\n")
	}
	if plan.Mechanism != "" {
		b.WriteString("\n" + c.e.mechanismBrief(plan.Mechanism))
	}
	if c.knowledgeBrief != "" {
		fmt.Fprintf(&b, "\nRetrieved knowledge (host-side; read a summary before searching):\n%s", c.knowledgeBrief)
	}
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
	if c.e.restoreErr != nil {
		fmt.Fprintf(&b, "\nRestore incomplete: %s\n", clip(c.e.restoreErr.Error(), 400))
	}
	fmt.Fprintf(&b, "\nHost limits: %s read-only without an edit; %d editor turns; %s decision window. The host blocks reading at the read budget; mutation, build, and cycle tools remain available.", limitCalls(c.e.cfg.EditorReadBudget, "no read-only cap"), c.turns(roleEditor), c.sessionTimeout(roleEditor))
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
	fmt.Fprintf(&b, "Host limits: %s; %d debugger turns; %s decision window. ", limitCalls(c.e.cfg.DebuggerToolBudget, "no total tool cap"), c.turns(roleDebugger), c.sessionTimeout(roleDebugger))
	b.WriteString("\nStart with GuestSSH action=ensure_exclusion, then inspect the guest (Defender exclusion on Windows, staging directory on Linux). This is the only debugger pass for this cycle. Do not repeat a command that already failed.")
	return b.String()
}
