package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// detectRun is one detection loop. The console owns the loop and can
// cancel it, list it, and append operator instructions.
type detectRun struct {
	id      string
	ctx     context.Context
	cancel  context.CancelFunc
	prompts *detection.OperatorPromptQueue
	started time.Time
	logPath string
	logger  *loopLogger
	done    chan struct{}

	current   atomic.Value // string
	attempt   atomic.Int32
	stopped   atomic.Bool
	verified  atomic.Bool
	err       atomic.Pointer[runError]
	finishOne sync.Once
}

// runError boxes an error so the atomic pointer has one concrete type.
type runError struct {
	err error
}

type detectRunInfo struct {
	LoopID        string    `json:"loop_id"`
	CurrentLoopID string    `json:"current_loop_id,omitempty"`
	Attempt       int       `json:"attempt"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	LogPath       string    `json:"log_path"`
	Prompts       int       `json:"prompts"`
	Verified      bool      `json:"verified,omitempty"`
	Error         string    `json:"error,omitempty"`
	OnDisk        bool      `json:"on_disk,omitempty"`
	Resumable     bool      `json:"resumable,omitempty"`
	ResumeAttempt int       `json:"resume_attempt,omitempty"`
}

var detectRuns sync.Map

func registerDetectRun(id string, prompts *detection.OperatorPromptQueue, logPath string, logger *loopLogger) (*detectRun, error) {
	ctx, cancel := context.WithCancel(context.Background())
	run := &detectRun{
		id: id, ctx: ctx, cancel: cancel, prompts: prompts,
		started: time.Now().UTC(), logPath: logPath, logger: logger,
		done: make(chan struct{}),
	}
	run.current.Store(id)
	run.attempt.Store(1)
	if _, loaded := detectRuns.LoadOrStore(id, run); loaded {
		cancel()
		return nil, fmt.Errorf("loop %s is already registered", id)
	}
	return run, nil
}

func findDetectRun(id string) *detectRun {
	id = strings.TrimSpace(id)
	if run, ok := detectRuns.Load(id); ok {
		return run.(*detectRun)
	}
	var found *detectRun
	detectRuns.Range(func(_, value any) bool {
		run := value.(*detectRun)
		if run.currentLoopID() == id {
			found = run
			return false
		}
		return true
	})
	return found
}

// listDetectRunInfos merges the in-memory registry with manifests and reports
// on disk. A loop that was stopped or interrupted is still visible after the
// console restarts, and a manifest-backed loop is resumable.
func listDetectRunInfos() []detectRunInfo {
	var infos []detectRunInfo
	seen := map[string]bool{}
	for _, run := range listDetectRuns() {
		info := run.info()
		infos = append(infos, info)
		seen[info.LoopID] = true
		if info.CurrentLoopID != "" {
			seen[info.CurrentLoopID] = true
		}
	}
	infos = append(infos, onDiskLoopInfos(seen)...)
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].StartedAt.Equal(infos[j].StartedAt) {
			return infos[i].LoopID < infos[j].LoopID
		}
		return infos[i].StartedAt.Before(infos[j].StartedAt)
	})
	return infos
}

func listDetectRuns() []*detectRun {
	var runs []*detectRun
	detectRuns.Range(func(_, value any) bool {
		runs = append(runs, value.(*detectRun))
		return true
	})
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].started.Before(runs[j].started)
	})
	return runs
}

func resetDetectRunsForTest() {
	detectRuns.Range(func(key, _ any) bool {
		detectRuns.Delete(key)
		return true
	})
}

func (r *detectRun) currentLoopID() string {
	current, _ := r.current.Load().(string)
	return current
}

func (r *detectRun) setCurrent(current string, attempt int) {
	r.current.Store(current)
	r.attempt.Store(int32(attempt))
}

func (r *detectRun) setResult(result *detection.EvolveResult) {
	if result == nil {
		return
	}
	r.verified.Store(result.PayloadVerified)
	if result.LoopID != "" {
		r.current.Store(result.LoopID)
	}
}

func (r *detectRun) setError(err error) {
	if err == nil {
		return
	}
	r.err.Store(&runError{err: err})
}

func (r *detectRun) isDone() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// requestStop cancels the run once. It reports whether this call stopped it.
func (r *detectRun) requestStop() bool {
	if r.isDone() {
		return false
	}
	if !r.stopped.CompareAndSwap(false, true) {
		return false
	}
	r.cancel()
	return true
}

func (r *detectRun) finish() {
	r.finishOne.Do(func() {
		if r.logger != nil {
			r.logger.close()
		}
		close(r.done)
	})
}

func (r *detectRun) terminalStatus() string {
	switch {
	case r.err.Load() != nil && !r.stopped.Load():
		return "failed"
	case r.verified.Load():
		return "verified"
	case r.stopped.Load():
		return "stopped"
	default:
		return "done"
	}
}

func (r *detectRun) status() string {
	select {
	case <-r.done:
		return r.terminalStatus()
	default:
		if r.stopped.Load() {
			return "stopping"
		}
		return "running"
	}
}

func (r *detectRun) info() detectRunInfo {
	info := detectRunInfo{
		LoopID: r.id, CurrentLoopID: r.currentLoopID(), Attempt: int(r.attempt.Load()),
		Status: r.status(), StartedAt: r.started, LogPath: r.logPath,
		Verified: r.verified.Load(),
	}
	if r.prompts != nil {
		info.Prompts = r.prompts.Len()
	}
	if failure := r.err.Load(); failure != nil {
		info.Error = failure.err.Error()
	}
	return info
}

func detectRunInfoRows(infos []detectRunInfo) []string {
	rows := make([]string, 0, len(infos)+1)
	rows = append(rows, fmt.Sprintf("%-30s %-7s %-11s %-19s %-7s %-9s %s",
		"LOOP", "ATTEMPT", "STATUS", "STARTED", "PROMPTS", "RESUMABLE", "LOG"))
	for _, info := range infos {
		started := "-"
		if !info.StartedAt.IsZero() {
			started = info.StartedAt.Local().Format("2006-01-02 15:04:05")
		}
		resumable := "no"
		if info.Resumable {
			resumable = fmt.Sprintf("yes (%d)", info.ResumeAttempt)
		}
		rows = append(rows, fmt.Sprintf("%-30s %-7d %-11s %-19s %-7d %-9s %s",
			sanitize.SanitizeOneLine(info.LoopID), info.Attempt, sanitize.SanitizeOneLine(info.Status),
			started, info.Prompts, resumable, sanitize.SanitizeOneLine(info.LogPath)))
	}
	return rows
}

// stopDetectRun cancels one loop and waits up to wait for it to
// return. The loop keeps a registry entry with a final status.
func stopDetectRun(id string, wait time.Duration) (detectRunInfo, bool, error) {
	run := findDetectRun(id)
	if run == nil {
		return detectRunInfo{}, false, fmt.Errorf("loop %q is not running", id)
	}
	if !run.requestStop() {
		return run.info(), false, nil
	}
	if wait > 0 {
		select {
		case <-run.done:
		case <-time.After(wait):
		}
	}
	return run.info(), true, nil
}

// stopAllDetectRuns cancels every loop. The console calls this on
// exit; process termination then ends any remaining build or model call.
func stopAllDetectRuns() {
	runs := listDetectRuns()
	if len(runs) == 0 {
		return
	}
	cancelled := 0
	for _, run := range runs {
		if run.requestStop() {
			cancelled++
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		remaining := false
		for _, run := range runs {
			if !run.isDone() {
				remaining = true
				break
			}
		}
		if !remaining {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	logging.Warningf("detect_loop: cancelled %d loop(s) on console exit", cancelled)
}

func appendDetectRunPrompt(id, text string) (detectRunInfo, error) {
	run := findDetectRun(id)
	if run == nil {
		return detectRunInfo{}, fmt.Errorf("loop %q is not running", id)
	}
	if run.isDone() {
		return run.info(), fmt.Errorf("loop %q has finished", id)
	}
	if run.prompts == nil {
		return run.info(), fmt.Errorf("loop %q has no prompt queue", id)
	}
	if _, err := run.prompts.Add(text); err != nil {
		return run.info(), err
	}
	return run.info(), nil
}

// removeFinishedDetectRun drops a completed registry entry so an on-disk loop
// can be resumed in the same console process.
func removeFinishedDetectRun(id string) error {
	run := findDetectRun(id)
	if run == nil {
		return nil
	}
	if !run.isDone() {
		return fmt.Errorf("loop %s is still running", run.currentLoopID())
	}
	detectRuns.Delete(run.id)
	return nil
}

// runDetectLoop drives one console loop and its verification restarts.
func runDetectLoop(run *detectRun, opts detectLoopOptions, shellcode, baseID string, startAttempt, maxAttempts int) {
	if startAttempt < 1 {
		startAttempt = 1
	}
	if maxAttempts < startAttempt {
		maxAttempts = startAttempt
	}
	backend := liveDetectC2Backend{}
	currentShellcode := shellcode
	currentOpts := opts
	currentID := baseID
	if startAttempt > 1 {
		currentID = fmt.Sprintf("%s-r%d", baseID, startAttempt)
	}
	run.setCurrent(currentID, startAttempt)
	saveLoopManifest(baseID, currentID, startAttempt, "running", currentOpts, run)
	defer func() {
		// Persist the terminal state before closing done. A concurrent resume
		// observes done and can register a new attempt; writing the manifest
		// after that would overwrite the new attempt with this one.
		saveLoopManifest(baseID, run.currentLoopID(), int(run.attempt.Load()), run.terminalStatus(), currentOpts, run)
		run.finish()
	}()
	lastAgent := opts.AgentUUID
	producers, err := detection.ParseProducerDirs(opts.Producers)
	if err != nil {
		run.setError(fmt.Errorf("producer paths: %w", err))
		return
	}
	guest, err := opts.guestConfig()
	if err != nil {
		run.setError(fmt.Errorf("guest SSH: %w", err))
		logging.Errorf("detect_loop: %v", err)
		return
	}

	logf := func(format string, args ...any) {
		if run.logger != nil {
			run.logger.printf(format, args...)
		}
	}
	for attempt := startAttempt; attempt <= maxAttempts; attempt++ {
		if run.ctx.Err() != nil {
			run.setError(run.ctx.Err())
			return
		}
		if attempt > startAttempt {
			if strings.TrimSpace(currentOpts.Shellcode) != "" && !currentOpts.ShellcodeGenerated {
				logf("payload verification failed; --shellcode was supplied and cannot be regenerated")
				break
			}
			logf("payload verification failed; restarting loop with a fresh agent (attempt %d/3)", attempt)
			forgetLoopAgent(lastAgent)
			nextShellcode, agentArtifact, producer, agentType, agentUUID, genErr := generateAgentShellcode(currentOpts, logf)
			if genErr != nil {
				run.setError(fmt.Errorf("restart shellcode generation: %w", genErr))
				break
			}
			currentShellcode = nextShellcode
			currentOpts.Shellcode = nextShellcode
			currentOpts.AgentArtifact = agentArtifact
			currentOpts.ShellcodeGenerated = true
			currentOpts.AgentType = agentType
			currentOpts.ShellcodeProducer = producer
			currentOpts.AgentUUID = agentUUID
			lastAgent = agentUUID
			currentID = fmt.Sprintf("%s-r%d", baseID, attempt)
			run.setCurrent(currentID, attempt)
			saveLoopManifest(baseID, currentID, attempt, "running", currentOpts, run)
			logf("restarted loop %s with agent %s", currentID, agentUUID)
		}

		cfg := detection.EvolveConfig{
			LoopID: currentID, BaseLoopID: baseID, Attempt: attempt,
			Module: currentOpts.Module, ModuleDir: currentOpts.ModuleDir,
			Platform: currentOpts.Platform, AgentSourceDir: currentOpts.AgentSourceDir,
			Shellcode: currentShellcode, InitialAgentArtifact: currentOpts.AgentArtifact,
			InitialShellcodeGenerated: currentOpts.ShellcodeGenerated,
			SandboxURL:                currentOpts.Sandbox,
			StoreRoot:                 filepath.Join(live.EmpWorkSpace, "detection"),
			Process:                   currentOpts.Process, Format: currentOpts.Format,
			Inject: currentOpts.Inject, SMW: currentOpts.SMW,
			ProducerDirs: producers, InitialProducer: currentOpts.ShellcodeProducer,
			ReadRoots: currentOpts.ReadRoots, KnowledgePath: currentOpts.Knowledge,
			ExpectedAgentUUID: currentOpts.AgentUUID,
			Iterations:        currentOpts.Iterations, Turns: currentOpts.Turns,
			Git:          currentOpts.Git,
			PlannerTurns: currentOpts.PlannerTurns, PlannerTimeout: currentOpts.PlannerTimeout,
			PlannerReadBudget: currentOpts.PlannerReadBudget, EditorReadBudget: currentOpts.EditorReadBudget,
			DebuggerToolBudget: currentOpts.DebuggerToolBudget,
			EditorTimeout:      currentOpts.EditorTimeout, EditorTurns: currentOpts.EditorTurns,
			DebuggerTurns: currentOpts.DebuggerTurns, DebuggerTimeout: currentOpts.DebuggerTimeout,
			DebuggerPolicy: currentOpts.DebuggerPolicy,
			Pricing:        currentOpts.Pricing,
			WorkerModels:   currentOpts.WorkerModels, Guest: guest,
			CycleTimeout:    currentOpts.CycleTimeout,
			SessionTimeout:  currentOpts.SessionTimeout,
			ToolIdleTimeout: currentOpts.ToolIdleTimeout,
			Goal:            currentOpts.Goal, AgentType: currentOpts.AgentType,
			AgentArch: currentOpts.Arch, AgentCC: currentOpts.CC,
			AgentGlibc: currentOpts.AgentGlibc, AgentDynload: currentOpts.AgentDynload, AgentLibc: currentOpts.AgentLibc,
			AgentTags: currentOpts.AgentTags,
			Prompts:   run.prompts,
			BuildAgent: func(buildOpts detection.AgentBuildOptions) (*detection.AgentBuildResult, error) {
				return backend.GenerateAgent(currentOpts.CC, buildOpts)
			},
			Verify: backend,
			FinalVerify: func(ctx context.Context, uuid string) (string, error) {
				return backend.FinalVerify(ctx, uuid, detection.DefaultVerifyModule)
			},
			Audit: backend.Audit,
			Logf:  logClassf(run.logger),
		}
		result, runErr := detection.RunEvolve(run.ctx, cfg)
		if runErr != nil {
			if errors.Is(runErr, detection.ErrCycleBudgetExhausted) {
				run.setError(runErr)
				logf("%v", runErr)
				printDetectRunReport(run, currentID)
				return
			}
			run.setError(runErr)
			if run.ctx.Err() != nil {
				printDetectRunReport(run, currentID)
				return
			}
			logging.Errorf("Detection loop %s: %v", currentID, runErr)
			logf("loop failed: %v", runErr)
			printDetectRunReport(run, currentID)
			return
		}
		run.setResult(result)
		if result.ExpectedAgentUUID != "" {
			lastAgent = result.ExpectedAgentUUID
			currentOpts.AgentUUID = result.ExpectedAgentUUID
		}
		if result.Last != nil {
			var last struct {
				Shellcode          string `json:"shellcode"`
				Producer           string `json:"producer"`
				ShellcodeGenerated bool   `json:"shellcode_generated"`
			}
			if json.Unmarshal([]byte(result.Last.Summary), &last) == nil {
				if last.Shellcode != "" {
					currentOpts.Shellcode = last.Shellcode
					if last.ShellcodeGenerated {
						currentOpts.ShellcodeGenerated = true
					}
				}
				if last.Producer != "" {
					currentOpts.ShellcodeProducer = last.Producer
				}
			}
		}
		saveLoopManifest(baseID, currentID, attempt, "running", currentOpts, run)
		printDetectRunReport(run, currentID)
		if result.PayloadVerified {
			return
		}
		if result.AgentOnlineSeen {
			// The beacon may die before the final BOF. A check-in at any point
			// proves the payload executed, so do not restart the whole loop and
			// discard the completed cycles just because the last check failed.
			logf("final verification was inconclusive, but the agent checked in; keeping the completed loop")
			return
		}
		if run.ctx.Err() != nil {
			run.setError(run.ctx.Err())
			return
		}
	}
	if run.ctx.Err() == nil {
		run.setError(fmt.Errorf("loop ended without a verified payload"))
	}
}

func printDetectRunReport(run *detectRun, loopID string) {
	reportPath := filepath.Join(live.EmpWorkSpace, "detection", "reports", loopID+".md")
	summary, source := readLoopSummary(reportPath)
	if strings.TrimSpace(summary) == "" {
		return
	}
	logging.Successf("Detection loop report: %s", reportPath)
	logging.DisplayMarkdown(summary)
	if run.logger != nil {
		run.logger.printf("executive summary printed from %s", source)
	}
}

// logClassf adapts the loop logger to detection's Logf callback.
func logClassf(logger *loopLogger) func(logging.Class, string, ...any) {
	if logger == nil {
		return func(logging.Class, string, ...any) {}
	}
	return logger.logf
}
