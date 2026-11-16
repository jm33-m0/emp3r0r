package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	defaultEvolveIterations = 3
	defaultEvolveTurns      = 60
	// maxEvolveIterations and maxEvolveTurns bound one loop even when the
	// caller supplies its own values; an MCP caller must not start an
	// unbounded model/build/detonation run.
	maxEvolveIterations = 50
	maxEvolveTurns      = 240
	maxEvolveBuildLog   = 8 << 20
	// maxEvolveStalledResumes bounds restarts that make no cycle progress.
	maxEvolveStalledResumes = 4
	// defaultCycleTimeout bounds one build/detonate/verify cycle.
	defaultCycleTimeout = 60 * time.Minute
	// defaultSessionTimeout bounds one model session even when it keeps
	// calling tools, so a stream that never terminates cannot run forever.
	defaultSessionTimeout = 2 * time.Hour
	// defaultToolIdleTimeout bounds a model session that stops calling tools.
	// An in-flight tool suspends the idle check.
	defaultToolIdleTimeout = 30 * time.Minute
	// defaultProgressInterval emits a heartbeat during long sessions.
	defaultProgressInterval = 2 * time.Minute
	// minAgentShellcodeBytes rejects a tiny blob that no real Go agent could
	// have produced. It catches a loader that drops the payload to reduce
	// detections.
	minAgentShellcodeBytes = 32 << 10
	// A loader embeds the active shellcode. Requiring the artifact to be at
	// least a quarter of it catches a build that removes the payload while
	// allowing a producer that compresses the blob.
	minArtifactShellcodeRatio = 4
)

// Execution states recorded for every cycle. A dynamic cycle is valid only
// when its generated agent checked in on the C2; the analyzer score of a
// payload that never ran says nothing about evasion.
const (
	executionVerified   = "verified"
	executionOffline    = "offline"
	executionUnverified = "unverified"
	executionStatic     = "static"
)

// EvolveConfig drives an autonomous detection -> feedback -> edit -> rebuild
// loop for one local payload module.
type EvolveConfig struct {
	LoopID string
	// BaseLoopID is the logical loop that spans attempts. Empty means LoopID.
	BaseLoopID string
	// Attempt is the one-based attempt number within BaseLoopID. Empty or zero
	// means the first attempt.
	Attempt   int
	Module    string
	ModuleDir string
	Shellcode string
	// InitialAgentArtifact is the agent executable or DLL wrapped into
	// Shellcode. The loop deletes it when it rotates the test agent.
	InitialAgentArtifact string
	// InitialShellcodeGenerated marks Shellcode as a loop artifact instead of
	// an operator-supplied file, so rotation may delete it.
	InitialShellcodeGenerated bool
	SandboxURL                string
	StoreRoot                 string
	// Process is passed to the loader build when non-empty. Leave it empty to
	// let the module's own default control the sacrificial process, so a source
	// edit to that default changes the next build.
	Process string
	Format  string
	Inject  string
	SMW     string
	Stages  []string
	// ProducerDirs maps a shellcode-producer module name (donut, crystal_pack)
	// to its source directory. The loop may read and edit these modules and run
	// their build to replace the shellcode a later cycle loads.
	ProducerDirs map[string]string
	// InitialProducer names the module that generated Shellcode. It tells the
	// model which producer to inspect when the blob itself is the signal.
	InitialProducer string
	// ReadRoots are extra directories the source tools may read but not edit,
	// such as modules/common or c_agent util sources a module links.
	ReadRoots []string
	// KnowledgePath is the offline reference cache. When it is empty the store
	// default is used; a missing cache only disables the knowledge tools.
	KnowledgePath string
	// Prompts is the operator instruction queue. The console appends
	// instructions while the loop runs; the loop drains them before each model
	// session and after each cycle.
	Prompts *OperatorPromptQueue
	// ExpectedAgentUUID is the UUID of the agent the active shellcode was
	// built from. The verification tools use it to distinguish the payload
	// under test from unrelated agents already connected to the C2.
	ExpectedAgentUUID string
	Iterations        int
	Turns             int
	// Provider and Model override the environment; tests use a scripted
	// provider, production uses EMP3R0R_DETECTION_* and the usual API key.
	Provider llm.Provider
	Model    string
	// RetryBase is the first recovery delay; it backs off to 30 seconds.
	RetryBase time.Duration
	// CycleTimeout bounds one build/detonate/verify cycle. Zero uses
	// defaultCycleTimeout.
	CycleTimeout time.Duration
	// SessionTimeout bounds one model session. Zero uses defaultSessionTimeout.
	SessionTimeout time.Duration
	// ToolIdleTimeout bounds a model session that stops calling tools. Zero
	// uses defaultToolIdleTimeout.
	ToolIdleTimeout time.Duration
	// Logf receives every loop line with its category so the host can colorize
	// model text, thinking, tool calls, builds, and cycles independently.
	Logf func(class logging.Class, format string, args ...any)
	// Build overrides the module build; tests use it to avoid the C toolchain.
	Build func(moduleDir string, flags map[string]string) (string, error)
	// BuildProducer overrides a shellcode-producer build. Production uses the
	// same local module build path as the payload module.
	BuildProducer func(moduleDir, module string, flags map[string]string) (string, error)
	// BuildAgent rebuilds the Go agent with new generator flags. The console
	// wires this to the operator builder; tests may stub it.
	BuildAgent func(AgentBuildOptions) (*AgentBuildResult, error)
	// Verify performs scoped C2 checks for the loop's own test agent. When
	// nil, AgentStatus, RunModule, and CleanupAgent are neither registered nor
	// permitted.
	Verify VerifyOps
	// FinalVerify runs once after the agent loop finishes. It polls for the
	// expected agent, executes a small BOF, and returns its output. A failed
	// verification marks the result and lets the caller restart the loop.
	FinalVerify func(context.Context, string) (string, error)
	// Audit records every C2 action the model can trigger, including denials.
	// The caller writes it to the operator audit log.
	Audit func(action, target, detail string)
	// Goal is the operator's high-level objective shown at the top of the
	// model prompt. Empty uses the default evasion-and-execution goal.
	Goal string
	// AgentType and AgentArch are the generator defaults shown to the model
	// and used by GenerateAgent when the model omits an override. The C2
	// address always comes from the operator configuration.
	AgentType string
	AgentArch string
	AgentCC   string
}

// AgentBuildOptions describes one real agent rebuild. Only the Windows payload
// types are accepted because loader_windows is x64 PE-only.
type AgentBuildOptions struct {
	Type string
	Arch string
}

// AgentBuildResult is the freshly generated agent artifact and its shellcode.
// ArtifactPath is the EXE or DLL; ShellcodePath is the Donut/PICO blob the
// loader embeds.
type AgentBuildResult struct {
	ArtifactPath  string
	ShellcodePath string
	Type          string
	Arch          string
	AgentUUID     string
	SHA256        string
	Size          int64
}

// EvolveResult is the final answer plus the cycles the agent ran.
type EvolveResult struct {
	LoopID            string          `json:"loop_id"`
	BaseLoopID        string          `json:"base_loop_id,omitempty"`
	Attempt           int             `json:"attempt,omitempty"`
	GlobalCycles      int             `json:"global_cycles,omitempty"`
	SourceTreeHash    string          `json:"source_tree_hash,omitempty"`
	Answer            json.RawMessage `json:"answer"`
	Report            string          `json:"report"`
	Cycles            []Cycle         `json:"cycles"`
	Last              *Cycle          `json:"last,omitempty"`
	PayloadVerified   bool            `json:"payload_verified"`
	AgentOnlineSeen   bool            `json:"agent_online_seen,omitempty"`
	ExpectedAgentUUID string          `json:"expected_agent_uuid,omitempty"`
}

type evolver struct {
	cfg           EvolveConfig
	loop          *Loop
	db            *TelemetryDB
	logf          func(logging.Class, string, ...any)
	iter          int
	last          *Cycle
	cycles        []Cycle
	roots         *sourceRoots
	shellcode     string
	agentArtifact string
	// initialShellcodeGenerated records whether cfg.Shellcode was built by the
	// loop, so rotation may delete the original file.
	initialShellcodeGenerated bool
	activeProducer            string
	expectedAgentUUID         string
	testedAgentUUIDs          map[string]struct{}
	testedShellcodes          map[string]struct{}
	shellSeq                  int
	knowledge                 *KnowledgeDB
	lastAnswer                map[string]any
	baselineFailure           string
	operatorPrompts           *OperatorPromptQueue
	// progress counts cycles that produced a comparable result; an offline
	// cycle consumes the budget but does not count as progress, so the stalled
	// session guard cannot be reset by builds whose payload never ran.
	progress         int
	lastExecuting    *Cycle
	executionBlocked bool
	// executionCheckTimeout overrides PayloadVerifyTimeout in tests.
	executionCheckTimeout time.Duration

	baseLoopID      string
	attempt         int
	globalUsed      int
	priorCycles     []Cycle
	priorAnswer     map[string]any
	pendingEdits    []EditRecord
	priorLastGood   *Cycle
	priorSourceHash string
	sourceTreeHash  string
	lastToolCall    atomic.Int64
	activeTools     atomic.Int32
	knowledgeSeen   map[string]struct{}
	started         time.Time
	cyclesDone      atomic.Int64
	toolCalls       atomic.Int64
	sessions        atomic.Int64
	agentSeenOnline atomic.Bool
	lastExecution   atomic.Value
	lastAgent       atomic.Value
}

func (e *evolver) dynamicEnabled() bool {
	stages, err := stageSet(e.cfg.Stages)
	return err == nil && (stages[string(StageDynamic)] || stages["edr"])
}

func (e *evolver) activeShellcode() string {
	if strings.TrimSpace(e.shellcode) != "" {
		return e.shellcode
	}
	return e.cfg.Shellcode
}

// payloadDir is the directory whose agent artifact and shellcode the producer
// may read. GenerateAgent updates the artifact before a producer runs.
func (e *evolver) payloadDir() string {
	if strings.TrimSpace(e.agentArtifact) != "" {
		return filepath.Dir(e.agentArtifact)
	}
	return filepath.Dir(e.activeShellcode())
}

func (e *evolver) log(format string, args ...any) {
	e.logf(logging.ClassLine, format, args...)
}

func (e *evolver) logClass(class logging.Class, format string, args ...any) {
	e.logf(class, format, args...)
}

// audit records one model-triggered C2 action. An unset callback means the
// caller has its own audit path (the MCP server audits detection_loop itself).
func (e *evolver) audit(action, target, detail string) {
	if e.cfg.Audit != nil {
		e.cfg.Audit(action, target, detail)
	}
}

// sourceRoots builds the named source tree the model sees. The payload module
// is editable; producer modules are editable because the loop must be able to
// tune the shellcode producer; read roots are read-only build inputs.
func (e *evolver) sourceRoots() *sourceRoots {
	roots := []sourceRoot{{Name: e.cfg.Module, Dir: e.cfg.ModuleDir, Writable: true}}
	used := map[string]bool{e.cfg.Module: true}
	for name, dir := range e.cfg.ProducerDirs {
		roots = append(roots, sourceRoot{Name: name, Dir: dir, Writable: true})
		used[name] = true
	}
	for _, dir := range e.cfg.ReadRoots {
		name := dependencyRootName(filepath.Base(filepath.Clean(dir)), used)
		used[name] = true
		roots = append(roots, sourceRoot{Name: name, Dir: dir})
	}
	trees, err := newSourceRoots(e.cfg.Module, roots...)
	if err != nil {
		e.log("source roots: %v; falling back to the payload module", err)
		fallback, _ := newSourceRoots(e.cfg.Module, sourceRoot{Name: e.cfg.Module, Dir: e.cfg.ModuleDir, Writable: true})
		return fallback
	}
	return trees
}

// dependencyRootName turns a directory name into a unique source-root name.
func dependencyRootName(base string, used map[string]bool) string {
	name := strings.ToLower(base)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name = strings.Trim(b.String(), "_-")
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "dep" + name
	}
	if len(name) > 28 {
		name = name[:28]
	}
	candidate := name
	for i := 2; used[candidate]; i++ {
		candidate = fmt.Sprintf("%s%d", name, i)
	}
	return candidate
}

// openKnowledge attaches the offline reference cache. A missing cache is not a
// loop failure; the knowledge tools then explain how to populate it.
func (e *evolver) openKnowledge() {
	path := strings.TrimSpace(e.cfg.KnowledgePath)
	if path == "" {
		path = KnowledgePath(e.cfg.StoreRoot)
	}
	db, err := OpenKnowledgeDB(path, false)
	if err != nil {
		e.log("knowledge cache unavailable: %v", err)
		return
	}
	e.knowledge = db
	if count, err := db.Count(context.Background()); err == nil {
		e.log("knowledge cache: %d documents from %s", count, path)
	}
}

func (e *evolver) root(name string) (sourceRoot, error) {
	return e.roots.pick(name)
}

func (e *evolver) producer(name string) (string, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	dir, ok := e.cfg.ProducerDirs[name]
	if !ok || strings.TrimSpace(dir) == "" {
		return "", "", fmt.Errorf("producer %q is not configured; available: %s", name, strings.Join(e.producerNames(), ", "))
	}
	return name, dir, nil
}

func (e *evolver) producerNames() []string {
	return slices.Sorted(maps.Keys(e.cfg.ProducerDirs))
}

// waitSandbox probes the sandbox once. The failure goes straight to the model
// instead of a host retry loop, so the loop never rebuilds or detonates again
// without model feedback.
func (e *evolver) waitSandbox(ctx context.Context) (Health, error) {
	health := e.loop.Available(ctx)
	if health.Available {
		return health, nil
	}
	reason := strings.TrimSpace(health.Error)
	if reason == "" {
		reason = strings.Join(health.Issues, "; ")
	}
	if reason == "" {
		reason = "health probe failed"
	}
	return Health{}, fmt.Errorf("sandbox %s is unreachable: %s", health.URL, reason)
}

// recover logs a failure and waits before the caller retries. Callers bound
// the number of attempts; recover returns false only when the context is done.
func (e *evolver) recover(ctx context.Context, attempt int, what string, err error) bool {
	delay := e.cfg.RetryBase
	if delay <= 0 {
		delay = 2 * time.Second
	}
	for i := 0; i < attempt && delay < 30*time.Second; i++ {
		delay = delay * 3 / 2
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	e.logClass(logging.ClassWarning, "%s failed (attempt %d): %v; retrying in %s", what, attempt+1, err, delay)
	select {
	case <-ctx.Done():
		return false
	case <-time.After(delay):
		return true
	}
}

// RunEvolve builds a baseline artifact, then lets a Norma agent drive the
// iteration. Bulk feedback, builds, and telemetry stay in SQLite; the model
// context carries instructions and bounded tool results only.
func RunEvolve(ctx context.Context, cfg EvolveConfig) (*EvolveResult, error) {
	if err := normalizeEvolveConfig(&cfg); err != nil {
		return nil, err
	}
	var err error
	provider := cfg.Provider
	model := cfg.Model
	if provider == nil {
		provider, model, err = configuredProvider()
		if err != nil {
			return nil, err
		}
	}
	if provider == nil {
		return nil, fmt.Errorf("detection loop has no model: set EMP3R0R_DETECTION_MODEL and the provider API key")
	}
	if model == "" {
		model = "configured"
	}
	loop, err := NewLoop(LoopConfig{SandboxURL: cfg.SandboxURL, StoreRoot: cfg.StoreRoot})
	if err != nil {
		return nil, err
	}
	if loop.Telemetry == nil {
		return nil, fmt.Errorf("telemetry database is not configured")
	}
	defer loop.Telemetry.Close()
	e := &evolver{
		cfg: cfg, loop: loop, db: loop.Telemetry, logf: cfg.Logf, shellcode: cfg.Shellcode,
		agentArtifact:             strings.TrimSpace(cfg.InitialAgentArtifact),
		initialShellcodeGenerated: cfg.InitialShellcodeGenerated,
		activeProducer:            strings.ToLower(strings.TrimSpace(cfg.InitialProducer)),
		expectedAgentUUID:         strings.TrimSpace(cfg.ExpectedAgentUUID),
		testedAgentUUIDs:          make(map[string]struct{}),
		testedShellcodes:          make(map[string]struct{}),
	}
	if e.logf == nil {
		e.logf = func(logging.Class, string, ...any) {}
	}
	e.baseLoopID = strings.TrimSpace(cfg.BaseLoopID)
	if e.baseLoopID == "" {
		e.baseLoopID = cfg.LoopID
	}
	e.attempt = cfg.Attempt
	if e.attempt < 1 {
		e.attempt = 1
	}
	e.operatorPrompts = cfg.Prompts
	e.roots = e.sourceRoots()
	e.sourceTreeHash = e.computeSourceTreeHash()
	if e.attempt > 1 || e.baseLoopID != cfg.LoopID {
		if err := e.loadAttemptState(ctx); err != nil {
			return nil, err
		}
	}
	if e.usedCycles() >= cfg.Iterations {
		return nil, fmt.Errorf("%w: %d of %d cycles used across attempts", ErrCycleBudgetExhausted, e.usedCycles(), cfg.Iterations)
	}
	e.log("detection loop %s: base=%s attempt=%d module=%s model=%s shellcode=%s",
		cfg.LoopID, e.baseLoopID, e.attempt, cfg.Module, model, cfg.Shellcode)
	e.logClass(logging.ClassWarning, "the loop executes model-chosen builds on this host; source review and prompt rules do not contain the model, so run it in a dedicated, disposable VM with no host credentials")
	if roots := e.roots.describe(); roots != "" {
		e.log("source roots: %s", roots)
	}
	if e.sourceTreeHash != "" {
		e.log("source tree: %s", e.sourceTreeHash)
	}
	e.started = time.Now()
	progressDone := make(chan struct{})
	go e.progressLoop(ctx, progressDone)
	defer close(progressDone)
	completed := false
	defer func() {
		if !completed {
			e.persistPartial()
		}
	}()
	e.openKnowledge()
	if e.knowledge != nil {
		defer func() { _ = e.knowledge.Close() }()
	}
	provider = &loggingProvider{next: provider, logf: e.logf}

	// A failed baseline goes to the model instead of a silent host retry: the
	// model can inspect the build log and telemetry, fix the cause, and then
	// call DetectionCycle.
	var baseline Cycle
	baseline, err = e.runCycle(ctx, "baseline", "baseline", "")
	switch {
	case err == nil:
		e.last = &baseline
	case errors.Is(err, ErrCycleBudgetExhausted):
		return nil, err
	case ctx.Err() != nil:
		return nil, ctx.Err()
	default:
		e.baselineFailure = clipUTF8(sanitizeLine(err.Error()), 4000)
		e.logClass(logging.ClassWarning,
			"baseline failed; asking the model to diagnose the failure before another attempt: %s",
			e.baselineFailure)
	}
	baselineJSON, _ := json.Marshal(baseline)

	producerList := "none configured"
	if names := e.producerNames(); len(names) > 0 {
		producerList = strings.Join(names, ", ")
	}
	rootList := e.roots.describe()
	executionState := "the host checks the generated agent after every dynamic cycle with AgentStatus and records execution=verified, offline, or unverified"
	if e.baselineFailure != "" {
		executionState = "the baseline did not complete; diagnose the failure and fix it before another cycle"
	} else if e.executionBlocked {
		executionState = "the baseline payload did not check in and no executing baseline exists; do not run more cycles; return the final JSON with the execution failure"
	} else if e.lastExecuting != nil {
		payload := shortPayloadKey(e.lastExecuting.PayloadKey)
		if payload == "" {
			payload = "the baseline"
		}
		executionState = fmt.Sprintf("the last executing payload is %s; the host checks every dynamic cycle with AgentStatus and restores this payload after a non-executing cycle", payload)
	}
	knowledgeState := "unavailable; ask the operator to run detect_loop knowledge-sync"
	if e.knowledge != nil {
		knowledgeState = "available: " + e.knowledge.Path() + " (KnowledgeSearch, KnowledgeRead, KnowledgeStats, KnowledgeList)"
		if stats, statsErr := e.knowledge.Stats(ctx); statsErr == nil {
			switch {
			case stats.Documents == 0:
				knowledgeState = "empty at " + e.knowledge.Path() + "; continue with telemetry and source evidence, and ask the operator to run detect_loop knowledge-sync"
			default:
				notebooks := make([]string, 0, 6)
				for _, item := range stats.Notebooks {
					if len(notebooks) >= 6 {
						notebooks = append(notebooks, "...")
						break
					}
					notebooks = append(notebooks, fmt.Sprintf("%s %d/%d content", item.Notebook, item.Contents, item.Documents))
				}
				knowledgeState = fmt.Sprintf("available: %d documents at %s (%d summaries, %d content); notebooks: %s; call KnowledgeStats before searching an unfamiliar surface",
					stats.Documents, e.knowledge.Path(), stats.Summaries, stats.Contents, strings.Join(notebooks, ", "))
			}
		} else {
			knowledgeState = "available: " + e.knowledge.Path() + " (coverage query failed; KnowledgeSearch still works)"
		}
	}
	system := evolveSystemPrompt
	carriedState := ""
	if len(e.priorCycles) > 0 || e.attempt > 1 {
		carriedState = "\nPrior attempt state:\n" + e.dossier()
	}
	prompt := fmt.Sprintf(`Loop ID: %s
Base loop ID: %s
Attempt: %d (%s)
Module: %s
Module source: %s
Active shellcode: %s
Active shellcode producer: %s
Producer modules: %s
Source roots: %s
Agent C2: %s
Expected agent UUID: %s
Goal: %s
Knowledge cache: %s
Execution gate: %s
Cycle budget: %d total across attempts; %d used before this attempt; %d remain after this baseline.
Stages: %s
Baseline cycle: %s
Baseline failure: %s
%s

Continue the loop. The full feedback, builds, and telemetry are in SQLite.
Use InspectFeedback, Payloads, ComparePayloads, TelemetryQuery, and the source
tools. Source tools accept module=%q for the payload module, a producer name
(donut, crystal_pack) to inspect or tune the shellcode generator, or a read-only
dependency root. EditSource writes only to the payload module and producer
modules; documented options and their choices in config.json cannot be removed.
Apply grounded source edits: start minimal when that removes the detection, but
change the design when the design itself is what the sandbox detects. Then call
DetectionCycle with the mechanism and one falsifiable prediction. The host records
prediction, observed result, and prediction_result with the cycle; after two
unobserved predictions for the same mechanism it blocks a third. Do not call
DetectionCycle without a source or shellcode change: the host rejects no-op cycles.

Changing the shellcode producer is a first-class move. Edit the producer module
(module="donut" or module="crystal_pack"), then call BuildShellcode with its
declared options. The produced artifact becomes the shellcode for every later
cycle; the cycle summary records its path. BuildShellcode validates options,
forces the output under the detection store, and refuses files outside the
operator payload directory. crystal_pack's runtime loader is
postex-loader/src; build.sh rebuilds those objects from the edited source
before linking the PICO, so loader edits take effect. donut rebuilds its
stubs and generator from src/ on every build.

GenerateAgent rebuilds the Go agent, not just the wrapper. agent_type may be
windows_executable or windows_dll; the result returns artifact_path without
wrapping it. Use BuildShellcode producer=donut with input=artifact_path, or
producer=crystal_pack with dll=artifact_path, to choose the shellcode wrapper.
Java is required for crystal_pack. Switching from a donut EXE agent to a
crystal_pack DLL agent is a design change, not a replacement of the agent
payload: the new artifact is a freshly built agent with the same configuration.
The agent payload itself must remain: do not replace the shellcode with a
smaller blob or build a loader that does not execute it.

Use all telemetry. Defender verdicts are one input; the events table carries
ETW, ETW-TI memory operations, kernel callbacks, ntdll hooks, PEB and loaded-DLL
queries, and Defender behavior. Each row has actor_pid, target_pid, operation,
category, signal, payload_role, src/dst endpoints, protection, status, and the
top kernel stack frames. payload_role is payload, payload-child, payload-target,
payload-scan, ambient, or unknown. Treat signal='noise' and signal='baseline' as
evidence only, not as findings. Query the findings table for the deterministic
result and the payload view for the raw events, then compare payloads after
every edit.

An actionable finding is one with a source location (finding.Sources is not
empty) or a real defender verdict. A finding with no source location cannot be
fixed by editing this module; report it as a residual with evidence instead of
repeating the same hypothesis. High static findings (.rdata entropy, checksum)
and analyzer matches on the embedded shellcode are residuals unless a producer
change removes them. Do not game static checks with size-inflating encoding or
padding.

If a cycle regresses, revert before trying another hypothesis: RevertToPayload
undoes every recorded edit made after the chosen payload and restores the source
and producer state. Then call DetectionCycle to confirm.

If coverage.missing is not empty, or an analyzer reports a scan error or early
termination, name the gap and do not treat the cycle as clean. Stop when the
cycle budget is exhausted, or when no actionable high/medium finding remains and
every residual is explained with evidence. Return the final JSON object.`,
		cfg.LoopID, e.baseLoopID, e.attempt, attemptLabel(e.attempt),
		cfg.Module, cfg.ModuleDir, e.shellcode, headerOrNone(e.activeProducer), producerList, rootList,
		headerOrNone(cfg.AgentCC), headerOrNone(e.expectedAgentUUID), headerOrNone(cfg.Goal), knowledgeState,
		executionState, cfg.Iterations, e.globalUsed, max(0, cfg.Iterations-e.usedCycles()),
		strings.Join(stageNames(cfg.Stages), ", "), baselineJSON, headerOrNone(e.baselineFailure),
		carriedState, cfg.Module)
	if e.baselineFailure != "" {
		prompt += "\n\nThe baseline failed before any model feedback. Do not repeat the same build blindly: " +
			"read the failure above, query the run's build and telemetry rows, inspect the source and active " +
			"shellcode, apply a grounded edit or rebuild the shellcode, then call DetectionCycle. " +
			"A failed attempt does not consume the cycle budget."
	}
	if cfg.BuildAgent == nil {
		prompt += "\n\nAgent generation (GenerateAgent) is disabled for this run; reuse the supplied shellcode or edit and rebuild an existing producer."
	}
	if !e.verifyEnabled() {
		prompt += "\n\nC2 agent verification tools (AgentStatus, RunModule, CleanupAgent) are disabled for this run."
	}

	var (
		text     string
		answer   map[string]any
		parseErr error
	)
	maxTokens := 16384
	progress := e.progress
	stalled := 0
	canResume := func() bool {
		if e.progress != progress {
			progress = e.progress
			stalled = 0
		}
		stalled++
		if stalled > maxEvolveStalledResumes {
			e.logClass(logging.ClassWarning, "stopping after %d agent restarts without a new cycle", stalled-1)
			return false
		}
		return true
	}
	for attempt := 0; ; attempt++ {
		if prompts := e.takeOperatorPrompts(); len(prompts) > 0 {
			prompt = appendOperatorPrompts(prompt, prompts)
		}
		e.sessions.Add(1)
		sessionTimeout := cfg.SessionTimeout
		if sessionTimeout <= 0 {
			sessionTimeout = defaultSessionTimeout
		}
		idleTimeout := cfg.ToolIdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = defaultToolIdleTimeout
		}
		sessionCtx, sessionCancel := context.WithCancel(ctx)
		var sessionExpired, idleExpired atomic.Bool
		sessionTimer := time.AfterFunc(sessionTimeout, func() {
			sessionExpired.Store(true)
			sessionCancel()
		})
		e.lastToolCall.Store(time.Now().UnixNano())
		watchdogDone := make(chan struct{})
		go func() {
			tick := idleTimeout / 4
			if tick > time.Minute {
				tick = time.Minute
			}
			if tick < time.Second {
				tick = time.Second
			}
			ticker := time.NewTicker(tick)
			defer ticker.Stop()
			for {
				select {
				case <-watchdogDone:
					return
				case <-sessionCtx.Done():
					return
				case <-ticker.C:
					if e.activeTools.Load() > 0 {
						continue
					}
					last := time.Unix(0, e.lastToolCall.Load())
					if time.Since(last) >= idleTimeout {
						idleExpired.Store(true)
						sessionCancel()
						return
					}
				}
			}
		}()
		text, err = agentcore.Run(sessionCtx, agentcore.Options{
			Provider:               provider,
			SystemPrompt:           []string{system},
			Tools:                  e.tools(),
			PermissionMode:         permission.ModeDontAsk,
			Hooks:                  e.hooks(),
			WorkingDir:             cfg.ModuleDir,
			MaxTurns:               cfg.Turns,
			MaxTokens:              maxTokens,
			DisableBackgroundTasks: true,
			Compaction:             &compaction.Config{ContextWindow: 200000, MaxOutputTokens: maxTokens, KeepRecent: 8},
			OnWarn:                 func(line string) { e.logf(logging.ClassWarning, "%s", line) },
		}, prompt)
		sessionTimer.Stop()
		close(watchdogDone)
		sessionCancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if sessionExpired.Load() {
				e.logClass(logging.ClassError, "stopping the session: it exceeded the %s wall-clock limit", sessionTimeout)
				break
			}
			if idleExpired.Load() {
				if !canResume() {
					break
				}
				e.logClass(logging.ClassWarning, "session made no tool call for %s; asking for a cycle or the final JSON", idleTimeout)
				prompt = e.resumePrompt(cfg, fmt.Sprintf("the previous session made no tool call for %s; call DetectionCycle or return the final JSON now", idleTimeout))
				continue
			}
			if e.executionBlocked {
				e.logClass(logging.ClassError, "stopping the session: the baseline payload did not execute and no executing baseline exists")
				break
			}
			if !canResume() {
				return nil, fmt.Errorf("agent session failed after repeated restarts: %w", err)
			}
			if !e.recover(ctx, attempt, "agent session", err) {
				return nil, ctx.Err()
			}
			prompt = e.resumePrompt(cfg, "the previous agent session failed")
			continue
		}
		e.logClass(logging.ClassAnswer, "%s", clip(text, 8000))
		answer, parseErr = parseAnalystAnswer(text)
		if parseErr == nil {
			e.lastAnswer = answer
			if e.usedCycles() < cfg.Iterations && e.needsMoreWork(ctx) {
				if !canResume() {
					break
				}
				e.logClass(logging.ClassWarning, "agent stopped with work remaining; resuming")
				prompt = e.resumePrompt(cfg, "real verdicts or actionable high/medium findings remain")
				continue
			}
			break
		}
		if e.usedCycles() < cfg.Iterations && !e.executionBlocked {
			if !canResume() {
				break
			}
			e.logClass(logging.ClassWarning, "agent stopped without the required JSON; resuming")
			prompt = e.resumePrompt(cfg, "the previous turn ended without the final JSON object")
			continue
		}
		break
	}
	if answer == nil {
		summary := strings.TrimSpace(text)
		if summary == "" {
			summary = "the agent stopped without returning a final summary"
		}
		answer = map[string]any{
			"summary":     clip(summary, 4000),
			"edits":       []any{},
			"residual":    []string{"the agent did not return the required JSON object"},
			"parse_error": "agent did not return JSON before the iteration limit",
		}
	}
	answer["loop_id"] = cfg.LoopID
	answer["base_loop_id"] = e.baseLoopID
	answer["attempt"] = e.attempt
	answer["global_cycles"] = e.usedCycles()
	answer["expected_agent_uuid"] = e.expectedAgentUUID
	e.sourceTreeHash = e.computeSourceTreeHash()
	if e.sourceTreeHash != "" {
		answer["source_tree_hash"] = e.sourceTreeHash
	}
	lastGood := e.lastExecuting
	if lastGood == nil {
		lastGood = e.priorLastGood
	}
	if lastGood != nil {
		answer["last_executing_payload"] = lastGood.PayloadKey
	}
	answer["cycles"] = e.cycles
	if cfg.FinalVerify != nil {
		if e.expectedAgentUUID == "" {
			answer["payload_verified"] = false
			answer["payload_verification_error"] = "no expected agent UUID"
		} else {
			output, verifyErr := cfg.FinalVerify(ctx, e.expectedAgentUUID)
			answer["payload_verified"] = verifyErr == nil && strings.TrimSpace(output) != ""
			if answer["payload_verified"] == true {
				e.agentSeenOnline.Store(true)
			}
			answer["payload_verification_output"] = clip(output, 4000)
			if verifyErr != nil {
				answer["payload_verification_error"] = verifyErr.Error()
			}
			e.logClass(logging.ClassCycle, "final payload verification for %s: verified=%v", e.expectedAgentUUID, answer["payload_verified"])
		}
	}
	verified, _ := answer["payload_verified"].(bool)
	answer["agent_online_seen"] = e.agentSeenOnline.Load()
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, fmt.Errorf("encode loop answer: %w", err)
	}
	edits, _ := e.db.LoopEdits(ctx, cfg.LoopID)
	report := RenderLoopReport(answer, e.cycles, edits)
	reportPath, reportErr := writeLoopReport(cfg.StoreRoot, cfg.LoopID, report)
	if reportErr != nil {
		e.logClass(logging.ClassError, "write report: %v", reportErr)
	} else {
		e.logClass(logging.ClassAnswer, "final report: %s", reportPath)
	}
	if summaryPath, summaryErr := writeLoopSummary(cfg.StoreRoot, cfg.LoopID, RenderLoopSummary(answer, e.cycles, edits)); summaryErr != nil {
		e.logClass(logging.ClassError, "write executive summary: %v", summaryErr)
	} else {
		e.logClass(logging.ClassAnswer, "executive summary: %s", summaryPath)
	}
	e.logClass(logging.ClassReport, "%s", report)
	if _, err := e.db.db.ExecContext(ctx, `
		INSERT INTO loop_results(loop_id, answer, report, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(loop_id) DO UPDATE SET answer = excluded.answer, report = excluded.report, created_at = excluded.created_at`,
		cfg.LoopID, string(encoded), report, time.Now().UTC().UnixMilli()); err != nil {
		return nil, fmt.Errorf("save loop result: %w", err)
	}
	completed = true
	return &EvolveResult{
		LoopID: cfg.LoopID, BaseLoopID: e.baseLoopID, Attempt: e.attempt,
		GlobalCycles: e.usedCycles(), SourceTreeHash: e.sourceTreeHash,
		Answer: encoded, Report: report, Cycles: e.cycles, Last: e.last,
		PayloadVerified: verified, AgentOnlineSeen: e.agentSeenOnline.Load(),
		ExpectedAgentUUID: e.expectedAgentUUID,
	}, nil
}

func normalizeEvolveConfig(cfg *EvolveConfig) error {
	cfg.Module = strings.ToLower(strings.TrimSpace(cfg.Module))
	if cfg.Module == "" {
		cfg.Module = "loader_windows"
	}
	if !Covered(cfg.Module) {
		return fmt.Errorf("module %q is not covered by the detection loop", cfg.Module)
	}
	// The autonomous loop passes loader_windows flags (shellcode, format, smw)
	// and requires the sandbox to execute a Windows PE. stager_linux has a
	// different flag set and no runnable dynamic stage here.
	if cfg.Module != "loader_windows" {
		return fmt.Errorf("the autonomous detection loop currently supports loader_windows only")
	}
	cfg.ModuleDir = strings.TrimSpace(cfg.ModuleDir)
	if cfg.ModuleDir == "" {
		return fmt.Errorf("module source directory is required")
	}
	if info, err := os.Stat(cfg.ModuleDir); err != nil || !info.IsDir() {
		return fmt.Errorf("module source directory %q is not readable", cfg.ModuleDir)
	}
	cfg.Shellcode = strings.TrimSpace(cfg.Shellcode)
	if cfg.Shellcode == "" {
		return fmt.Errorf("shellcode path is required")
	}
	if info, err := os.Stat(cfg.Shellcode); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("shellcode %q is not readable", cfg.Shellcode)
	}
	if cfg.StoreRoot == "" {
		return fmt.Errorf("detection store root is required")
	}
	if cfg.LoopID == "" {
		cfg.LoopID = "loop-" + time.Now().UTC().Format("20060102-150405")
	}
	if cfg.Format == "" {
		cfg.Format = "exe"
	}
	// An empty inject or process flag means "use the module's own default", so
	// a source edit to that default is testable without the harness overriding
	// it on every build.
	if cfg.SMW == "" {
		cfg.SMW = "on"
	}
	producers := make(map[string]string, len(cfg.ProducerDirs))
	for name, dir := range cfg.ProducerDirs {
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "donut", "crystal_pack":
		default:
			return fmt.Errorf("producer %q is not supported; use donut or crystal_pack", name)
		}
		dir = strings.TrimSpace(dir)
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return fmt.Errorf("producer %s directory %q is not readable", name, dir)
		}
		producers[name] = dir
	}
	cfg.AgentType = strings.ToLower(strings.TrimSpace(cfg.AgentType))
	if cfg.AgentType == "" || cfg.AgentType == "auto" {
		cfg.AgentType = "windows_executable"
	}
	if cfg.AgentType != "windows_executable" && cfg.AgentType != "windows_dll" {
		return fmt.Errorf("agent type must be windows_executable or windows_dll")
	}
	cfg.AgentArch = strings.ToLower(strings.TrimSpace(cfg.AgentArch))
	if cfg.AgentArch == "" {
		cfg.AgentArch = "amd64"
	}
	cfg.ProducerDirs = producers
	roots := make([]string, 0, len(cfg.ReadRoots))
	for _, dir := range cfg.ReadRoots {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return fmt.Errorf("read root %q is not a directory", dir)
		}
		roots = append(roots, dir)
	}
	if len(roots) > 8 {
		return fmt.Errorf("at most 8 read roots are supported")
	}
	cfg.ReadRoots = roots
	if len(cfg.Stages) == 0 {
		cfg.Stages = []string{"static", "dynamic"}
	}
	static, dynamic, edr, err := parseEvolveStages(cfg.Stages)
	if err != nil {
		return err
	}
	if !dynamic && !edr {
		return fmt.Errorf("the autonomous loop requires the dynamic or edr stage for per-payload telemetry")
	}
	_ = static
	if cfg.Iterations <= 0 {
		cfg.Iterations = defaultEvolveIterations
	}
	if cfg.Iterations > maxEvolveIterations {
		return fmt.Errorf("iterations must be at most %d", maxEvolveIterations)
	}
	if cfg.Turns <= 0 {
		cfg.Turns = defaultEvolveTurns
	}
	if cfg.Turns > maxEvolveTurns {
		return fmt.Errorf("turns must be at most %d", maxEvolveTurns)
	}
	return nil
}

// stageSet normalizes stage names once for parsing, prompting, and the
// dynamic gate.
func stageSet(stages []string) (map[string]bool, error) {
	set := make(map[string]bool, 3)
	for _, stage := range stages {
		name := strings.ToLower(strings.TrimSpace(stage))
		switch name {
		case "":
		case "static", "dynamic", "edr":
			set[name] = true
		default:
			return nil, fmt.Errorf("unknown stage %q; use static, dynamic, or edr", stage)
		}
	}
	return set, nil
}

func parseEvolveStages(stages []string) (static, dynamic, edr bool, err error) {
	set, err := stageSet(stages)
	if err != nil {
		return false, false, false, err
	}
	return set["static"], set["dynamic"], set["edr"], nil
}

type cycleSummary struct {
	LoopID           string          `json:"loop_id"`
	Iteration        int             `json:"iteration"`
	Attempt          int             `json:"attempt,omitempty"`
	GlobalIteration  int             `json:"global_iteration,omitempty"`
	PayloadKey       string          `json:"payload_key"`
	PayloadTable     string          `json:"payload_table"`
	RunID            string          `json:"run_id"`
	SHA256           string          `json:"sha256"`
	Score            float64         `json:"score"`
	Level            string          `json:"level,omitempty"`
	Findings         int             `json:"findings"`
	Verdicts         []string        `json:"verdicts,omitempty"`
	TraceID          int64           `json:"trace_id,omitempty"`
	Events           int             `json:"telemetry_events"`
	Telemetry        *TelemetryStats `json:"telemetry,omitempty"`
	SourceEdits      int             `json:"source_edits"`
	TopFindings      []string        `json:"top_findings,omitempty"`
	BuildTail        []string        `json:"build_tail,omitempty"`
	Edits            []EditRecord    `json:"edits,omitempty"`
	Shellcode        string          `json:"shellcode,omitempty"`
	Producer         string          `json:"producer,omitempty"`
	Mechanism        string          `json:"mechanism,omitempty"`
	Prediction       string          `json:"prediction,omitempty"`
	PredictionResult string          `json:"prediction_result,omitempty"`
	Observed         string          `json:"observed,omitempty"`
	Stages           []string        `json:"stages,omitempty"`
	Note             string          `json:"note,omitempty"`
	Executed         bool            `json:"executed"`
	Execution        string          `json:"execution,omitempty"`
	AgentOnline      *bool           `json:"agent_online,omitempty"`
	NetworkEvents    int             `json:"network_events,omitempty"`
	SourceTreeHash   string          `json:"source_tree_hash,omitempty"`
	Knowledge        []KnowledgeHit  `json:"knowledge,omitempty"`
	KBRefs           []string        `json:"kb_refs,omitempty"`
}

func ensurePayloadPreserved(shellcode string, artifact Artifact) error {
	info, err := os.Stat(shellcode)
	if err != nil {
		return fmt.Errorf("active shellcode %q: %w", shellcode, err)
	}
	if info.Size() < minAgentShellcodeBytes {
		return fmt.Errorf("active shellcode is only %d bytes; a real agent payload is larger", info.Size())
	}
	if artifact.Size < info.Size()/minArtifactShellcodeRatio {
		return fmt.Errorf("artifact is %d bytes but the active shellcode is %d bytes; the build removed the agent payload",
			artifact.Size, info.Size())
	}
	return nil
}

// runDiagnostics collects the stage errors, sandbox notes, and trace identity
// that explain why a detection run was rejected or unattributed.
func runDiagnostics(run Run) string {
	var parts []string
	for _, stage := range run.Stages {
		if stage.Status == "error" || stage.Error != "" {
			parts = append(parts, stage.Tool+": "+stage.Error)
		}
	}
	if len(run.Notes) > 0 {
		parts = append(parts, "notes="+strings.Join(run.Notes, "; "))
	}
	if run.Telemetry != nil {
		parts = append(parts, fmt.Sprintf("trace=%d events=%d attribution=%s",
			run.Telemetry.TraceID, run.Telemetry.Events, headerOrNone(run.Telemetry.Attribution)))
	}
	if len(parts) == 0 {
		return "no stage error was reported"
	}
	return clipUTF8(sanitizeLine(strings.Join(parts, "; ")), 4000)
}

func (e *evolver) runCycle(ctx context.Context, note, mechanism, prediction string) (Cycle, error) {
	if e.usedCycles() >= e.cfg.Iterations {
		return Cycle{}, fmt.Errorf("%w: %d of %d cycles used", ErrCycleBudgetExhausted, e.usedCycles(), e.cfg.Iterations)
	}
	timeout := e.cfg.CycleTimeout
	if timeout <= 0 {
		timeout = defaultCycleTimeout
	}
	cycleCtx, cancelCycle := context.WithTimeout(ctx, timeout)
	defer cancelCycle()
	iteration := e.iter + 1

	if _, err := e.waitSandbox(cycleCtx); err != nil {
		return Cycle{}, err
	}
	if e.dynamicEnabled() {
		// TOFU pins the first key per UUID. The host rotates the agent before
		// reusing a shellcode instead of letting the C2 reject the check-in.
		if err := e.ensureFreshAgent(cycleCtx); err != nil {
			return Cycle{}, err
		}
	}

	shellcode := e.activeShellcode()
	flags := map[string]string{
		"shellcode": shellcode,
		"format":    e.cfg.Format,
		"arch":      "x64",
		"smw":       e.cfg.SMW,
	}
	if e.cfg.Inject != "" {
		flags["inject"] = e.cfg.Inject
	}
	if e.cfg.Process != "" {
		flags["process"] = e.cfg.Process
	}
	e.logClass(logging.ClassCycle, "cycle %d (attempt %d, global %d): building %s (shellcode %s)",
		iteration, e.attempt, e.globalUsed+iteration, e.cfg.Module, shellcode)
	build := e.cfg.Build
	if build == nil {
		build = func(dir string, values map[string]string) (string, error) {
			return modules.BuildLocalModuleAt(dir, e.cfg.Module, values)
		}
	}
	buildLog, buildErr := build(e.cfg.ModuleDir, flags)
	if len(buildLog) > maxEvolveBuildLog {
		buildLog = buildLog[:maxEvolveBuildLog] + "\n[build log truncated]\n"
	}
	e.logClass(logging.ClassBuild, "%s", buildLog)
	if buildErr != nil {
		return Cycle{}, fmt.Errorf("build %s: %w\n%s", e.cfg.Module, buildErr,
			clipUTF8(strings.Join(lastLines(buildLog, 20), "\n"), 8000))
	}
	payloads := ParseGeneratedPayloads(buildLog)
	if len(payloads) == 0 {
		return Cycle{}, fmt.Errorf("build did not report a generated payload")
	}
	artifactPath := payloads[len(payloads)-1].Path
	artifact, err := InspectArtifact(artifactPath)
	if err != nil {
		return Cycle{}, err
	}
	if strings.EqualFold(e.cfg.Module, "loader_windows") {
		if err := ensurePayloadPreserved(shellcode, artifact); err != nil {
			return Cycle{}, err
		}
	}
	if err := e.loop.Store.RecordArtifact(e.cfg.Module, artifact); err != nil {
		return Cycle{}, err
	}
	plan, err := e.loop.CreatePlan(cycleCtx, Request{
		Module: e.cfg.Module, ModuleDir: e.cfg.ModuleDir,
		ArtifactPath: artifact.Path,
	})
	if err != nil {
		return Cycle{}, err
	}
	static, dynamic, edr, err := parseEvolveStages(e.cfg.Stages)
	if err != nil {
		return Cycle{}, err
	}
	parentKey := ""
	if e.last != nil {
		parentKey = e.last.PayloadKey
	}
	if dynamic || edr {
		// Record the attempt before detonation: even a failed run has spent
		// this agent identity, so the next cycle must rotate it.
		e.markActiveAgentUsed()
	}
	// Watch the C2 while the payload runs. A sandbox beacon can check in and
	// die before the post-run AgentStatus poll; seeing it once is proof that
	// the payload executed and must not be downgraded to offline afterwards.
	watchCtx, stopWatch := context.WithCancel(cycleCtx)
	seenOnline := e.watchAgentOnline(watchCtx, e.expectedAgentUUID)
	runCtx, cancel := context.WithTimeout(cycleCtx, 12*time.Minute)
	run, runErr := e.loop.RunPlan(runCtx, plan, RunOptions{
		Static: static, Dynamic: dynamic, EDR: edr, ApproveExecution: true,
		Timeout: 10 * time.Minute, ParentKey: parentKey,
	})
	cancel()
	stopWatch()
	if runErr != nil {
		return Cycle{}, fmt.Errorf("detection run %s: %w (%s)", headerOrNone(run.ID), runErr, runDiagnostics(run))
	}
	if run.Telemetry == nil {
		return Cycle{}, fmt.Errorf("detection run %s produced no telemetry: %s", headerOrNone(run.ID), runDiagnostics(run))
	}
	// An unattributed trace is still usable evidence: the model sees the
	// attribution finding and the run notes, and can query the stored events.
	// Re-running the same payload without model feedback only repeats the
	// failure, so the trace is kept and reported instead of retried here.
	if run.Telemetry.Attribution == "unknown" {
		e.logClass(logging.ClassWarning,
			"run %s has no payload PEB; keeping trace %d (%d events) for the model",
			headerOrNone(run.ID), run.Telemetry.TraceID, run.Telemetry.Events)
	}
	feedback := BuildFeedback(run)
	if (dynamic || edr) && !run.Executed {
		return Cycle{}, fmt.Errorf("dynamic or EDR stages were selected but the sandbox did not execute the artifact: %s", runDiagnostics(run))
	}
	traceID := int64(0)
	if run.Telemetry != nil {
		traceID = run.Telemetry.TraceID
	}
	execution, online, networkEvents := e.checkExecution(cycleCtx, traceID, dynamic || edr, seenOnline)
	if err := e.linkEdits(cycleCtx, iteration, run.Telemetry.PayloadID); err != nil {
		e.logClass(logging.ClassError, "link edits: %v", err)
	}
	e.iter = iteration
	summary := summarizeCycle(e.cfg.LoopID, iteration, run, feedback, buildLog, note, mechanism, shellcode, e.activeProducer, execution, online, networkEvents)
	summary.Attempt = e.attempt
	summary.GlobalIteration = e.globalUsed + iteration
	summary.Prediction = clip(prediction, 500)
	summary.Stages = stageNames(e.cfg.Stages)
	summary.Observed = observedFindings(feedback)
	summary.PredictionResult = evaluatePrediction(prediction, feedback)
	e.cyclesDone.Store(int64(e.globalUsed + iteration))
	e.lastExecution.Store(summary.Execution)
	e.lastAgent.Store(e.expectedAgentUUID)
	e.sourceTreeHash = e.computeSourceTreeHash()
	summary.SourceTreeHash = e.sourceTreeHash
	if edits, err := e.db.LoopEdits(cycleCtx, e.cfg.LoopID); err != nil {
		e.logClass(logging.ClassError, "read edits for cycle summary: %v", err)
	} else {
		for _, edit := range edits {
			if edit.Iteration != iteration {
				continue
			}
			if len(summary.Edits) >= 24 {
				break
			}
			summary.Edits = append(summary.Edits, EditRecord{
				Module: edit.Module, File: edit.File, Reason: sanitizeLine(edit.Reason),
			})
		}
	}
	e.attachKnowledge(cycleCtx, &summary, feedback)
	summaryJSON, _ := json.Marshal(summary)
	cycle := Cycle{
		LoopID: e.cfg.LoopID, Iteration: iteration, Attempt: e.attempt, GlobalIteration: e.globalUsed + iteration,
		PayloadID:  run.Telemetry.PayloadID,
		PayloadKey: run.Telemetry.PayloadKey, RunID: run.ID, Score: feedback.Score,
		Level: feedback.Level, Findings: len(feedback.Findings),
		Verdicts: len(summary.Verdicts), TraceID: run.Telemetry.TraceID,
		Executed: summary.Executed, Execution: summary.Execution,
		AgentOnline: summary.AgentOnline, NetworkEvents: summary.NetworkEvents,
		Summary: string(summaryJSON), CreatedAt: time.Now().UTC(),
	}
	if _, err := e.db.SaveCycle(cycleCtx, cycle); err != nil {
		return Cycle{}, err
	}
	if body, err := json.Marshal(feedback); err == nil {
		if err := e.db.SaveFeedback(cycleCtx, FeedbackRecord{
			LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: run.Telemetry.PayloadID,
			RunID: run.ID, Body: body,
		}); err != nil {
			e.logClass(logging.ClassError, "save feedback: %v", err)
		}
	}
	if err := e.db.SaveBuild(cycleCtx, BuildRecord{
		LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: run.Telemetry.PayloadID,
		Artifact: artifact.Path, SHA256: artifact.SHA256, Log: buildLog,
	}); err != nil {
		e.logClass(logging.ClassError, "save build: %v", err)
	}
	e.baselineFailure = ""
	e.last = &cycle
	e.cycles = append(e.cycles, cycle)
	e.logClass(logging.ClassCycle, "cycle %d: payload=%s sha=%s score=%.2f verdicts=%v findings=%d execution=%s",
		iteration, cycle.PayloadKey, shortSHA(artifact.SHA256), cycle.Score, summary.Verdicts, cycle.Findings, summary.Execution)
	e.applyExecutionGate(cycleCtx, &cycle, summary)
	return cycle, nil
}

func summarizeCycle(loopID string, iteration int, run Run, feedback Feedback, buildLog, note, mechanism, shellcode, producer, execution string, online *bool, networkEvents int) cycleSummary {
	summary := cycleSummary{
		LoopID: loopID, Iteration: iteration, RunID: run.ID,
		Mechanism: mechanism,
		SHA256:    run.Plan.Artifact.SHA256, Score: feedback.Score, Level: sanitizeLine(feedback.Level),
		Findings: len(feedback.Findings), SourceEdits: len(feedback.SourceEdits),
		Shellcode: shellcode, Producer: producer, Note: note,
		Executed: execution == executionVerified, Execution: execution,
		AgentOnline: online, NetworkEvents: networkEvents,
	}
	if run.Telemetry != nil {
		summary.PayloadKey = run.Telemetry.PayloadKey
		summary.PayloadTable = run.Telemetry.PayloadTable
		summary.TraceID = run.Telemetry.TraceID
		summary.Events = run.Telemetry.Events
		summary.Telemetry = run.Telemetry.Stats
		if summary.Telemetry == nil {
			summary.Telemetry = &TelemetryStats{
				TraceID: run.Telemetry.TraceID, Events: run.Telemetry.Events,
				Findings: len(run.Telemetry.Findings), Coverage: run.Telemetry.Coverage,
			}
		}
		for _, finding := range run.Telemetry.Findings {
			if finding.Rule == "defender/verdict" {
				summary.Verdicts = appendUnique(summary.Verdicts, sanitizeLine(finding.Indicator))
				if len(summary.Verdicts) >= 8 {
					break
				}
			}
		}
	}
	for _, finding := range feedback.Findings {
		summary.TopFindings = append(summary.TopFindings,
			clipUTF8(fmt.Sprintf("%s %s %s", sanitizeLine(finding.Severity), sanitizeLine(finding.Rule),
				sanitizeLine(finding.Indicator)), 500))
		if len(summary.TopFindings) >= 8 {
			break
		}
	}
	lines := strings.Split(strings.TrimSpace(buildLog), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	for _, line := range lines {
		summary.BuildTail = append(summary.BuildTail, clipUTF8(line, 500))
	}
	return summary
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// shortPayloadKey abbreviates a payload key for logs and reports.
func shortPayloadKey(key string) string {
	return shortSHA(strings.TrimPrefix(strings.TrimSpace(key), "sha256:"))
}

// watchAgentOnline polls the C2 while one payload runs and latches the first
// successful check-in. The returned flag stays set after the beacon dies.
func (e *evolver) watchAgentOnline(ctx context.Context, uuid string) *atomic.Bool {
	seen := &atomic.Bool{}
	uuid = strings.TrimSpace(uuid)
	if e.cfg.Verify == nil || uuid == "" {
		return seen
	}
	go func() {
		for {
			status, err := e.cfg.Verify.AgentStatus(ctx, uuid)
			if err == nil && status != nil && status.Online {
				seen.Store(true)
				e.agentSeenOnline.Store(true)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return seen
}

// checkExecution verifies that a dynamic payload reached the agent runtime. It
// returns the recorded state, the C2 online flag when it was checked, and the
// trace's network event count as corroborating evidence.
func (e *evolver) checkExecution(ctx context.Context, traceID int64, dynamic bool, seenOnline *atomic.Bool) (string, *bool, int) {
	network := 0
	if e.db != nil && traceID != 0 {
		if count, err := e.db.NetworkEventCount(ctx, traceID); err == nil {
			network = count
		} else {
			e.logClass(logging.ClassWarning, "count network events for trace %d: %v", traceID, err)
		}
	}
	if !dynamic {
		return executionStatic, nil, network
	}
	if e.cfg.Verify == nil || strings.TrimSpace(e.expectedAgentUUID) == "" {
		return executionUnverified, nil, network
	}
	if seenOnline != nil && seenOnline.Load() {
		online := true
		e.agentSeenOnline.Store(true)
		return executionVerified, &online, network
	}
	timeout := e.executionCheckTimeout
	if timeout <= 0 {
		timeout = PayloadVerifyTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		status, err := e.cfg.Verify.AgentStatus(ctx, e.expectedAgentUUID)
		if err != nil {
			// A transient C2 error is not proof that the payload failed to run.
			e.logClass(logging.ClassWarning, "agent status for %s: %v", e.expectedAgentUUID, err)
			return executionUnverified, nil, network
		}
		if status != nil && status.Online {
			online := true
			e.agentSeenOnline.Store(true)
			return executionVerified, &online, network
		}
		if !time.Now().Before(deadline) {
			break
		}
		wait := time.Second
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return executionUnverified, nil, network
		case <-time.After(wait):
		}
	}
	online := false
	return executionOffline, &online, network
}

// applyExecutionGate counts only comparable cycles as progress and rolls a
// non-executing cycle back to the last payload that actually checked in.
func (e *evolver) applyExecutionGate(ctx context.Context, cycle *Cycle, summary cycleSummary) {
	switch summary.Execution {
	case executionVerified:
		e.lastExecuting = cycle
		e.progress++
	case executionStatic, executionUnverified:
		e.progress++
	case executionOffline:
		if e.lastExecuting == nil {
			e.executionBlocked = true
			e.logClass(logging.ClassError, "cycle %d did not execute and no executing baseline exists; stopping further detection cycles", cycle.Iteration)
			return
		}
		e.logClass(logging.ClassWarning, "cycle %d did not execute (agent %s offline); restoring payload %s",
			cycle.Iteration, headerOrNone(e.expectedAgentUUID),
			shortPayloadKey(e.lastExecuting.PayloadKey))
		e.restoreExecutingState(ctx)
	}
}

// restoreExecutingState rolls the editable source and active shellcode back to
// the last payload whose agent checked in.
func (e *evolver) restoreExecutingState(ctx context.Context) {
	baseline := e.lastExecuting
	if baseline == nil {
		e.executionBlocked = true
		return
	}
	if _, err := e.revertCycleEdits(ctx, e.lastPayloadID(), baseline.PayloadKey); err != nil {
		e.logClass(logging.ClassWarning, "restore %s source: %v",
			shortPayloadKey(baseline.PayloadKey), err)
	}
	var summary cycleSummary
	if err := json.Unmarshal([]byte(baseline.Summary), &summary); err != nil {
		return
	}
	path := strings.TrimSpace(summary.Shellcode)
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		e.logClass(logging.ClassWarning, "restore shellcode %s: %v", path, err)
		return
	}
	if !info.Mode().IsRegular() {
		e.logClass(logging.ClassWarning, "restore shellcode %s: not a regular file", path)
		return
	}
	e.shellcode = path
	e.activeProducer = summary.Producer
	e.logClass(logging.ClassEdit, "restored shellcode %s (producer %s)", path, headerOrNone(summary.Producer))
}

func (e *evolver) linkEdits(ctx context.Context, iteration int, payloadID int64) error {
	_, err := e.db.db.ExecContext(ctx, `
		UPDATE loop_edits SET next_payload_id = ?
		WHERE loop_id = ? AND iteration = ? AND next_payload_id IS NULL`,
		payloadID, e.cfg.LoopID, iteration)
	return err
}

func writeLoopReport(storeRoot, loopID, report string) (string, error) {
	return writeLoopText(storeRoot, loopID, report)
}

func writeLoopSummary(storeRoot, loopID, summary string) (string, error) {
	return writeLoopText(storeRoot, loopID+"-summary", summary)
}

func writeLoopText(storeRoot, name, text string) (string, error) {
	if strings.TrimSpace(storeRoot) == "" {
		return "", fmt.Errorf("store root is empty")
	}
	dir := filepath.Join(storeRoot, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name = sanitizeName(name)
	if name == "" {
		name = "loop"
	}
	path := filepath.Join(dir, name+".md")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (e *evolver) resumePrompt(cfg EvolveConfig, reason string) string {
	latest, _ := json.Marshal(e.last)
	return fmt.Sprintf(`Resume the detection loop.
Loop ID: %s
Reason: %s
Latest cycle: %s

Dossier (already established; do not re-derive it):
%s
%s
%s
Full feedback, builds, and telemetry are in SQLite. Continue from the current
source state: inspect only what the dossier does not answer, apply any remaining
source edit, and call DetectionCycle with the mechanism under test. The dossier
records the mechanism and edit reasons for recent cycles; do not repeat a
hypothesis it lists as tried. If those cycles refined the same mechanism, choose
a different one or record the concrete constraint that rules the alternatives
out. Return the required JSON object when the loop is complete.`,
		cfg.LoopID, reason, latest, e.dossier(), e.executionHint(), e.directionHint())
}

// executionHint makes a non-executing payload the first thing a resumed session
// sees, because its analyzer score is not evidence about evasion.
func (e *evolver) executionHint() string {
	if e.baselineFailure != "" {
		return "Baseline failure: " + e.baselineFailure +
			". Diagnose it before another cycle; a failed attempt does not consume the cycle budget."
	}
	if e.executionBlocked {
		return "Execution gate: no dynamic payload has checked in. Do not run more cycles; return the final JSON with the execution failure."
	}
	if e.last != nil && e.last.Execution == executionOffline && e.lastExecuting != nil {
		return fmt.Sprintf("Execution gate: the last cycle did not execute. The host restored payload %s; fix why the generated agent never checked in before changing detection code.",
			shortPayloadKey(e.lastExecuting.PayloadKey))
	}
	return "Execution gate: the host checks the generated agent after every dynamic cycle and records execution=verified, offline, or unverified."
}

// directionHint calls out a repeated mechanism so a resumed session does not
// continue polishing the same loading path for another cycle.
func (e *evolver) directionHint() string {
	cycles := e.recentCycles(2)
	if len(cycles) < 2 {
		return ""
	}
	var previous, last cycleSummary
	if json.Unmarshal([]byte(cycles[len(cycles)-2].Summary), &previous) != nil ||
		json.Unmarshal([]byte(cycles[len(cycles)-1].Summary), &last) != nil {
		return ""
	}
	if previous.Mechanism == "" || previous.Mechanism != last.Mechanism {
		return ""
	}
	return fmt.Sprintf("The last two cycles both used mechanism %q. Do not spend another cycle on the same mechanism unless you are changing a different component of it; test a different mechanism or record the concrete constraint that rules the alternatives out.", last.Mechanism)
}

// dossier is the compact state carried into a fresh agent session. It spans
// attempts so a restart sees the logical loop's history, not just its own
// baseline.
func (e *evolver) dossier() string {
	if hash := e.computeSourceTreeHash(); hash != "" {
		e.sourceTreeHash = hash
	}
	var b strings.Builder
	fmt.Fprintf(&b, "- logical loop: %s; attempt %d (%s)\n", e.baseLoopID, e.attempt, attemptLabel(e.attempt))
	fmt.Fprintf(&b, "- cycles used: %d of %d global; %d in this attempt\n", e.usedCycles(), e.cfg.Iterations, e.iter)
	if e.baselineFailure != "" {
		fmt.Fprintf(&b, "- baseline failure: %s\n", clip(e.baselineFailure, 600))
	}
	if e.globalUsed > 0 {
		fmt.Fprintf(&b, "- prior attempts used %d cycles before this attempt\n", e.globalUsed)
	}
	if e.sourceTreeHash != "" {
		fmt.Fprintf(&b, "- source tree: %s\n", e.sourceTreeHash)
	}
	priorHash := answerString(e.priorAnswer, "source_tree_hash")
	if priorHash == "" {
		priorHash = e.priorSourceHash
	}
	if priorHash != "" && priorHash != e.sourceTreeHash {
		fmt.Fprintf(&b, "- prior attempt source tree: %s\n", priorHash)
	}
	if e.priorLastGood != nil {
		fmt.Fprintf(&b, "- last executing payload from a prior attempt: %s\n", lastGoodRef(e.priorLastGood))
	}
	if len(e.priorAnswer) > 0 {
		if summary := answerString(e.priorAnswer, "summary"); summary != "" {
			fmt.Fprintf(&b, "- prior attempt summary: %s\n", clip(sanitizeLine(summary), 600))
		}
		if residual, ok := e.priorAnswer["residual"]; ok {
			fmt.Fprintf(&b, "- prior attempt residuals: %s\n", clip(fmt.Sprintf("%v", residual), 600))
		}
		if verifyErr := answerString(e.priorAnswer, "payload_verification_error"); verifyErr != "" {
			fmt.Fprintf(&b, "- prior attempt verification error: %s\n", clip(sanitizeLine(verifyErr), 400))
		}
	}
	for _, line := range e.pendingEditLines(6) {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	fmt.Fprintf(&b, "- active shellcode: %s\n", e.shellcode)
	fmt.Fprintf(&b, "- active shellcode producer: %s\n", headerOrNone(e.activeProducer))
	if names := e.producerNames(); len(names) > 0 {
		fmt.Fprintf(&b, "- producers: %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(&b, "- editable roots: %s\n", e.roots.describe())
	for _, cycle := range e.recentCycles(8) {
		var summary cycleSummary
		_ = json.Unmarshal([]byte(cycle.Summary), &summary)
		files := make([]string, 0, len(summary.Edits))
		for _, edit := range summary.Edits {
			files = append(files, edit.Module+"/"+edit.File)
		}
		attempt := cycle.Attempt
		if attempt < 1 {
			attempt = logicalAttempt(e.baseLoopID, cycle.LoopID)
		}
		global := cycle.GlobalIteration
		if global < 1 {
			global = e.globalUsed + cycle.Iteration
		}
		fmt.Fprintf(&b, "- attempt %d cycle %d (global %d): mechanism=%s score=%.2f level=%s findings=%d verdicts=%d execution=%s network=%d shellcode=%s files=%s\n",
			attempt, cycle.Iteration, global, headerOrNone(summary.Mechanism), cycle.Score, cycle.Level,
			cycle.Findings, cycle.Verdicts, headerOrNone(summary.Execution), summary.NetworkEvents,
			headerOrNone(filepath.Base(summary.Shellcode)), joinOrNone(files))
		if strings.TrimSpace(summary.Note) != "" {
			fmt.Fprintf(&b, "  tested: %s\n", clip(sanitizeLine(summary.Note), 240))
		}
		if strings.TrimSpace(summary.Prediction) != "" {
			fmt.Fprintf(&b, "  predicted: %s -> %s\n", clip(sanitizeLine(summary.Prediction), 240), headerOrNone(summary.PredictionResult))
		}
		for i, edit := range summary.Edits {
			if i >= 2 {
				break
			}
			fmt.Fprintf(&b, "  edit: %s/%s — %s\n", edit.Module, edit.File, clip(sanitizeLine(edit.Reason), 220))
		}
		if len(summary.TopFindings) > 0 {
			fmt.Fprintf(&b, "  top: %s\n", strings.Join(limitStrings(summary.TopFindings, 4), " | "))
		}
		if len(summary.KBRefs) > 0 {
			fmt.Fprintf(&b, "  kb: %s\n", strings.Join(limitStrings(summary.KBRefs, 4), ", "))
		}
	}
	if len(e.lastAnswer) > 0 {
		if mechanism, ok := e.lastAnswer["mechanism"]; ok {
			fmt.Fprintf(&b, "- last mechanism: %s\n", clip(fmt.Sprintf("%v", mechanism), 80))
		}
		if summary, ok := e.lastAnswer["summary"]; ok {
			fmt.Fprintf(&b, "- last answer summary: %s\n", clip(fmt.Sprintf("%v", summary), 600))
		}
		if residual, ok := e.lastAnswer["residual"]; ok {
			fmt.Fprintf(&b, "- decided residuals: %s\n", clip(fmt.Sprintf("%v", residual), 600))
		}
	}
	return b.String()
}

func headerOrNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

func limitStrings(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

// takeOperatorPrompts drains queued instructions and logs them. The queue is
// local operator input, not sandbox telemetry, so it is safe to surface as a
// directive to the model.
func (e *evolver) takeOperatorPrompts() []string {
	if e.operatorPrompts == nil {
		return nil
	}
	prompts := e.operatorPrompts.Drain()
	for _, prompt := range prompts {
		e.logClass(logging.ClassWarning, "operator prompt: %s", prompt)
	}
	return prompts
}

func appendOperatorPrompts(prompt string, prompts []string) string {
	block := FormatOperatorPrompts(prompts)
	if block == "" {
		return prompt
	}
	return strings.TrimRight(prompt, "\n") + "\n\n" + block
}

func (e *evolver) needsMoreWork(ctx context.Context) bool {
	if e.executionBlocked {
		return false
	}
	if e.last == nil {
		return true
	}
	if e.last.Execution == executionOffline {
		return true
	}
	var body string
	if err := e.db.db.QueryRowContext(ctx, `
		SELECT body FROM loop_feedback WHERE loop_id = ? AND iteration = ?
		ORDER BY id DESC LIMIT 1`, e.last.LoopID, e.last.Iteration).Scan(&body); err != nil {
		return e.last.Verdicts > 0
	}
	var feedback Feedback
	if json.Unmarshal([]byte(body), &feedback) != nil {
		return e.last.Verdicts > 0
	}
	if e.residualCovers(feedback.Findings) {
		return false
	}
	if e.last.Verdicts > 0 {
		return true
	}
	return hasActionableFindings(feedback.Findings)
}

// residualCovers reports whether the final answer names every actionable
// finding, so the loop does not resume only to restate residuals.
func (e *evolver) residualCovers(findings []Finding) bool {
	residual := answerStrings(e.lastAnswer, "residual")
	if len(residual) == 0 {
		return false
	}
	text := strings.ToLower(strings.Join(residual, " "))
	for _, finding := range findings {
		if !actionableFinding(finding) {
			continue
		}
		indicator := strings.ToLower(strings.TrimSpace(finding.Indicator))
		rule := strings.ToLower(strings.TrimSpace(finding.Rule))
		if indicator != "" && strings.Contains(text, indicator) {
			continue
		}
		if rule != "" && strings.Contains(text, rule) {
			continue
		}
		return false
	}
	return true
}

func actionableFinding(finding Finding) bool {
	if finding.Signal == "noise" || finding.Signal == "baseline" {
		return false
	}
	if finding.Rule == "defender/verdict" {
		return true
	}
	if len(finding.Sources) == 0 {
		return false
	}
	return finding.Severity == "high" || finding.Severity == "critical" ||
		(finding.Stage == StageTelemetry && finding.Severity == "medium")
}

// hasActionableFindings reports whether another source edit could plausibly
// remove a remaining finding. Unmatched medium findings have no source
// location, so they are residuals rather than work.
func hasActionableFindings(findings []Finding) bool {
	for _, finding := range findings {
		if actionableFinding(finding) {
			return true
		}
	}
	return false
}

// --- Norma agent -----------------------------------------------------------

func (e *evolver) verifyEnabled() bool {
	return e.cfg.Verify != nil
}

func (e *evolver) allowToolHook(toolName string) hook.Result {
	switch toolName {
	case "SourceList", "SourceRead", "SourceSearch", "TelemetryQuery",
		"InspectFeedback", "Payloads", "ComparePayloads", "DetectionCycle", "EditSource",
		"BuildShellcode", "RevertToPayload", "KnowledgeSearch", "KnowledgeRead",
		"KnowledgeStats", "KnowledgeList":
		return hook.Result{}
	case "GenerateAgent":
		if e.cfg.BuildAgent != nil {
			return hook.Result{}
		}
	case "AgentStatus", "RunModule", "CleanupAgent":
		if e.verifyEnabled() {
			return hook.Result{}
		}
	}
	return hook.Result{Decision: "block", Message: "tool is not part of the detection loop"}
}

func (e *evolver) hooks() *hook.Registry {
	hooks := hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, event hook.Event) hook.Result {
		decision := e.allowToolHook(event.ToolName)
		if decision.Decision != "block" {
			e.lastToolCall.Store(time.Now().UnixNano())
			e.activeTools.Add(1)
		}
		return decision
	})
	hooks.On(hook.PostToolUse, func(_ context.Context, event hook.Event) hook.Result {
		e.lastToolCall.Store(time.Now().UnixNano())
		e.toolCalls.Add(1)
		for {
			active := e.activeTools.Load()
			if active <= 0 || e.activeTools.CompareAndSwap(active, active-1) {
				break
			}
		}
		status := "ok"
		if event.IsError {
			status = "error"
		}
		preview := clip(sanitizeLine(string(event.Result)), 300)
		if preview == "" {
			preview = "(no output)"
		}
		e.logClass(logging.ClassToolResult, "%s %s: %s", event.ToolName, status, preview)
		return hook.Result{}
	})
	return hooks
}

func (e *evolver) tools() []tool.CoreTool {
	tools := []tool.CoreTool{
		moduleListTool(e.roots),
		moduleReadTool(e.roots),
		moduleSearchTool(e.roots),
		analystTelemetryTool(e.db),
		e.detectionCycleTool(),
		e.inspectFeedbackTool(),
		e.payloadsTool(),
		e.comparePayloadsTool(),
		e.editSourceTool(),
		e.buildShellcodeTool(),
		e.revertPayloadTool(),
	}
	if e.cfg.BuildAgent != nil {
		tools = append(tools, e.generateAgentTool())
	}
	if e.verifyEnabled() {
		tools = append(tools, e.agentStatusTool(), e.runModuleTool(), e.cleanupAgentTool())
	}
	if e.knowledge != nil {
		tools = append(tools, e.knowledgeSearchTool(), e.knowledgeReadTool(), e.knowledgeStatsTool(), e.knowledgeListTool())
	}
	return tools
}

func (e *evolver) detectionCycleTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "DetectionCycle",
		Description: "Rebuild the module from its current source and detonate the artifact in the sandbox. " +
			"The full feedback, build log, and telemetry are stored in SQLite; this returns a bounded summary. " +
			"The host checks the generated agent with AgentStatus and reports execution=verified, offline, or unverified. " +
			"Call it after a source edit or shellcode build with one falsifiable prediction; a cycle with no source or " +
			"shellcode change is rejected.",
		Prompt: "Build and run one detection cycle.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mechanism": map[string]any{
					"type": "string",
					"enum": []string{
						"baseline", "self-load", "remote-apc", "remote-thread",
						"section-map", "module-stomp", "pe-image", "producer", "static-hygiene", "other",
					},
					"description": "Execution mechanism or producer under test. " +
						"Use a different value when you change the loading path; reuse it only when refining the same mechanism. " +
						"Name the concrete mechanism, not an incidental file or import change.",
				},
				"note":       map[string]any{"type": "string", "description": "What this cycle is testing."},
				"prediction": map[string]any{"type": "string", "description": "One falsifiable prediction for this cycle: the expected analyzer, event, verdict, or absence of one. The host records it with the observed result."},
			},
			"required": []string{"mechanism"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Mechanism  string `json:"mechanism"`
				Note       string `json:"note"`
				Prediction string `json:"prediction"`
			}
			_ = json.Unmarshal(raw, &args)
			if e.executionBlocked {
				return tool.Errorf("payload execution is blocked: no dynamic payload has checked in and no executing baseline exists; return the final JSON with the execution failure"), nil
			}
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf(fmt.Sprintf("iteration limit reached (%d); return the final JSON", e.cfg.Iterations)), nil
			}
			mechanism := clip(args.Mechanism, 80)
			if strings.TrimSpace(mechanism) == "" {
				mechanism = "other"
			}
			if err := e.cyclePreconditions(mechanism); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			cycle, err := e.runCycle(ctx, clip(args.Note, 500), mechanism, clip(args.Prediction, 500))
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			edits, _ := e.db.EditsForPayload(ctx, cycle.PayloadKey)
			payload, _ := e.db.PayloadByKey(ctx, cycle.PayloadKey)
			var summary any
			_ = json.Unmarshal([]byte(cycle.Summary), &summary)
			message := "full feedback and build log are in SQLite; use InspectFeedback or TelemetryQuery"
			switch cycle.Execution {
			case executionVerified:
				message = "the payload executed and its agent checked in; full feedback and build log are in SQLite"
			case executionOffline:
				if e.lastExecuting != nil {
					message = "the payload did not execute; the host restored the last executing source and shellcode. Fix agent check-in before changing detection code."
				} else {
					message = "the payload did not execute and no executing baseline exists; return the final JSON with the execution failure."
				}
			case executionUnverified:
				message = "agent verification is not configured, so execution could not be proven; full feedback and build log are in SQLite"
			}
			out := map[string]any{
				"cycle":            cycle,
				"summary":          summary,
				"payload":          payload,
				"edits":            edits,
				"iterations":       e.cfg.Iterations,
				"remaining_cycles": max(0, e.cfg.Iterations-e.usedCycles()),
				"active_shellcode": e.shellcode,
				"message":          message,
			}
			if prompts := e.takeOperatorPrompts(); len(prompts) > 0 {
				out["operator_prompts"] = prompts
			}
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) inspectFeedbackTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "InspectFeedback",
		Description: "Return the stored feedback for a payload or run: score, top findings with source " +
			"locations, pending stages, telemetry trace, and edits that produced it. Full feedback stays in SQLite.",
		Prompt: "Inspect stored detection feedback.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"run_id":      map[string]any{"type": "string"},
				"payload_key": map[string]any{"type": "string"},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				RunID      string `json:"run_id"`
				PayloadKey string `json:"payload_key"`
			}
			_ = json.Unmarshal(raw, &args)
			body, runID, payloadKey, err := e.loadFeedback(ctx, args.RunID, args.PayloadKey)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			var feedback Feedback
			if err := json.Unmarshal(body, &feedback); err != nil {
				return tool.Errorf("decode feedback"), nil
			}
			edits, _ := e.db.EditsForPayload(ctx, payloadKey)
			out := feedbackSummary(feedback, runID, payloadKey, edits)
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) payloadsTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "Payloads",
		Description: "List recent payloads with their per-payload SQLite view name, artifact hash, score, verdict count, and parent payload.",
		Prompt:      "List payloads.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer", "description": "Maximum rows, at most 100."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Limit int `json:"limit"`
			}
			_ = json.Unmarshal(raw, &args)
			payloads, err := e.db.ListPayloads(ctx, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(payloads)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) comparePayloadsTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "ComparePayloads",
		Description: "Diff two payloads' per-payload telemetry views. Returns the largest added and removed " +
			"event signatures, which shows what the source edit changed. Omit from/to to compare the current payload with its parent.",
		Prompt: "Compare payload telemetry.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"from": map[string]any{"type": "string", "description": "Previous payload key."},
				"to":   map[string]any{"type": "string", "description": "Current payload key."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				From string `json:"from"`
				To   string `json:"to"`
			}
			_ = json.Unmarshal(raw, &args)
			from, to := args.From, args.To
			if e.last != nil {
				if to == "" {
					to = e.last.PayloadKey
				}
				if from == "" {
					payload, err := e.db.PayloadByKey(ctx, to)
					if err == nil && payload.ParentID != 0 {
						payloads, _ := e.db.ListPayloads(ctx, 100)
						for _, parent := range payloads {
							if parent.ID == payload.ParentID {
								from = parent.Key
								break
							}
						}
					}
				}
			}
			if from == "" || to == "" {
				return tool.Errorf("from and to payload keys are required"), nil
			}
			diff, err := e.db.ComparePayloads(ctx, from, to)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(diff)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) editSourceTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "EditSource",
		Description: "Replace one exact string in a module source file. The old string must occur once. " +
			"module selects the payload module (default) or a producer module (donut, crystal_pack). " +
			"crystal_pack links postex-loader/src and rebuilds it on the next BuildShellcode; donut rebuilds src/. " +
			"The edit is atomic, stored in SQLite with before/after text, and takes effect on the next DetectionCycle.",
		Prompt: "Apply one source edit.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":     map[string]any{"type": "string", "description": "Writable source root: the payload module (default), donut, or crystal_pack."},
				"file":       map[string]any{"type": "string", "description": "Path relative to the module root."},
				"old_string": map[string]any{"type": "string", "description": "Exact text to replace; must occur once."},
				"new_string": map[string]any{"type": "string", "description": "Replacement text."},
				"reason":     map[string]any{"type": "string", "description": "Why this edit removes the finding."},
			},
			"required": []string{"file", "old_string", "new_string"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module    string `json:"module"`
				File      string `json:"file"`
				OldString string `json:"old_string"`
				NewString string `json:"new_string"`
				Reason    string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf("iteration limit reached; the edit could not be built or tested"), nil
			}
			root, err := e.root(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if !root.Writable {
				return tool.Errorf(fmt.Sprintf("source root %s is read-only", root.Name)), nil
			}
			result, err := e.applyEdit(ctx, root, args.File, args.OldString, args.NewString, args.Reason)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(result)
			return tool.Text(string(data)), nil
		},
	})
}

type editResult struct {
	Module  string `json:"module"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Bytes   int    `json:"bytes"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

func (e *evolver) applyEdit(ctx context.Context, root sourceRoot, file, oldText, newText, reason string) (editResult, error) {
	if oldText == "" || newText == "" {
		return editResult{}, fmt.Errorf("old_string and new_string are required")
	}
	if oldText == newText {
		return editResult{}, fmt.Errorf("old_string and new_string are identical")
	}
	if len(oldText) > 16<<10 || len(newText) > 16<<10 {
		return editResult{}, fmt.Errorf("edit text exceeds 16 KiB")
	}
	updated, err := writeSourceFile(root, file, oldText, newText)
	if err != nil {
		return editResult{}, err
	}
	payloadID := int64(0)
	if e.last != nil {
		payloadID = e.last.PayloadID
	}
	iteration := e.iter + 1
	if err := e.db.SaveEdit(ctx, EditRecord{
		LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: payloadID,
		Module: root.Name, File: file, Old: oldText, New: newText, Reason: reason,
	}); err != nil {
		if restoreErr := restoreSourceFile(updated.Path, updated.Original); restoreErr != nil {
			return editResult{}, fmt.Errorf("save edit: %w (restore %s failed: %v)", err, file, restoreErr)
		}
		return editResult{}, fmt.Errorf("save edit: %w", err)
	}
	e.logClass(logging.ClassEdit, "%s/%s:%d (%s): %s", root.Name, file, updated.Line, reason, clip(newText, 160))
	return editResult{
		Module: root.Name, File: file, Line: updated.Line, Bytes: len(updated.Updated), Reason: reason,
		Message: "edit applied; call DetectionCycle to rebuild and detonate",
	}, nil
}

// sourceWrite records one atomic source replacement and the file state it
// replaced, so a failed database record can be rolled back.
type sourceWrite struct {
	Updated  string
	Line     int
	Path     string
	Original []byte
}

// writeSourceFile replaces one exact string in a writable module file and
// rejects edits that remove a documented module or option from config.json.
func writeSourceFile(root sourceRoot, file, oldText, newText string) (sourceWrite, error) {
	if !root.Writable {
		return sourceWrite{}, fmt.Errorf("source root %s is read-only", root.Name)
	}
	path, err := analystPath(root.Dir, file)
	if err != nil {
		return sourceWrite{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sourceWrite{}, fmt.Errorf("read %s: %w", file, err)
	}
	if strings.Count(string(data), oldText) != 1 {
		return sourceWrite{}, fmt.Errorf("%s: old_string must occur exactly once", file)
	}
	index := strings.Index(string(data), oldText)
	line := strings.Count(string(data[:index]), "\n") + 1
	updated := strings.Replace(string(data), oldText, newText, 1)
	if strings.EqualFold(filepath.Base(path), "config.json") {
		if err := guardModuleConfig(string(data), updated); err != nil {
			return sourceWrite{}, err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return sourceWrite{}, fmt.Errorf("stat %s: %w", file, err)
	}
	if err := writeFileAtomic(path, []byte(updated), info.Mode().Perm()); err != nil {
		return sourceWrite{}, fmt.Errorf("replace %s: %w", file, err)
	}
	return sourceWrite{Updated: updated, Line: line, Path: path, Original: data}, nil
}

// restoreSourceFile puts back the bytes a failed edit replaced.
func restoreSourceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, info.Mode().Perm())
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".detect-edit-*")
	if err != nil {
		return fmt.Errorf("create edit file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod edit file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write edit file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync edit file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close edit file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

// guardModuleConfig keeps the documented module and option surface intact. It
// allows adding options and changing defaults, but not renaming or removing a
// module, a parameter, or one of its declared choices.
func guardModuleConfig(before, after string) error {
	type parameter struct {
		Name    string   `json:"name"`
		Choices []string `json:"choices"`
	}
	type module struct {
		Name       string      `json:"name"`
		Build      string      `json:"build"`
		Parameters []parameter `json:"parameters"`
	}
	var oldModules, newModules []module
	if err := json.Unmarshal([]byte(before), &oldModules); err != nil {
		return fmt.Errorf("config.json is not valid JSON before the edit: %w", err)
	}
	if err := json.Unmarshal([]byte(after), &newModules); err != nil {
		return fmt.Errorf("config.json is not valid JSON after the edit: %w", err)
	}
	byName := make(map[string]module, len(newModules))
	for _, mod := range newModules {
		if _, exists := byName[mod.Name]; exists {
			return fmt.Errorf("config.json would define module %q twice", mod.Name)
		}
		byName[mod.Name] = mod
	}
	for _, old := range oldModules {
		next, ok := byName[old.Name]
		if !ok {
			return fmt.Errorf("edit removes documented module %q", old.Name)
		}
		if next.Build != old.Build {
			return fmt.Errorf("edit changes the build entrypoint of module %q", old.Name)
		}
		params := make(map[string]parameter, len(next.Parameters))
		for _, param := range next.Parameters {
			params[param.Name] = param
		}
		for _, oldParam := range old.Parameters {
			param, ok := params[oldParam.Name]
			if !ok {
				return fmt.Errorf("edit removes documented option %q from module %q", oldParam.Name, old.Name)
			}
			if len(oldParam.Choices) > 0 {
				for _, choice := range oldParam.Choices {
					found := false
					for _, candidate := range param.Choices {
						if candidate == choice {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("edit removes choice %q from option %q", choice, oldParam.Name)
					}
				}
			}
		}
	}
	return nil
}

// --- feedback helpers ------------------------------------------------------

func (e *evolver) loadFeedback(ctx context.Context, runID, payloadKey string) (json.RawMessage, string, string, error) {
	var (
		body      string
		foundRun  string
		payloadID int64
	)
	query := `SELECT body, run_id, payload_id FROM loop_feedback`
	var args []any
	switch {
	case runID != "":
		query += ` WHERE run_id = ? ORDER BY id DESC LIMIT 1`
		args = append(args, runID)
	case payloadKey != "":
		id, err := payloadIDByKey(ctx, e.db.db, payloadKey)
		if err != nil {
			return nil, "", "", err
		}
		query += ` WHERE payload_id = ? ORDER BY id DESC LIMIT 1`
		args = append(args, id)
	default:
		query += ` ORDER BY id DESC LIMIT 1`
	}
	if err := e.db.db.QueryRowContext(ctx, query, args...).Scan(&body, &foundRun, &payloadID); err != nil {
		return nil, "", "", fmt.Errorf("feedback not found: %w", err)
	}
	payload, err := e.db.PayloadByKey(ctx, payloadKey)
	if payloadKey == "" && err == nil {
		payloadKey = payload.Key
	}
	return json.RawMessage(body), foundRun, payloadKey, nil
}

func feedbackSummary(feedback Feedback, runID, payloadKey string, edits []EditRecord) map[string]any {
	SanitizeFeedback(&feedback)
	out := map[string]any{
		"run_id": runID, "payload_key": payloadKey,
		"score": feedback.Score, "level": feedback.Level,
		"findings": len(feedback.Findings), "source_edits": len(feedback.SourceEdits),
	}
	if feedback.Telemetry != nil {
		telemetry := map[string]any{
			"trace_id": feedback.Telemetry.TraceID, "events": feedback.Telemetry.Events,
			"payload_table": feedback.Telemetry.PayloadTable,
			"payload_pid":   feedback.Telemetry.PayloadPID,
			"attribution":   feedback.Telemetry.Attribution,
			"coverage":      feedback.Telemetry.Coverage,
		}
		if feedback.Telemetry.Stats != nil {
			telemetry["stats"] = feedback.Telemetry.Stats
		}
		out["telemetry"] = telemetry
	}
	var findings []map[string]any
	for _, finding := range feedback.Findings {
		if len(findings) >= 15 {
			break
		}
		row := map[string]any{
			"severity":  sanitizeLine(finding.Severity),
			"rule":      sanitizeLine(finding.Rule),
			"indicator": sanitizeLine(finding.Indicator),
		}
		if finding.Detail != "" {
			row["detail"] = clipUTF8(sanitizeLine(finding.Detail), 300)
		}
		if len(finding.Sources) > 0 {
			row["sources"] = finding.Sources
		}
		findings = append(findings, row)
	}
	out["top_findings"] = findings
	if len(feedback.SourceEdits) > 10 {
		out["source_edit_list"] = feedback.SourceEdits[:10]
	} else {
		out["source_edit_list"] = feedback.SourceEdits
	}
	out["pending"] = feedback.Pending
	if len(edits) > 10 {
		edits = edits[:10]
	}
	out["edits"] = edits
	return out
}

// BuildFeedbackFromCycle is a small adapter for logging; the full feedback is
// read from SQLite when the model asks for it.
const evolveSystemPrompt = `You are an autonomous detection engineer for the emp3r0r loader.

The host has already built and detonated a baseline. Your job is to remove real
detections by editing module source, rebuilding, and re-testing.

Data policy:
- SQLite is the source of truth. Full feedback, build logs, and per-payload
  telemetry stay there. Never ask for them as raw blobs.
- Each payload has its own SQLite view named payload_<hash>. The payloads table
  maps artifact SHA-256, parent payload, view name, score, and verdict count.
- Use InspectFeedback for a bounded summary, Payloads to see build history,
  ComparePayloads to see what your edit changed, and TelemetryQuery for SQL.
- Use only the read-only SQL tool; it accepts one SELECT or WITH statement.
- The findings table holds the deterministic telemetry findings for a trace;
  the events table holds every raw event. Query trace_pk-scoped events or the
  per-payload view.
- The sandbox result bundle contains file info, static YARA/CheckPlz/Stringnalyzer, dynamic
  RedEdr/Moneta/pe-sieve/HollowsHunter/HSB/Patriot/Blender/YARA/CheckPlz,
  HolyGrail, and every EDR profile. Analyzer output is a type='analysis' event
  with the analyzer JSON in attrs; its finding rule is analyzer/<analyzer>.
  Query the findings table and these events together.
- Attribution columns matter: actor_pid performed the operation, pid is the
  subject, target_pid is the target or child, payload_role says whether the
  event belongs to the payload, a child, the payload as a target, a Defender
  scan, or ambient traffic. signal is
  signal/verdict/scan/info/unattributed/baseline/noise. unattributed means the
  capture could not identify the payload process, but the operation itself is
  high-value; treat it as evidence, not as noise.
- Categories include process, image, file, network, audit, thread, defender,
  query, module, hook, memory (ETW-TI), and analysis. ETW-TI rows carry
  operation, protection, size, bytes, status, and stack. Hook rows carry the
  intercepted Nt* API. Ambient MsMpEng events are stored but are not payload
  actions. Unattributed ETW-TI memory operations are also emitted as
  low-severity telemetry/unattributed-etwti findings; inspect their protection,
  size, and pid sequence before dismissing them.

Work loop:
1. Inspect the baseline and identify a real defender verdict or a high/medium
   telemetry finding that maps to module source. Use the findings table first,
   then the payload view for the events behind a finding. Check RedEdr and the
   type='analysis' analyzers before deciding a finding is resolved.
2. Before choosing a mechanism or editing source, consult the knowledge base
   as described under "Knowledge base" below: classify the finding, search with
   the mechanism plus the exact detector/API name, read the best document, and
   put the document_ref and the prediction it supports in the edit reason and
   the cycle note. A missing cache or a no-hit search is a valid result: state
   it and continue with telemetry and source evidence.
   Read the relevant source and trace the detection to its cause. Prefer a
   minimal, grounded EditSource call when that removes the detection. A design
   change is allowed and expected when the current design is what the sandbox
   detects: add, remove, split, merge, or replace source files and components,
   restructure data flow, change the loading or call path, and rewrite the
   implementation. Do not preserve a detected design just because it already
   exists, and do not settle for renaming, reordering, or hiding the same
   behavior. Update every default that controls the behavior, not a dead copy.
   Use multiple EditSource calls when a redesign needs them. Source tools take
   module=<name> to read a read-only dependency or a producer module.
3. The shellcode producer is part of the design. You may edit the configured
   producer modules (donut, crystal_pack) through EditSource with
   module=<producer>, then call BuildShellcode to regenerate the shellcode. The
   result replaces the shellcode every later cycle loads. Producer options are
   validated against the module's config.json; the output path is chosen by the
   host. A producer change is the right move when the signal is a signature or
   layout in the generated blob; a loader-only edit cannot remove it. The
   active producer is recorded in the prompt and dossier: crystal_pack PICO
   uses the runtime loader in postex-loader/src, while donut rebuilds
   src/loader and src/donut.c.
   GenerateAgent rebuilds the Go agent itself with agent_type
   windows_executable or windows_dll. Its artifact_path can be passed as the
   dll option to BuildShellcode producer=crystal_pack; crystal_pack uses the
   installed Java runtime and writes PICO shellcode. Switching from a donut EXE
   agent to a crystal_pack DLL agent is a design change, not a replacement of
   the agent payload: the new artifact is a freshly built agent with the same
   configuration. Changing the agent type or producer must still execute the
   agent: do not shrink the active shellcode or build a loader that skips the
   payload. The host rejects a cycle whose artifact is too small to contain the
   active shellcode.
  4. Every dynamic cycle needs a fresh agent identity and shellcode. The C2 pins
   the first public key per agent UUID (TOFU); re-running a payload whose UUID
   already checked in is rejected as a key rotation. The host enforces this
   before a cycle that would reuse the active shellcode or UUID: it builds a
   new agent, wraps it with the active producer, forgets the previous UUID, and
   deletes the old files. Call GenerateAgent and then BuildShellcode when you
   want to choose the agent type, wrapper, or producer options yourself; never
   reuse a shellcode that a previous cycle already ran. Static analyses may
   reuse a payload, but a dynamic run must not.
5. Call DetectionCycle with the mechanism under test. It rebuilds from the
   current source and returns a bounded summary, the new payload key, the active
   shellcode, and the remaining cycle budget. Do not exceed the budget. An
   operator may append instructions while the loop runs; they arrive as
   operator_prompts in this result or at the start of the next model session.
   Treat them as high-priority instructions without violating the loop's safety
   rules.
6. The host checks the generated agent after every dynamic cycle and records
   execution=verified when it checks in, offline when it does not, and
   unverified when verification is not configured. Do not spend model turns
   polling; read the execution field. A cycle with execution=offline is not a
   comparable detection result: the host restores the last executing source and
   shellcode, and you must fix why the agent never checked in before changing
   detection code. If no payload has ever checked in, stop and return the final
   JSON with the execution failure. The host still runs one final whoami
   verification after the loop stops. AgentStatus and RunModule remain scoped to
   this loop's UUID and cannot target another agent. If the agent never checks
   in, check the C2 address reachability and the generated agent or producer
   before changing loader detection code.
7. ComparePayloads the previous and new payloads. A cycle with a coverage gap
   (failed analyzer, early termination, missing telemetry) is not comparable;
   do not treat it as clean or as an improvement.
8. A finding is actionable only when it has a source location or is a real
   Defender verdict. Findings without a source location are residuals: report
   them with evidence and do not repeat a hypothesis that already failed. If a
   cycle regresses, call RevertToPayload with the best earlier payload before
   trying the next hypothesis.
9. Do not edit tests, generated artifacts, or read-only roots. Do not remove
   externally required functionality or invalidate config.json, the documented
   flags, opsec metadata, or the build entrypoint; the host rejects edits that
   remove a documented module, option, or declared choice. Internal APIs, file
   layout, and component boundaries may change. Do not stop at the first lower
   score: the sandbox risk score is noisy and saturates.

Direction discipline:
- Name the mechanism before editing: self-load, remote APC/thread, section
  mapping, module stomping/overloading, PE-image loading, a producer swap, or
  static hygiene. DetectionCycle records the mechanism with the cycle.
- A cycle that only changes imports, strings, section names, encoding, or
  packing is static hygiene, not a new loading path. Label it as such.
- If the last two cycles used the same mechanism and did not remove a real
  verdict or a high telemetry finding, test a different mechanism, or record
  the concrete constraint that makes every alternative infeasible. Module
  stomping needs an image with enough executable slack for the payload; if the
  payload cannot fit, state that and choose section mapping, PE-image loading,
  or a producer change instead.

Knowledge base:
- KnowledgeSearch, KnowledgeRead, KnowledgeStats, and KnowledgeList read the
  trusted offline security reference cache. Use it as guidance, but it is not
  evidence about this payload: source and telemetry win when they disagree.
- KnowledgeStats shows per-notebook document counts and content coverage;
  KnowledgeList lists references; KnowledgeSearch deduplicates hits by URL.
- Consult it once per mechanism, before the first EditSource or DetectionCycle
  for that mechanism:
  1. Classify the finding by the surface it comes from: on-disk static
     signature, in-memory scan, or behavioral telemetry.
  2. Search two or three concrete tokens: the mechanism plus the exact
     detector, API, event, or analyzer from the finding. For example
     "module stomping pe-sieve", "indirect syscall ETW-TI", "AMSI
     AmsiScanBuffer", "Crystal Palace PICO", "call stack spoofing". Do not
     paste a sentence.
  3. Read the top hit's summary. If it names the detector or API you are
     fighting, read the content pages you need with next_offset and stop when
     the mechanism and its telemetry footprint are clear. Content is cached only
     when the operator synced it with --content; if it is missing,
     KnowledgeRead returns the summary with fallback=true.
  4. Discard hits about a different problem. A document is not support for an
     edit just because it shares a word with the finding.
- DetectionCycle attaches a few top hits for new high/medium findings and
  records their kb= references in the cycle summary. Use those instead of
  searching the same finding again.
- Notebook focus: maldev (loaders, injection, shellcode, syscalls, call stacks,
  sleep obfuscation), edrdev (EDR internals, ETW/ETW-TI, kernel callbacks,
  drivers, hooks), redteam (C2, BOF, persistence), amsi (AMSI and user-mode ETW
  bypass, CLR/.NET), staticanalysis (PE format, obfuscation, signatures),
  vulndrivers (BYOVD, EDR killers), crystalstardust (Crystal Palace/PICO),
  com (COM/DCOM/RPC), lsass (credential dumping), defender (Defender/AV
  internals), mynotebook (reference essays). Filter with notebook only when the
  surface is ambiguous; KnowledgeSearch already deduplicates URLs, so cite the
  returned document_ref and do not repeat the same source.
- The overview 'maldev/blog.deeb.ch_posts_how-edr-works' frames the three
  surfaces as "bubbles of bane": hiding a loader from a signature scan, a
  memory scan, or behavioral telemetry usually moves the detection to another
  surface or adds telemetry. Search "bubbles of bane" to find it; read it once
  when the baseline has findings in more than one surface. Do not treat the
  disappearance of one verdict as success when ComparePayloads shows new
  telemetry in another surface.
- Turn what you read into one falsifiable prediction per cycle and put it in
  the DetectionCycle prediction field: the analyzer, event, or verdict that
  should change and in which direction. Verify it from the cycle feedback. If
  the prediction fails, say so and change the hypothesis instead of re-reading
  the same document.

Stop when no actionable high/medium finding remains and every residual is
explained with evidence, or when the cycle budget is exhausted. The host runs
final payload verification and restarts the loop if the agent does not come
online; report the last cycle honestly. Return one JSON object:
{"summary":"what changed and why","mechanism":"the loading path or producer under test","verdicts_before":["..."],"verdicts_after":["..."],"edits":[{"module":"...","file":"...","reason":"..."}],"residual":["..."],"cycles":<number>}

The host will store your answer. Be concise.`

// loggingProvider forwards Norma's normalized stream events unchanged while
// writing model text, thinking, and tool calls to the loop log. agentcore.Run
// itself returns only the final assistant text, so without this wrapper the log
// shows tools' side effects but no model output.
type loggingProvider struct {
	next     llm.Provider
	logf     func(logging.Class, string, ...any)
	text     strings.Builder
	think    strings.Builder
	tool     strings.Builder
	toolName string
}

func (p *loggingProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for event, err := range p.next.Stream(ctx, req) {
			p.observe(event)
			if !yield(event, err) {
				return
			}
		}
		p.flush()
	}
}

func (p *loggingProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.next.Complete(ctx, req)
}

func (p *loggingProvider) observe(event llm.StreamEvent) {
	switch event.Type {
	case llm.SETextDelta:
		p.text.WriteString(event.Text)
		if strings.Contains(event.Text, "\n") {
			p.flushText()
		}
	case llm.SEThinkingDelta:
		p.think.WriteString(event.Text)
		if strings.Contains(event.Text, "\n") {
			p.flushThinking()
		}
	case llm.SEToolUseStart:
		p.flushText()
		p.flushThinking()
		p.flushTool()
		p.toolName = event.ToolName
	case llm.SEToolInputJSON:
		p.tool.WriteString(event.Text)
	case llm.SEMessageDelta, llm.SEMessageStop:
		p.flush()
	}
}

func (p *loggingProvider) flush() {
	p.flushText()
	p.flushThinking()
	p.flushTool()
}

func (p *loggingProvider) flushText() {
	p.flushBlock(&p.text, logging.ClassModel)
}

func (p *loggingProvider) flushThinking() {
	p.flushBlock(&p.think, logging.ClassThinking)
}

// flushBlock hands the buffered text to the class logger as one block. The
// logger splits it into tagged lines, so indentation and code blocks survive.
func (p *loggingProvider) flushBlock(b *strings.Builder, class logging.Class) {
	text := strings.TrimRight(b.String(), "\r\n")
	b.Reset()
	if strings.TrimSpace(text) == "" {
		return
	}
	p.logf(class, "%s", text)
}

func (p *loggingProvider) flushTool() {
	if p.toolName == "" {
		p.tool.Reset()
		return
	}
	args := strings.TrimSpace(p.tool.String())
	if args == "" {
		p.logf(logging.ClassTool, "%s", p.toolName)
	} else {
		p.logf(logging.ClassTool, "%s %s", p.toolName, args)
	}
	p.toolName = ""
	p.tool.Reset()
}
