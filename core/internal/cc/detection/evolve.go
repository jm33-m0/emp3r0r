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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	defaultEvolveIterations = 3
	defaultEvolveTurns      = 60
	maxEvolveBuildLog       = 8 << 20
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
	// defaultPlannerTimeout bounds one coordinator decision. The planner reads
	// evidence; it does not design the edit, so it gets a short window.
	defaultPlannerTimeout = 5 * time.Minute
	// defaultEditorTimeout bounds the editor's analysis before it must act.
	// The window resets on a completed cycle.
	defaultEditorTimeout = 10 * time.Minute
	// Debugger policies. cycle runs a guest pass after every non-executing
	// cycle, final reserves one pass for the stop decision, and off disables
	// the debugger. A non-executing cycle is rolled back to the last clean
	// baseline, so mid-loop diagnosis mostly repeats the same harness
	// findings instead of informing a new edit.
	debuggerPolicyCycle = "cycle"
	debuggerPolicyFinal = "final"
	debuggerPolicyOff   = "off"
	// defaultDebuggerPolicy spends the guest pass once, on the last payload,
	// instead of after every execution failure.
	defaultDebuggerPolicy = debuggerPolicyFinal
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
	// Git records every writable source root in a shadow repository under the
	// detection store. Callers enable it explicitly; the console and MCP do.
	Git bool
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
	// Turns is the per-session turn cap used when the role-specific value is
	// zero.
	Turns int
	// PlannerTurns, EditorTurns, and DebuggerTurns bound each worker session.
	// Zero falls back to Turns.
	PlannerTurns int
	// PlannerTimeout bounds one planner decision, including retries after a
	// malformed answer. Zero uses five minutes.
	PlannerTimeout time.Duration
	// EditorTimeout bounds the editor's model time before it must apply an
	// edit and call DetectionCycle. A running tool or cycle suspends the
	// window, so a build is never cut off. Zero uses ten minutes.
	EditorTimeout time.Duration
	EditorTurns   int
	DebuggerTurns int
	// PlannerReadBudget and EditorReadBudget bound the read-only calls before
	// the worker must act. Zero uses the built-in default (12); a negative
	// value disables the cap. Mutation, build, and detonation tools are never
	// blocked by these budgets.
	PlannerReadBudget int
	EditorReadBudget  int
	// DebuggerToolBudget bounds the total calls in one debugger pass. Zero
	// means no total cap; the turn and time limits still apply.
	DebuggerToolBudget int
	// DebuggerTimeout bounds one debugger session. Zero uses the cycle timeout.
	DebuggerTimeout time.Duration
	// WorkerModels overrides the model per worker role ("planner", "editor",
	// "debugger"). Empty entries use Model.
	WorkerModels map[string]string
	// Guest is the sandbox guest SSH endpoint. When nil, the debugger worker
	// is not registered and offline cycles follow the restore-only path.
	Guest *GuestSSHConfig
	// DebuggerPolicy selects when the guest debugger runs: final (default),
	// cycle, or off. final reserves one pass for the stop decision.
	DebuggerPolicy string
	// Pricing is the operator's USD-per-million-token price sheet for the
	// worker model. Unset rates show token counts without a dollar estimate.
	Pricing TokenPricing
	// GuestRunner overrides the SSH client. Tests inject a fake; production
	// leaves it nil so Guest builds the real client.
	GuestRunner GuestRunner
	// Provider and Model override the environment; tests use a scripted
	// provider, production uses EMP3R0R_DETECTION_* and the usual API key.
	Provider llm.Provider
	Model    string
	// RetryBase is the first recovery delay; it backs off to 30 seconds.
	RetryBase time.Duration
	// CycleTimeout bounds one build/detonate/verify cycle and the time a model
	// session may run without completing a cycle. The session is stopped and
	// the model is required to apply an edit and retry; the loop continues.
	// Zero uses defaultCycleTimeout.
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
	// expected agent and treats a live check-in as health. The sandbox may
	// terminate the beacon before a verification BOF can run, so BOF output is
	// diagnostic, not a health signal.
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
	// AgentGlibc, AgentDynload, and AgentLibc are the Linux C agent provider
	// choices used by GenerateAgent and automatic rotation. Empty values keep
	// glibc, 2.17, and auto.
	AgentGlibc   string
	AgentDynload string
	AgentLibc    string
	// Platform selects the payload model. Empty derives it from Module:
	// loader_windows is Windows, stager_linux is Linux.
	Platform string
	// AgentSourceDir is the editable C agent tree the agent builder consumes.
	// Linux uses it now; a future Windows C agent builder can use the same
	// field. It is a writable source root, so an agent edit is part of the
	// payload design. Empty derives it from ModuleDir.
	AgentSourceDir string
}

const (
	platformWindows = "windows"
	platformLinux   = "linux"
)

// platformForModule maps the payload module to the runtime platform whose
// sandbox executes it.
func platformForModule(module string) string {
	module = strings.ToLower(strings.TrimSpace(module))
	if mod, ok := def.GetModule(module); ok && mod != nil {
		switch strings.ToLower(strings.TrimSpace(mod.Platform)) {
		case platformLinux:
			return platformLinux
		case platformWindows:
			return platformWindows
		}
	}
	switch module {
	case "stager_linux":
		return platformLinux
	default:
		return platformWindows
	}
}

// PlatformForModule is the operator-facing form of platformForModule.
func PlatformForModule(module string) string { return platformForModule(module) }

func (e *evolver) platform() string {
	if p := strings.ToLower(strings.TrimSpace(e.cfg.Platform)); p != "" {
		return p
	}
	return platformForModule(e.cfg.Module)
}

// AgentBuildOptions describes one real agent rebuild. Windows loops build a Go
// EXE or DLL and wrap it with a producer; a Linux loop builds the C agent PIC
// that stager_linux embeds.
type AgentBuildOptions struct {
	Type      string
	Arch      string
	Platform  string
	SourceDir string
	// Glibc, Dynload, and Libc select the Linux C agent compatibility build.
	// Empty values keep the builder defaults: glibc, 2.17, and auto.
	Glibc   string
	Dynload string
	Libc    string
}

// AgentBuildResult is the freshly generated agent artifact and the blob the
// payload module embeds. For Windows, ArtifactPath is the EXE or DLL and
// ShellcodePath is the producer output. For Linux, ArtifactPath and
// ShellcodePath are the C agent PIC.
type AgentBuildResult struct {
	ArtifactPath  string
	ShellcodePath string
	Type          string
	Arch          string
	Platform      string
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
	TokenUsage        TokenUsage      `json:"token_usage"`
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
	shellcodeGenerated        bool
	activeProducer            string
	expectedAgentUUID         string
	agentGlibc                string
	agentDynload              string
	agentLibc                 string
	// testedAgentUUIDs and testedShellcodes are sets shared with tool
	// goroutines; sync.Map publishes immutable membership.
	testedAgentUUIDs sync.Map
	testedShellcodes sync.Map
	// buildOpts holds the payload module's effective build flags for the next
	// cycle; producerOpts holds each producer's non-path options, keyed by
	// producer and option name. Both are copied into the cycle summary so a
	// rollback restores the last executing build state.
	buildOpts    sync.Map
	producerOpts sync.Map
	shellSeq     int
	knowledge    *KnowledgeDB
	lastAnswer   map[string]any
	// plannedMechanism is the planner's mechanism for the active editor plan.
	// DetectionCycle refuses a different label so the progress gate compares
	// like with like.
	plannedMechanism string
	// producerReads and producerQueries record the module-reading done before
	// a PICO-contract edit. The map keys are "module|path" and "module".
	producerReads   sync.Map
	producerQueries sync.Map
	baselineFailure string
	operatorPrompts *OperatorPromptQueue
	lastExecuting   *Cycle
	// lastComparable is the newest verified payload with complete analyzer
	// coverage. Finding comparisons use it instead of an executing payload
	// whose telemetry was incomplete.
	lastComparable *Cycle
	// regressionBaseline is the cycle the last verified regression was
	// measured against. It can be an executing cycle that was held because its
	// instrumentation set had not yet repeated, so the coordinator restores it
	// instead of the older comparable baseline.
	regressionBaseline *Cycle
	// lastComparison is the cycle the last verified cycle was compared with.
	// The current cycle is already appended to e.cycles when the gate runs, so
	// the memory recorder must use this value instead of scanning for a
	// same-instrumentation cycle and finding the current cycle itself.
	lastComparison *Cycle
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
	deadlineHit     atomic.Bool
	// preservedShellcode is the shellcode of the last payload whose agent
	// checked in. Rotation must not delete it: the execution gate restores it
	// when a later cycle never runs.
	preservedShellcode string
	// restoreErr records an incomplete execution-gate restore so the next
	// planner brief does not describe a broken state as executable.
	restoreErr     error
	cycleErrMu     sync.Mutex
	lastCycleError error
	lastReason     atomic.Value
	usage          usageTracker
	// toolGate closes the race between a deadline cancelling a session and a
	// tool starting in that same session.
	toolGate          sync.Mutex
	knowledgeSeen     sync.Map
	knowledgeSeenOnce sync.Once
	started           time.Time
	cyclesDone        atomic.Int64
	toolCalls         atomic.Int64
	sessions          atomic.Int64
	// agentSeenOnline is the loop-wide "any agent checked in" latch used for
	// reporting and restart decisions.
	agentSeenOnline atomic.Bool
	// payloadSeenOnline is scoped to the current payload. It is reset at the
	// start of every cycle and on agent rotation, so a baseline or debugger
	// relaunch cannot make a later failed payload look verified.
	payloadSeenOnline atomic.Bool
	lastExecution     atomic.Value
	lastAgent         atomic.Value
	// guest is the debugger's sandbox surface. Nil when SSH is not configured.
	guest GuestRunner
	// git records source commits in shadow repositories. Nil when disabled.
	git *gitRecorder
	// sessionCycles counts completed DetectionCycle calls in the current
	// editor session; one plan produces one detonation.
	sessionCycles atomic.Int32
	// sessionCancel stops the active worker session. DetectionCycle closes it
	// as soon as the cycle finishes so the coordinator can route an offline
	// cycle to the debugger instead of letting the editor keep theorizing.
	sessionCancel atomic.Pointer[sessionCanceller]
	sessionDone   atomic.Bool
}

// sessionCanceller publishes one immutable cancel function for the active
// session. The pointer is swapped, never mutated.
type sessionCanceller struct {
	cancel context.CancelFunc
}

// setSessionCancel records the cancel function for the active session and
// clears any stop left by a previous session.
func (e *evolver) setSessionCancel(cancel context.CancelFunc) {
	e.sessionCancel.Store(&sessionCanceller{cancel: cancel})
	e.sessionDone.Store(false)
}

// stopSessionAfterCycle ends the editor session as soon as its one allowed
// cycle has completed. The coordinator then runs the execution gate and the
// guest debugger before any more source analysis.
func (e *evolver) stopSessionAfterCycle() {
	e.sessionDone.Store(true)
	if canceller := e.sessionCancel.Load(); canceller != nil {
		canceller.cancel()
	}
}

// sessionStopped reports whether a completed cycle closed the current session.
func (e *evolver) sessionStopped() bool {
	return e.sessionDone.Load()
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
	if e.platform() == platformLinux {
		if root := e.artifactRoot(); root != "" {
			return root
		}
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
	if dir := strings.TrimSpace(e.cfg.AgentSourceDir); dir != "" {
		name := dependencyRootName(filepath.Base(dir), used)
		roots = append(roots, sourceRoot{Name: name, Dir: dir, Writable: true})
		used[name] = true
	}
	if e.platform() == platformWindows && strings.TrimSpace(e.cfg.AgentSourceDir) == "" {
		if dir := DefaultGoAgentSourceDir(e.cfg.ModuleDir); strings.TrimSpace(dir) != "" {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				name := dependencyRootName("go_agent", used)
				roots = append(roots, sourceRoot{Name: name, Dir: dir, Writable: true})
				used[name] = true
			}
		}
	}
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

// agentSourceBrief names the actual writable agent root. A custom
// --agent-source-dir can have a different root name, and the Windows Go source
// is mirrored as go_agent; the model must not have to infer either from the
// static prompt.
func (e *evolver) agentSourceBrief() string {
	if e.roots == nil {
		return ""
	}
	expected := strings.TrimSpace(e.cfg.AgentSourceDir)
	if expected == "" {
		if e.platform() == platformLinux {
			expected = DefaultAgentSourceDir(e.cfg.ModuleDir)
		} else {
			expected = DefaultGoAgentSourceDir(e.cfg.ModuleDir)
		}
	}
	if expected != "" {
		for _, name := range e.roots.names {
			root := e.roots.roots[name]
			if !root.Writable {
				continue
			}
			if sameSourceDir(root.Dir, expected) {
				return fmt.Sprintf("Agent source root: %s=%s (edit). Edit this root for agent behavior, then call GenerateAgent to rebuild it.", name, root.Dir)
			}
		}
	}
	return ""
}

func sameSourceDir(a, b string) bool {
	a, b = filepath.Clean(strings.TrimSpace(a)), filepath.Clean(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	realA, errA := filepath.EvalSymlinks(a)
	realB, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && realA == realB
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

// ErrSandboxUnreachable means the LitterBox endpoint is not answering. The
// loop cannot build or detonate until it returns; this is a host outage, not a
// hypothesis failure.
var ErrSandboxUnreachable = errors.New("sandbox unreachable")

// errBuildFailed marks a source edit that does not compile. The host restores
// the last executing source and lets the editor retry the same plan; unlike a
// model or sandbox failure, this is repairable without spending the editor
// failure budget.
var errBuildFailed = errors.New("build failed")

// waitSandbox probes the sandbox once. The failure goes straight to the model
// instead of a host retry loop, so the loop never rebuilds or detonates again
// without model feedback.
func (e *evolver) waitSandbox(ctx context.Context) (Health, error) {
	health := e.loop.AvailableFor(ctx, e.platform())
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
	return Health{}, fmt.Errorf("%w: %s: %s", ErrSandboxUnreachable, health.URL, reason)
}

// setCycleError records why DetectionCycle failed before a detonation. The
// editor session can end without a cycle; the coordinator reads this cause
// instead of reporting a generic contract failure.
func (e *evolver) setCycleError(err error) {
	e.cycleErrMu.Lock()
	e.lastCycleError = err
	e.cycleErrMu.Unlock()
}

func (e *evolver) takeCycleError() error {
	e.cycleErrMu.Lock()
	defer e.cycleErrMu.Unlock()
	err := e.lastCycleError
	e.lastCycleError = nil
	return err
}

func (e *evolver) clearCycleError() {
	e.setCycleError(nil)
}

// recover logs a failure and waits before the caller retries. Callers bound
// the number of attempts; recover returns false only when the context is done.
func (e *evolver) recover(ctx context.Context, attempt int, what string, err error) bool {
	return e.backoff(ctx, attempt, fmt.Sprintf("%s failed: %v", what, err))
}

// backoff waits before the next session so a model that keeps returning
// without progress cannot spin the loop. It returns false only when the loop
// context is done.
func (e *evolver) backoff(ctx context.Context, attempt int, reason string) bool {
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
	e.logClass(logging.ClassWarning, "%s (attempt %d); retrying in %s", reason, attempt+1, delay)
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
	loop, err := NewLoop(LoopConfig{SandboxURL: cfg.SandboxURL, Platform: cfg.Platform, StoreRoot: cfg.StoreRoot})
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
		shellcodeGenerated:        cfg.InitialShellcodeGenerated,
		activeProducer:            strings.ToLower(strings.TrimSpace(cfg.InitialProducer)),
		expectedAgentUUID:         strings.TrimSpace(cfg.ExpectedAgentUUID),
		agentGlibc:                strings.TrimSpace(cfg.AgentGlibc),
		agentDynload:              strings.TrimSpace(cfg.AgentDynload),
		agentLibc:                 strings.TrimSpace(cfg.AgentLibc),
	}
	if e.logf == nil {
		e.logf = func(logging.Class, string, ...any) {}
	}
	e.initBuildOptions(initialBuildOptions(cfg))
	switch {
	case cfg.GuestRunner != nil:
		e.guest = cfg.GuestRunner
		defer func() { _ = cfg.GuestRunner.Close() }()
	case cfg.Guest != nil:
		guest, guestErr := newGuestSSH(*cfg.Guest, cfg.StoreRoot)
		if guestErr != nil {
			return nil, fmt.Errorf("guest SSH: %w", guestErr)
		}
		e.guest = guest
		defer func() { _ = guest.Close() }()
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
	if cfg.Git {
		recorder, gitErr := newGitRecorder(cfg.StoreRoot, e.baseLoopID, e.roots, e.logf)
		if gitErr != nil {
			return nil, gitErr
		}
		if initErr := recorder.Init(ctx); initErr != nil {
			return nil, fmt.Errorf("git init: %w", initErr)
		}
		e.git = recorder
	}
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
	provider = &resilientProvider{next: provider, logf: e.logf}
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
	case errors.Is(err, ErrSandboxUnreachable):
		return nil, err
	case ctx.Err() != nil:
		return nil, ctx.Err()
	default:
		e.baselineFailure = clipUTF8(sanitizeLine(err.Error()), 4000)
		e.logClass(logging.ClassWarning,
			"baseline failed; asking the model to diagnose the failure before another attempt: %s",
			e.baselineFailure)
	}
	// The baseline does not consume a model decision window: each worker
	// session starts its own watchdog.
	baselineJSON, _ := json.Marshal(baseline)

	knowledgeState := "unavailable; ask the operator to run detect_loop knowledge-sync"
	if e.knowledge != nil {
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
	coord := newCoordinator(e, provider, model, baselineJSON, knowledgeState)
	answer, err := coord.run(ctx)
	if err != nil {
		return nil, err
	}
	if coord.lastDiagnosis != nil {
		answer["debugger_diagnosis"] = coord.lastDiagnosis
	}
	if e.git != nil {
		if commits, gitErr := e.git.CommitAll(ctx, "final"); gitErr != nil {
			e.logClass(logging.ClassWarning, "git final commit: %v", gitErr)
		} else {
			answer["git_heads"] = commits
			answer["git_dir"] = e.git.baseDir
		}
	}
	if answer == nil {
		answer = map[string]any{
			"summary":  "the coordinator returned no answer",
			"edits":    []any{},
			"residual": []string{"no final answer"},
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
	if lastVerified := lastVerifiedCycle(e.recentCycles(0)); lastVerified != nil {
		answer["last_verified_payload"] = lastVerified.PayloadKey
	}
	answer["cycles"] = e.cycles
	if cfg.FinalVerify != nil {
		if e.expectedAgentUUID == "" {
			answer["payload_verified"] = false
			answer["payload_verification_error"] = "no expected agent UUID"
		} else {
			output, verifyErr := cfg.FinalVerify(ctx, e.expectedAgentUUID)
			payloadSeen := e.payloadSeenOnline.Load()
			verified := finalPayloadVerified(output, verifyErr, payloadSeen)
			if verified && (verifyErr != nil || strings.TrimSpace(output) == "") {
				answer["payload_verification_note"] = "this payload checked in; BOF output is not required because the sandbox terminates the beacon after the capture window"
			}
			if !verified && e.guest != nil && !payloadSeen {
				// A fresh agent restart cannot fix a guest-side execution
				// fault. Let the debugger inspect the sandbox first, then
				// retry the final check once when it reports a fix.
				diag, diagErr := coord.debug(ctx, debugRequest{Trigger: "final payload verification", Cycle: e.last, Repeat: true})
				if diagErr != nil {
					e.logClass(logging.ClassWarning, "final debugger: %v", diagErr)
				}
				if diag != nil {
					answer["final_diagnosis"] = diag
					if diag.AgentOnlineAfter {
						output, verifyErr = cfg.FinalVerify(ctx, e.expectedAgentUUID)
						verified = verifyErr == nil && strings.TrimSpace(output) != ""
					}
				}
			}
			answer["payload_verified"] = verified
			if verified {
				e.agentSeenOnline.Store(true)
			}
			answer["payload_verification_output"] = clip(output, 4000)
			if verifyErr != nil {
				answer["payload_verification_error"] = verifyErr.Error()
			}
			e.logClass(logging.ClassCycle, "final payload verification for %s: verified=%v", e.expectedAgentUUID, verified)
		}
	}
	verified, _ := answer["payload_verified"].(bool)
	answer["agent_online_seen"] = e.agentSeenOnline.Load()
	usage := e.usage.snapshot(cfg.Pricing)
	answer["token_usage"] = usage
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
		ExpectedAgentUUID: e.expectedAgentUUID, TokenUsage: usage,
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
	platform := strings.ToLower(strings.TrimSpace(cfg.Platform))
	if platform == "" {
		platform = platformForModule(cfg.Module)
	}
	if platform != platformWindows && platform != platformLinux {
		return fmt.Errorf("platform must be windows or linux")
	}
	if platform != platformForModule(cfg.Module) {
		return fmt.Errorf("module %q is a %s payload", cfg.Module, platformForModule(cfg.Module))
	}
	cfg.Platform = platform
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
	if cfg.Guest != nil {
		cfg.Guest.Platform = platform
		if err := cfg.Guest.normalize(cfg.StoreRoot); err != nil {
			return fmt.Errorf("guest SSH: %w", err)
		}
	}
	if platform == platformLinux {
		cfg.AgentSourceDir = strings.TrimSpace(cfg.AgentSourceDir)
		if cfg.AgentSourceDir == "" {
			cfg.AgentSourceDir = DefaultAgentSourceDir(cfg.ModuleDir)
		}
		if info, err := os.Stat(cfg.AgentSourceDir); err != nil || !info.IsDir() {
			return fmt.Errorf("c agent source directory %q is not readable", cfg.AgentSourceDir)
		}
		cfg.AgentType = "linux_so"
		cfg.AgentArch = "amd64"
		cfg.Format = "executable"
		cfg.SMW = ""
		cfg.Process = ""
		cfg.Inject = ""
		malasadaDir := LinuxProducerDir(cfg.ModuleDir)
		for name, dir := range cfg.ProducerDirs {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "malasada" {
				return fmt.Errorf("producer %q is not supported for stager_linux; use the shipped malasada module", name)
			}
			if malasadaDir == "" {
				return fmt.Errorf("stager_linux requires the shipped malasada producer")
			}
			if !strings.EqualFold(filepath.Clean(strings.TrimSpace(dir)), filepath.Clean(malasadaDir)) {
				return fmt.Errorf("malasada is shipped with emp3r0r; remove the custom producer path")
			}
		}
		if cfg.BuildAgent != nil && malasadaDir == "" {
			return fmt.Errorf("stager_linux requires the shipped malasada producer; install the operator kit")
		}
		if malasadaDir == "" {
			cfg.ProducerDirs = nil
		} else {
			cfg.ProducerDirs = map[string]string{"malasada": malasadaDir}
		}
	} else {
		if cfg.Format == "" {
			cfg.Format = "exe"
		}
		// An empty inject or process flag means "use the module's own default",
		// so a source edit to that default is testable without the harness
		// overriding it on every build.
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
	}
	if cfg.LoopID == "" {
		cfg.LoopID = "loop-" + time.Now().UTC().Format("20060102-150405")
	}
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
	if cfg.PlannerTimeout <= 0 {
		cfg.PlannerTimeout = defaultPlannerTimeout
	}
	if cfg.EditorTimeout <= 0 {
		cfg.EditorTimeout = defaultEditorTimeout
	}
	if cfg.Turns <= 0 {
		cfg.Turns = defaultEvolveTurns
	}
	if cfg.PlannerReadBudget == 0 {
		cfg.PlannerReadBudget = plannerReadBudget
	}
	if cfg.EditorReadBudget == 0 {
		cfg.EditorReadBudget = editorReadBudget
	}
	if cfg.Pricing.InputPerMillion < 0 || cfg.Pricing.OutputPerMillion < 0 ||
		cfg.Pricing.CacheReadPerMillion < 0 || cfg.Pricing.CacheWritePerMillion < 0 {
		return fmt.Errorf("token prices must not be negative")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DebuggerPolicy)) {
	case "":
		cfg.DebuggerPolicy = defaultDebuggerPolicy
	case debuggerPolicyCycle, debuggerPolicyFinal, debuggerPolicyOff:
		cfg.DebuggerPolicy = strings.ToLower(strings.TrimSpace(cfg.DebuggerPolicy))
	default:
		return fmt.Errorf("unknown debugger policy %q; use final, cycle, or off", cfg.DebuggerPolicy)
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

// hygieneFinding is one stable static-hygiene item the planner can act on.
// Stringnalyzer indicators are excluded from this list because their names
// change with every build; the top-finding view still carries them.
type hygieneFinding struct {
	Rule      string `json:"rule,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Indicator string `json:"indicator"`
	Detail    string `json:"detail,omitempty"`
	Source    string `json:"source,omitempty"`
}

type cycleSummary struct {
	LoopID              string           `json:"loop_id"`
	Iteration           int              `json:"iteration"`
	Attempt             int              `json:"attempt,omitempty"`
	GlobalIteration     int              `json:"global_iteration,omitempty"`
	PayloadKey          string           `json:"payload_key"`
	PayloadTable        string           `json:"payload_table"`
	RunID               string           `json:"run_id"`
	SHA256              string           `json:"sha256"`
	Score               float64          `json:"score"`
	Level               string           `json:"level,omitempty"`
	Findings            int              `json:"findings"`
	HighFindings        int              `json:"high_findings,omitempty"`
	MediumFindings      int              `json:"medium_findings,omitempty"`
	StaticFindings      int              `json:"static_findings,omitempty"`
	DetectionClassified bool             `json:"detection_classified,omitempty"`
	DetectionHigh       int              `json:"detection_high,omitempty"`
	DetectionMedium     int              `json:"detection_medium,omitempty"`
	HygieneHigh         int              `json:"hygiene_high,omitempty"`
	HygieneMedium       int              `json:"hygiene_medium,omitempty"`
	HygieneStatic       int              `json:"hygiene_static,omitempty"`
	StableTotal         int              `json:"stable_total,omitempty"`
	Verdicts            []string         `json:"verdicts,omitempty"`
	TraceID             int64            `json:"trace_id,omitempty"`
	Events              int              `json:"telemetry_events"`
	Telemetry           *TelemetryStats  `json:"telemetry,omitempty"`
	SourceEdits         int              `json:"source_edits"`
	TopFindings         []string         `json:"top_findings,omitempty"`
	Hygiene             []hygieneFinding `json:"hygiene,omitempty"`
	BuildTail           []string         `json:"build_tail,omitempty"`
	Edits               []EditRecord     `json:"edits,omitempty"`
	Shellcode           string           `json:"shellcode,omitempty"`
	Producer            string           `json:"producer,omitempty"`
	ShellcodeGenerated  bool             `json:"shellcode_generated,omitempty"`
	// BuildOptions and ProducerOptions are the effective build state for the
	// cycle. They are restored with the last executing payload, so a build
	// option that regressed cannot leak into a later cycle.
	BuildOptions     map[string]string `json:"build_options"`
	ProducerOptions  map[string]string `json:"producer_options"`
	Mechanism        string            `json:"mechanism,omitempty"`
	Prediction       string            `json:"prediction,omitempty"`
	PredictionResult string            `json:"prediction_result,omitempty"`
	Observed         string            `json:"observed,omitempty"`
	Stages           []string          `json:"stages,omitempty"`
	Note             string            `json:"note,omitempty"`
	Executed         bool              `json:"executed"`
	Execution        string            `json:"execution,omitempty"`
	AgentOnline      *bool             `json:"agent_online,omitempty"`
	NetworkEvents    int               `json:"network_events,omitempty"`
	SourceTreeHash   string            `json:"source_tree_hash,omitempty"`
	DesignKey        string            `json:"design_key,omitempty"`
	CoverageMissing  []string          `json:"coverage_missing,omitempty"`
	Knowledge        []KnowledgeHit    `json:"knowledge,omitempty"`
	KBRefs           []string          `json:"kb_refs,omitempty"`
	// RecoveredBy, DebuggerCause, and GuestActions record a debugger-assisted
	// execution recovery without changing the cycle's detection data.
	RecoveredBy   string            `json:"recovered_by,omitempty"`
	DebuggerCause string            `json:"debugger_cause,omitempty"`
	GuestActions  []string          `json:"guest_actions,omitempty"`
	GitCommits    map[string]string `json:"git_commits,omitempty"`
	// InstrumentationChanged records that the sandbox delivered a different
	// set of instrumentation features than the baseline, so an offline result
	// is not attributable to a source edit. NewHighFindings lists high top
	// findings that did not exist in the baseline.
	InstrumentationChanged bool     `json:"instrumentation_changed,omitempty"`
	InstrumentationNote    string   `json:"instrumentation_note,omitempty"`
	NewHighFindings        []string `json:"new_high_findings,omitempty"`
	// DynamicRegions attributes executable regions in medium analyzer findings
	// to the loader's outer PICO or the producer's inner PICO by size.
	DynamicRegions []string `json:"dynamic_regions,omitempty"`
	// FailureLayer is the load-pipeline stage where an offline cycle stopped,
	// derived from the trace categories. It is host evidence, not model prose.
	FailureLayer string `json:"failure_layer,omitempty"`
	// Platform is the sandbox runtime that produced the trace.
	Platform string `json:"platform,omitempty"`
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
	if mechanism == "producer-swap" {
		previous := e.lastProducer()
		if previous != "" && strings.EqualFold(previous, e.activeProducer) {
			return Cycle{}, fmt.Errorf("producer-swap did not change the shellcode producer (still %s); call GenerateAgent and BuildShellcode with a different producer before DetectionCycle",
				headerOrNone(e.activeProducer))
		}
	}

	if _, err := e.waitSandbox(cycleCtx); err != nil {
		return Cycle{}, err
	}
	if e.dynamicEnabled() {
		// TOFU pins the first key per UUID. The host rotates the agent before
		// reusing a shellcode instead of letting the C2 reject the check-in.
		if err := e.ensureFreshAgent(cycleCtx); err != nil {
			if errors.Is(err, errBuildFailed) {
				e.rollbackFailedBuild(iteration, err)
			}
			return Cycle{}, err
		}
	}
	// Health proof belongs to this payload, not to any earlier agent.
	e.payloadSeenOnline.Store(false)

	var gitCommits map[string]string
	if e.git != nil {
		commits, gitErr := e.git.CommitAll(cycleCtx, fmt.Sprintf("cycle %d: %s", iteration, mechanism))
		if gitErr != nil {
			e.logClass(logging.ClassWarning, "git commit: %v", gitErr)
		} else {
			gitCommits = commits
		}
	}
	shellcode := e.activeShellcode()
	buildOptions := e.buildOptionsSnapshot()
	flags := e.payloadBuildFlags(shellcode, iteration)
	e.logClass(logging.ClassCycle, "cycle %d (attempt %d, global %d): building %s (shellcode %s, options %s)",
		iteration, e.attempt, e.globalUsed+iteration, e.cfg.Module, shellcode, formatBuildOptions(buildOptions))
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
		e.rollbackFailedBuild(iteration, buildErr)
		return Cycle{}, fmt.Errorf("%w: build %s: %w\n%s", errBuildFailed, e.cfg.Module, buildErr,
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
		AgentSourceDir: e.cfg.AgentSourceDir,
		ArtifactPath:   artifact.Path,
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
		if e.platform() == platformLinux {
			e.logClass(logging.ClassWarning,
				"run %s has no payload process; keeping trace %d (%d events) for the model",
				headerOrNone(run.ID), run.Telemetry.TraceID, run.Telemetry.Events)
		} else {
			e.logClass(logging.ClassWarning,
				"run %s has no payload PEB; keeping trace %d (%d events) for the model",
				headerOrNone(run.ID), run.Telemetry.TraceID, run.Telemetry.Events)
		}
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
	summary := summarizeCycle(e.cfg.LoopID, iteration, run, feedback, buildLog, note, mechanism, shellcode, e.activeProducer, execution, online, networkEvents, e.shellcodeGenerated)
	summary.BuildOptions = buildOptions
	summary.ProducerOptions = e.activeProducerOptions()
	summary.Attempt = e.attempt
	summary.GlobalIteration = e.globalUsed + iteration
	summary.Prediction = clip(prediction, 500)
	summary.Stages = stageNames(e.cfg.Stages)
	summary.Observed = observedFindings(feedback)
	summary.PredictionResult = evaluatePredictionWithExecution(prediction, feedback, execution, online)
	summary.DynamicRegions = dynamicRegionSummary(feedback, shellcode)
	summary.GitCommits = gitCommits
	summary.FailureLayer = failureLayer(&summary)
	if prev := e.previousInstrumentationSummary(); prev != nil && iteration > 1 {
		if earlyTermination(summary.Telemetry) {
			e.logClass(logging.ClassWarning,
				"cycle %d ended before dynamic analysis; instrumentation comparison skipped", iteration)
		} else if changed, note := instrumentationDelta(prev, &summary); changed {
			summary.InstrumentationChanged = true
			summary.InstrumentationNote = note
			e.logClass(logging.ClassWarning, "cycle %d: %s", iteration, note)
		}
		// A high that appears only because the sandbox started delivering a
		// new source is not a payload change. Compare highs only within one
		// instrumentation era, the same way finding counts are compared.
		if !summary.InstrumentationChanged {
			if highs := newHighFindings(prev.TopFindings, summary.TopFindings); len(highs) > 0 {
				summary.NewHighFindings = highs
				e.logClass(logging.ClassWarning, "cycle %d added high finding(s): %s", iteration, strings.Join(highs, ", "))
			}
		}
	}
	e.cyclesDone.Store(int64(e.globalUsed + iteration))
	e.lastExecution.Store(summary.Execution)
	e.lastAgent.Store(e.expectedAgentUUID)
	e.sourceTreeHash = e.computeSourceTreeHash()
	summary.SourceTreeHash = e.sourceTreeHash
	summary.DesignKey = designKey(e.sourceTreeHash, summary.BuildOptions, summary.ProducerOptions, summary.Producer, e.cfg.AgentType)
	if edits, err := e.db.LoopEdits(cycleCtx, e.cfg.LoopID); err != nil {
		e.logClass(logging.ClassError, "read edits for cycle summary: %v", err)
	} else {
		for _, edit := range edits {
			if edit.Iteration != iteration || editKind(edit.Kind) != EditKindModel || edit.Reverted {
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
	cycleID, err := e.db.SaveCycle(cycleCtx, cycle)
	if err != nil {
		return Cycle{}, err
	}
	cycle.ID = cycleID
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
	e.logClass(logging.ClassCycle, "cycle %d: payload=%s sha=%s high=%d static=%d findings=%d verdicts=%v execution=%s",
		iteration, cycle.PayloadKey, shortSHA(artifact.SHA256), summary.HighFindings,
		summary.StaticFindings, cycle.Findings, summary.Verdicts, summary.Execution)
	// The coordinator applies the execution gate after the editor session so a
	// debugger can inspect the guest before a non-executing cycle is reverted.
	return cycle, nil
}

// failureLayer names the load-pipeline stage where an offline cycle stopped.
// The categories come from the trace, so this is evidence rather than a guess
// about which source file to edit.
func failureLayer(summary *cycleSummary) string {
	if summary == nil || summary.Execution == executionVerified {
		return ""
	}
	if summary.InstrumentationChanged {
		return "instrumentation"
	}
	if summary.Telemetry == nil {
		return "unknown"
	}
	categories := summary.Telemetry.ByCategory
	switch {
	case categories["process"] == 0:
		return "loader-start"
	case categories["memory"] == 0 && categories["thread"] == 0:
		return "payload-mapping"
	case categories["network"] == 0:
		return "agent-network"
	default:
		return "agent-checkin"
	}
}

func failureLayerAction(layer string) string {
	switch layer {
	case "loader-start":
		return "the loader process did not start; inspect the host/launch path before editing the payload or producer"
	case "payload-mapping":
		return "the process ran but did not map/execute the payload; test the loader-to-producer boundary first"
	case "agent-network":
		return "the payload executed but produced no network/check-in; inspect the agent configuration and C2 path"
	case "agent-checkin":
		return "network activity exists but the expected agent did not check in; inspect the agent identity and C2 verification"
	case "instrumentation":
		return "the sandbox delivered a different instrumentation set; cycles across the change are not comparable, and the next verified cycle establishes a new baseline"
	default:
		return "the trace does not identify the stage; inspect the events before editing"
	}
}

// knowledgeQuery builds a compact search from the last cycle's top findings and
// mechanism. The host runs it before a worker session and puts the hits in the
// brief, so the model is not required to spend its read budget rediscovering
// the technique.
func (e *evolver) knowledgeQuery(mechanism string) string {
	if e == nil || e.last == nil {
		return ""
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &summary) != nil {
		return ""
	}
	var parts []string
	for _, finding := range summary.TopFindings {
		text := strings.TrimSpace(finding)
		for _, prefix := range []string{"high", "medium", "low"} {
			text = strings.TrimSpace(strings.TrimPrefix(text, prefix))
		}
		if text == "" || strings.Contains(text, "analyzer/") {
			continue
		}
		parts = append(parts, text)
		if len(parts) == 2 {
			break
		}
	}
	mechanism = strings.TrimSpace(mechanism)
	if mechanism == "" {
		mechanism = strings.TrimSpace(summary.Mechanism)
	}
	if mechanism != "" {
		parts = append(parts, mechanism)
	}
	if summary.Execution == executionOffline {
		parts = append(parts, "offline")
	}
	if summary.InstrumentationChanged {
		parts = append(parts, "instrumentation")
	}
	if summary.FailureLayer != "" {
		parts = append(parts, strings.ReplaceAll(summary.FailureLayer, "-", " "))
	}
	if len(summary.NewHighFindings) > 0 {
		parts = append(parts, "static high regression")
	}
	return strings.Join(parts, " ")
}

// failureLayerHint is the host-derived stage for the last offline cycle.
func (e *evolver) failureLayerHint() string {
	if e == nil || e.last == nil {
		return ""
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &summary) != nil || summary.FailureLayer == "" {
		return ""
	}
	return "Failure layer: " + summary.FailureLayer + " — " + failureLayerAction(summary.FailureLayer)
}

// dynamicRegionHint is the host-derived attribution for the last cycle's
// executable medium findings. It tells the planner whether a region belongs to
// the loader's outer PICO or to the producer's inner PICO.
func (e *evolver) dynamicRegionHint() string {
	if e == nil || e.last == nil {
		return ""
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &summary) != nil || len(summary.DynamicRegions) == 0 {
		return ""
	}
	return "Dynamic regions: " + strings.Join(summary.DynamicRegions, "; ") +
		". A region matching the active shellcode is the loader's outer PICO; an unmatched executable region is inside the producer PICO. A loader-only edit cannot remove an unmatched producer region: plan one change per owner or a producer-swap that covers both."
}

// previousInstrumentationSummary returns the last cycle whose telemetry can be
// used for an instrumentation comparison. A run that ended before dynamic
// analysis is skipped; any other run, including an offline one, observed the
// same guest and can confirm whether a delivered set is stable.
func (e *evolver) previousInstrumentationSummary() *cycleSummary {
	if e == nil {
		return nil
	}
	for i := len(e.cycles) - 1; i >= 0; i-- {
		var summary cycleSummary
		if json.Unmarshal([]byte(e.cycles[i].Summary), &summary) != nil {
			continue
		}
		if summary.Telemetry == nil || earlyTermination(summary.Telemetry) {
			continue
		}
		return &summary
	}
	return nil
}

// instrumentationDelta compares the instrumentation features the sandbox
// delivered for a cycle with the baseline. A change means an offline cycle is
// not attributable to a source edit; the model must stabilize the guest first.
func instrumentationDelta(baseline, current *cycleSummary) (bool, string) {
	if baseline == nil || current == nil || baseline.Telemetry == nil || current.Telemetry == nil {
		return false, ""
	}
	features := []string{"hook", "kernel", "etwti", "etw", "antimalware", "defender_trace"}
	before := stringSet(baseline.Telemetry.Coverage.Delivered)
	after := stringSet(current.Telemetry.Coverage.Delivered)
	var added, removed []string
	for _, feature := range features {
		if after[feature] && !before[feature] {
			added = append(added, feature)
		}
		if before[feature] && !after[feature] {
			removed = append(removed, feature)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return false, ""
	}
	note := "guest instrumentation changed since the previous verified cycle"
	if len(added) > 0 {
		note += "; added " + strings.Join(added, ", ")
	}
	if len(removed) > 0 {
		note += "; removed " + strings.Join(removed, ", ")
	}
	note += ". Cycles across the change are not comparable"
	return true, note
}

// instrumentationComparable reports whether two cycles were observed under the
// same delivered instrumentation. A cycle without telemetry is treated as
// unknown and comparable, which preserves the pre-telemetry behaviour for
// static cycles and older summaries.
func instrumentationComparable(previous *Cycle, current *cycleSummary) bool {
	if previous == nil || current == nil {
		return false
	}
	var prev cycleSummary
	if json.Unmarshal([]byte(previous.Summary), &prev) != nil || prev.Telemetry == nil || current.Telemetry == nil {
		return true
	}
	return sameDelivered(&prev, current)
}

// sameDelivered compares the telemetry features two reports delivered.
func sameDelivered(a, b *cycleSummary) bool {
	if a == nil || b == nil || a.Telemetry == nil || b.Telemetry == nil {
		return false
	}
	before := stringSet(a.Telemetry.Coverage.Delivered)
	after := stringSet(b.Telemetry.Coverage.Delivered)
	if len(before) != len(after) {
		return false
	}
	for feature := range before {
		if !after[feature] {
			return false
		}
	}
	return true
}

// newHighFindings lists high top-findings that the baseline did not have.
func newHighFindings(baseline, current []string) []string {
	before := map[string]bool{}
	for _, finding := range baseline {
		if indicator := highIndicator(finding); indicator != "" {
			before[indicator] = true
		}
	}
	seen := map[string]bool{}
	var added []string
	for _, finding := range current {
		indicator := highIndicator(finding)
		if indicator == "" || before[indicator] || seen[indicator] {
			continue
		}
		seen[indicator] = true
		added = append(added, indicator)
	}
	return added
}

func highIndicator(finding string) string {
	finding = strings.TrimSpace(finding)
	if !strings.HasPrefix(finding, "high") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(finding, "high"))
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.ToLower(strings.TrimSpace(value))] = true
	}
	return set
}

// highRegressionHint names the high findings an edit added. A new high is
// worse than the baseline even when the cycle did not execute.
func (e *evolver) highRegressionHint() string {
	if e == nil || e.last == nil {
		return ""
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &summary) != nil || len(summary.NewHighFindings) == 0 {
		return ""
	}
	return "Static regression: the last cycle added high finding(s) " + strings.Join(summary.NewHighFindings, ", ") + ". Revert that change; a new high is worse than the baseline."
}

var dynamicRegionPattern = regexp.MustCompile(`(?i)Base:\s*(0x[0-9a-f]+).*?Size:\s*(0x[0-9a-f]+)`)

// dynamicRegionSummary attributes medium analyzer regions to the loader's
// outer PICO or to the producer's inner PICO. Region size is the only stable
// signal: the outer PICO is the active shellcode, while the masked DLL inside
// Crystal Palace has a different size. This is host evidence for the planner;
// it does not claim which source line created the region.
// earlyTermination reports that the sandbox stopped the payload before the
// dynamic analyzers could attach. Missing providers in such a trace are a
// consequence of the early exit, not evidence that the guest instrumentation
// changed; treating them as a gate would block the source fix for the crash.
func earlyTermination(stats *TelemetryStats) bool {
	if stats == nil {
		return false
	}
	for _, missing := range stats.Coverage.Missing {
		lower := strings.ToLower(missing)
		if strings.Contains(lower, "early termination") || strings.Contains(lower, "not started") {
			return true
		}
	}
	status := strings.ToLower(stats.Coverage.Analyzers["dynamic/analysis_metadata"])
	return strings.Contains(status, "early termination") || strings.Contains(status, "not started")
}

func dynamicRegionSummary(feedback Feedback, shellcode string) []string {
	shellcodeSize := int64(0)
	if info, err := os.Stat(strings.TrimSpace(shellcode)); err == nil {
		shellcodeSize = info.Size()
	}
	seen := map[string]bool{}
	var out []string
	for _, finding := range feedback.Findings {
		if !strings.EqualFold(strings.TrimSpace(finding.Severity), "medium") {
			continue
		}
		match := dynamicRegionPattern.FindStringSubmatch(finding.Indicator + " " + finding.Detail)
		if match == nil {
			continue
		}
		base, hexSize := match[1], match[2]
		size, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(hexSize), "0x"), 16, 64)
		if err != nil || size == 0 {
			continue
		}
		owner := "producer PICO (size does not match the active shellcode)"
		if shellcodeSize > 0 && size >= uint64(shellcodeSize) && size <= uint64(shellcodeSize)+0x2000 {
			owner = "loader outer PICO (size matches the active shellcode)"
		}
		key := base + ":" + hexSize
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fmt.Sprintf("%s size=%s (%d B) tool=%s: %s",
			sanitizeLine(base), sanitizeLine(hexSize), size, sanitizeLine(finding.Tool), owner))
		if len(out) == 8 {
			break
		}
	}
	return out
}

// verdictFindings returns the sandbox's named verdicts. Windows uses Defender
// threat verdicts; Linux uses high/critical Falco alerts.
func verdictFindings(platform string, findings []Finding, limit int) []string {
	var out []string
	for _, finding := range findings {
		match := finding.Rule == "defender/verdict"
		if platform == platformLinux {
			match = strings.HasPrefix(strings.ToLower(strings.TrimSpace(finding.Rule)), "falco/") &&
				(finding.Severity == "critical" || finding.Severity == "high")
		}
		if !match {
			continue
		}
		out = appendUnique(out, sanitizeLine(finding.Indicator))
		if len(out) >= limit {
			break
		}
	}
	return out
}

func summarizeCycle(loopID string, iteration int, run Run, feedback Feedback, buildLog, note, mechanism, shellcode, producer, execution string, online *bool, networkEvents int, shellcodeGenerated bool) cycleSummary {
	summary := cycleSummary{
		LoopID: loopID, Iteration: iteration, RunID: run.ID,
		Mechanism: mechanism,
		SHA256:    run.Plan.Artifact.SHA256, Score: feedback.Score, Level: sanitizeLine(feedback.Level),
		Findings: len(feedback.Findings), SourceEdits: len(feedback.SourceEdits),
		Shellcode: shellcode, Producer: producer, ShellcodeGenerated: shellcodeGenerated, Note: note,
		Executed: execution == executionVerified, Execution: execution,
		AgentOnline: online, NetworkEvents: networkEvents,
	}
	counts := countFindings(feedback.Findings)
	summary.HighFindings, summary.MediumFindings, summary.StaticFindings = counts.High, counts.Medium, counts.Static
	summary.DetectionClassified = true
	summary.DetectionHigh, summary.DetectionMedium = counts.DetectionHigh, counts.DetectionMedium
	summary.HygieneHigh, summary.HygieneMedium = counts.HygieneHigh, counts.HygieneMedium
	summary.HygieneStatic, summary.StableTotal = counts.HygieneStatic, counts.StableTotal
	if run.Telemetry != nil {
		summary.PayloadKey = run.Telemetry.PayloadKey
		summary.PayloadTable = run.Telemetry.PayloadTable
		summary.TraceID = run.Telemetry.TraceID
		summary.Events = run.Telemetry.Events
		summary.Platform = run.Telemetry.Platform
		summary.Telemetry = run.Telemetry.Stats
		summary.CoverageMissing = coverageMissing(run.Telemetry.Coverage)
		if summary.Telemetry == nil {
			summary.Telemetry = &TelemetryStats{
				TraceID: run.Telemetry.TraceID, Events: run.Telemetry.Events,
				Findings: len(run.Telemetry.Findings), Coverage: run.Telemetry.Coverage,
			}
		}
		summary.Verdicts = verdictFindings(run.Telemetry.Platform, run.Telemetry.Findings, 8)
	}
	if summary.Platform == "" && run.Plan.Platform != "" {
		summary.Platform = run.Plan.Platform
	}
	if len(summary.Verdicts) < 8 {
		for _, verdict := range verdictFindings(summary.Platform, feedback.Findings, 8) {
			summary.Verdicts = appendUnique(summary.Verdicts, verdict)
		}
	}
	for _, finding := range feedback.Findings {
		if classifyFinding(finding) == findingContext {
			continue
		}
		summary.TopFindings = append(summary.TopFindings,
			clipUTF8(fmt.Sprintf("%s %s %s", sanitizeLine(finding.Severity), sanitizeLine(finding.Rule),
				sanitizeLine(finding.Indicator)), 500))
		if len(summary.TopFindings) >= 8 {
			break
		}
	}
	summary.Hygiene = hygieneSummary(feedback.Findings)
	lines := strings.Split(strings.TrimSpace(buildLog), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	for _, line := range lines {
		summary.BuildTail = append(summary.BuildTail, clipUTF8(line, 500))
	}
	return summary
}

// hygieneSummary keeps the stable static findings the model can fix. The
// stringnalyzer output is deliberately excluded: its section and string names
// change on every build, so it is evidence about this artifact, not a backlog
// item that can be driven to zero.
func hygieneSummary(findings []Finding) []hygieneFinding {
	out := make([]hygieneFinding, 0, 8)
	seen := map[string]struct{}{}
	for _, finding := range findings {
		if finding.Stage != StageStatic || strings.EqualFold(finding.Tool, "stringnalyzer") {
			continue
		}
		indicator := clipUTF8(sanitizeLine(finding.Indicator), 300)
		if indicator == "" {
			continue
		}
		item := hygieneFinding{
			Rule:      clipUTF8(sanitizeLine(finding.Rule), 200),
			Tool:      clipUTF8(sanitizeLine(finding.Tool), 80),
			Severity:  clipUTF8(sanitizeLine(finding.Severity), 20),
			Indicator: indicator,
			Detail:    clipUTF8(sanitizeLine(finding.Detail), 300),
		}
		if len(finding.Sources) > 0 {
			source := finding.Sources[0]
			file := clipUTF8(sanitizeLine(filepath.ToSlash(source.File)), 200)
			item.Source = fmt.Sprintf("%s:%d", file, source.Line)
		}
		key := hygieneKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func hygieneKey(item hygieneFinding) string {
	return strings.ToLower(strings.TrimSpace(item.Rule)) + "|" + strings.ToLower(strings.TrimSpace(item.Indicator))
}

func formatHygiene(item hygieneFinding) string {
	parts := make([]string, 0, 3)
	if item.Severity != "" {
		parts = append(parts, item.Severity)
	}
	if item.Rule != "" {
		parts = append(parts, item.Rule)
	}
	parts = append(parts, item.Indicator)
	line := strings.Join(parts, " ")
	if item.Source != "" {
		line += " (" + item.Source + ")"
	}
	return clipUTF8(line, 300)
}

// hygieneBacklog reads the stable static findings from the payload later
// cycles restore to, not from a rejected attempt whose state was discarded.
func (e *evolver) hygieneBacklog() []hygieneFinding {
	cycle := e.lastExecuting
	if cycle == nil {
		cycle = e.last
	}
	if cycle == nil {
		return nil
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) != nil {
		return nil
	}
	return summary.Hygiene
}

func (e *evolver) hygieneLines() []string {
	items := e.hygieneBacklog()
	out := make([]string, 0, len(items))
	for i, item := range items {
		if i >= 8 {
			break
		}
		out = append(out, formatHygiene(item))
	}
	return out
}

// coverageMissing bounds the analyzer failures carried into a cycle summary.
// A missing analyzer means the cycle cannot be compared with a complete run.
func coverageMissing(coverage TelemetryCoverage) []string {
	out := make([]string, 0, len(coverage.Missing))
	seen := map[string]struct{}{}
	for _, item := range coverage.Missing {
		item = clipUTF8(sanitizeLine(item), 300)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func coverageComplete(summary cycleSummary) bool {
	return len(summary.CoverageMissing) == 0
}

// comparisonBaseline returns the newest payload whose findings can be
// compared. An executing payload with a coverage gap is still the restore
// target, but it cannot reset the finding baseline.
func (e *evolver) comparisonBaseline() *Cycle {
	if e.lastComparable != nil {
		return e.lastComparable
	}
	cycle := e.lastExecuting
	if cycle == nil {
		return nil
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) == nil && !coverageComplete(summary) {
		return nil
	}
	return cycle
}

// comparisonBaselineFor returns the newest verified cycle with complete
// coverage and the same delivered instrumentation as the current one. A cycle
// that was held because its set was new becomes the comparison target as soon
// as the set repeats, so a trade-off that removed findings is not thrown away
// by restoring an older era.
func (e *evolver) comparisonBaselineFor(current *Cycle, summary *cycleSummary) *Cycle {
	if e == nil || summary == nil || summary.Telemetry == nil {
		return e.comparisonBaseline()
	}
	for i := len(e.cycles) - 1; i >= 0; i-- {
		cycle := &e.cycles[i]
		if sameCycle(cycle, current) {
			continue
		}
		if cycle.Execution != executionVerified {
			continue
		}
		var prior cycleSummary
		if json.Unmarshal([]byte(cycle.Summary), &prior) != nil || prior.Telemetry == nil || !coverageComplete(prior) {
			continue
		}
		if sameDelivered(&prior, summary) {
			return cycle
		}
	}
	return e.comparisonBaseline()
}

func sameCycle(a, b *Cycle) bool {
	if a == nil || b == nil {
		return false
	}
	if a.ID != 0 && b.ID != 0 {
		return a.ID == b.ID
	}
	return a.LoopID == b.LoopID && a.Iteration == b.Iteration && a.PayloadKey == b.PayloadKey
}

func (e *evolver) coverageHint() string {
	cycle := e.last
	if cycle == nil {
		cycle = e.lastExecuting
	}
	if cycle == nil {
		return ""
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) != nil || coverageComplete(summary) {
		return ""
	}
	return fmt.Sprintf("Coverage gap in cycle %d: %s. Its finding counts are not comparable; fix the analyzer coverage or treat the residuals as unresolved.",
		cycle.Iteration, clip(strings.Join(summary.CoverageMissing, "; "), 600))
}

// findingCounts is the metric the loop optimizes: real verdicts, high-severity
// findings, static signature hits, and the total for a secondary comparison.
// Sandbox risk scores are not part of this tuple.
type findingCounts struct {
	High   int
	Medium int
	Static int
	Total  int
	// Verdicts are the sandbox's named detections (Defender threat verdicts on
	// Windows, high-confidence Falco alerts on Linux). They are the loop's
	// primary objective and are compared before the weighted finding score.
	Verdicts int
	// Detection and hygiene are disjoint; context findings (build-random
	// stringnalyzer output, coverage/attribution notes) are excluded from the
	// stable comparison.
	DetectionHigh   int
	DetectionMedium int
	HygieneHigh     int
	HygieneMedium   int
	HygieneStatic   int
	StableTotal     int
}

// countFindings classifies one feedback set. Detection and hygiene are the
// stable classes; context findings are counted in the raw totals but never in
// the comparison.
func countFindings(findings []Finding) findingCounts {
	counts := findingCounts{Total: len(findings)}
	for _, finding := range findings {
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		class := classifyFinding(finding)
		switch severity {
		case "critical", "high":
			counts.High++
			switch class {
			case findingDetection:
				counts.DetectionHigh++
			case findingHygiene:
				counts.HygieneHigh++
			}
		case "medium":
			counts.Medium++
			switch class {
			case findingDetection:
				counts.DetectionMedium++
			case findingHygiene:
				counts.HygieneMedium++
			}
		}
		if finding.Stage == StageStatic {
			counts.Static++
		}
		if class == findingHygiene {
			counts.HygieneStatic++
		}
		if class != findingContext {
			counts.StableTotal++
		}
	}
	return counts
}

// findingRegression reports whether current is worse than previous. A new
// detection or hygiene high is always a regression. With the high counts
// unchanged, a verdict change decides: a real detection is the loop's primary
// objective, so losing one is progress even when the medium count rises, and
// gaining one is a regression even when the weighted score improves. Only when
// the verdict count is unchanged does the weighted finding score decide, so a
// material static or hygiene win can outweigh a medium increase; an exact score
// tie falls back to the stable total. Build-random context never decides a
// regression.
func findingRegression(previous, current findingCounts) bool {
	if current.HygieneHigh > previous.HygieneHigh || current.DetectionHigh > previous.DetectionHigh {
		return true
	}
	if current.Verdicts != previous.Verdicts {
		return current.Verdicts > previous.Verdicts
	}
	if score := findingScore(previous, current); score != 0 {
		return score < 0
	}
	return current.StableTotal > previous.StableTotal
}

// findingsImproved is the inverse comparison used by the mechanism gate.
func findingsImproved(previous, current findingCounts) bool {
	return findingRegression(current, previous)
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// finalPayloadVerified treats a check-in from the current payload as healthy
// even when the verification BOF produced no output. LitterBox kills the
// beacon at the capture boundary, so a missing BOF result is not proof of a
// failed payload. The caller passes payloadSeenOnline, never the loop-wide
// agentSeenOnline latch, so a baseline or debugger relaunch cannot vouch for a
// later payload.
func finalPayloadVerified(output string, err error, payloadSeen bool) bool {
	if err == nil && strings.TrimSpace(output) != "" {
		return true
	}
	return payloadSeen
}

// lastVerifiedCycle returns the newest cycle whose payload checked in. The
// finding baseline can lag behind it: a cycle that holds the baseline is still
// the artifact that ran last and the one the final check verifies.
func lastVerifiedCycle(cycles []Cycle) *Cycle {
	for i := len(cycles) - 1; i >= 0; i-- {
		if cycles[i].Execution == executionVerified {
			return &cycles[i]
		}
	}
	return nil
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
				e.payloadSeenOnline.Store(true)
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
		e.payloadSeenOnline.Store(true)
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
			e.payloadSeenOnline.Store(true)
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

// applyExecutionGate tracks the last executing cycle and rolls a non-executing
// cycle back to the last payload that actually checked in.
type executionGate int

const (
	gateUnchanged executionGate = iota
	gateExecuting
	gateBlocked
	gateRestore
	gateRegressed
)

// cycleFindingCounts reads the comparable finding counts from a cycle
// summary. Older rows without the fields count as zero; the total comes from
// the cycle row so it is available even when the summary is absent.
func cycleFindingCounts(cycle *Cycle) findingCounts {
	if cycle == nil {
		return findingCounts{}
	}
	counts := findingCounts{Total: cycle.Findings}
	if strings.TrimSpace(cycle.Summary) == "" {
		return counts
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) != nil {
		return counts
	}
	counts = countsFromSummary(summary, cycle.Findings)
	if cycle.Verdicts > counts.Verdicts {
		// The column is persisted separately from the summary, so an older
		// summary without the verdict list must not hide a real detection.
		counts.Verdicts = cycle.Verdicts
	}
	return counts
}

func summaryFindingCounts(summary cycleSummary, total int) findingCounts {
	return countsFromSummary(summary, total)
}

func countsFromSummary(summary cycleSummary, total int) findingCounts {
	counts := findingCounts{
		High: summary.HighFindings, Medium: summary.MediumFindings,
		Static: summary.StaticFindings, Total: total,
		Verdicts: len(summary.Verdicts),
	}
	if summary.DetectionClassified {
		counts.DetectionHigh = summary.DetectionHigh
		counts.DetectionMedium = summary.DetectionMedium
		counts.HygieneHigh = summary.HygieneHigh
		counts.HygieneMedium = summary.HygieneMedium
		counts.HygieneStatic = summary.HygieneStatic
		counts.StableTotal = summary.StableTotal
		return counts
	}
	// Older summaries have no class split. Treat their high/medium/static
	// counts as the stable set so a resumed loop keeps the previous gate.
	counts.DetectionHigh = counts.High
	counts.DetectionMedium = counts.Medium
	counts.HygieneStatic = counts.Static
	counts.StableTotal = total
	return counts
}

// recordExecution updates the last-executing state without touching the
// source. The coordinator can then run the debugger before deciding whether
// to restore a non-executing cycle.
func (e *evolver) recordExecution(cycle *Cycle, summary cycleSummary) executionGate {
	switch summary.Execution {
	case executionVerified:
		// A verified cycle always becomes the restore target, even when the
		// guest delivered a different instrumentation set. Findings are only
		// compared against a baseline observed under the same set; a changed
		// set starts a new comparison era instead of pinning the loop to its
		// first cycle forever.
		e.regressionBaseline = nil
		previous := e.comparisonBaselineFor(cycle, &summary)
		e.lastComparison = previous
		if previous != nil && previous.ID != 0 && instrumentationComparable(previous, &summary) {
			if findingRegression(cycleFindingCounts(previous), summaryFindingCounts(summary, cycle.Findings)) {
				e.regressionBaseline = previous
				return gateRegressed
			}
		}
		e.lastExecuting = cycle
		e.setPreservedShellcode(summary.Shellcode)
		// A changed delivered set is one observation, not a new era. Keep the
		// source and the executing state, but do not replace the comparison
		// baseline until the next cycle confirms the same set; a one-off
		// RedEdr source loss must not become the baseline, and a trade-off that
		// removed real findings must not be reverted on that first sighting.
		if summary.InstrumentationChanged || !coverageComplete(summary) {
			return gateUnchanged
		}
		e.lastComparable = cycle
		e.restoreErr = nil
		return gateExecuting
	case executionStatic, executionUnverified:
		return gateUnchanged
	case executionOffline:
		// Restore only when a payload has executed before. A loop whose
		// baseline never checked in still goes to the guest debugger and the
		// planner: execution is unproven, not a dead end.
		return gateRestore
	}
	return gateUnchanged
}

// applyExecutionGate is the immediate path used when no debugger is
// configured. The coordinator uses recordExecution and restores only after the
// guest diagnosis.
func (e *evolver) applyExecutionGate(ctx context.Context, cycle *Cycle, summary cycleSummary) {
	gate := e.recordExecution(cycle, summary)
	if cycle != nil {
		e.recordTechniqueMemory(ctx, *cycle, summary, gate)
	}
	switch gate {
	case gateBlocked:
		return
	case gateRestore:
		e.logClass(logging.ClassWarning, "cycle %d did not execute (agent %s offline); restoring payload %s",
			cycle.Iteration, headerOrNone(e.expectedAgentUUID),
			shortPayloadKey(e.lastExecuting.PayloadKey))
		if err := e.restoreExecutingState(ctx); err != nil {
			e.logClass(logging.ClassWarning, "restore incomplete: %v", err)
		}
	}
}

// setPreservedShellcode records the shellcode that belongs to the last
// executing payload. Rotation keeps it so the execution gate can restore a
// state that is known to run.
func (e *evolver) setPreservedShellcode(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	previous := e.preservedShellcode
	e.preservedShellcode = path
	if previous != "" && previous != path {
		e.cleanupGeneratedFile(previous)
	}
}

// rollbackFailedBuild restores the last executing source when an edit breaks a
// build. The model can then try a different change instead of leaving a broken
// tree that aborts every later cycle. A build failure before any payload has
// checked in has no known-good source to restore.
func (e *evolver) rollbackFailedBuild(iteration int, cause error) {
	if e == nil || e.lastExecuting == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.restoreExecutingStateFromBuild(ctx); err != nil {
		e.logClass(logging.ClassWarning,
			"cycle %d build failed; source rollback incomplete: %v", iteration, err)
		return
	}
	causeText := "unknown error"
	if cause != nil {
		causeText = clip(sanitizeLine(cause.Error()), 500)
	}
	e.logClass(logging.ClassWarning,
		"cycle %d build failed; restored source and shellcode from %s: %s",
		iteration, shortPayloadKey(e.lastExecuting.PayloadKey), causeText)
}

// restoreExecutingState rolls the editable source and active shellcode back to
// the last payload whose agent checked in. It returns an error when only part
// of the state could be restored, so the next brief does not claim a working
// baseline.
func (e *evolver) restoreExecutingState(ctx context.Context) error {
	return e.restoreExecutingStateTo(ctx, e.lastExecuting, true)
}

// restoreExecutingStateFromBuild restores after an edit failed to build. The
// failed cycle never produced a payload, so only pending edits are undone; the
// edits that produced the executing baseline must stay in place.
func (e *evolver) restoreExecutingStateFromBuild(ctx context.Context) error {
	return e.restoreExecutingStateTo(ctx, e.lastExecuting, false)
}

// restoreExecutingStateTo restores an explicit baseline. A regression uses the
// last comparable payload, not a newer executing payload whose coverage was
// incomplete.
func (e *evolver) restoreExecutingStateTo(ctx context.Context, baseline *Cycle, revertFailedCycle bool) error {
	if baseline == nil {
		return fmt.Errorf("no executing baseline to restore")
	}
	var errs []error
	lastIteration := 0
	if e.last != nil {
		lastIteration = e.last.Iteration
	}
	if _, err := e.revertPendingEdits(ctx, baseline.PayloadID, lastIteration, baseline.PayloadKey); err != nil {
		e.logClass(logging.ClassWarning, "restore %s pending edits: %v",
			shortPayloadKey(baseline.PayloadKey), err)
		errs = append(errs, fmt.Errorf("pending edits: %w", err))
	}
	failedPayloadID := e.lastPayloadID()
	if revertFailedCycle || (failedPayloadID != 0 && failedPayloadID != baseline.PayloadID) {
		if _, err := e.revertCycleEdits(ctx, failedPayloadID, baseline.PayloadKey); err != nil {
			e.logClass(logging.ClassWarning, "restore %s source: %v",
				shortPayloadKey(baseline.PayloadKey), err)
			errs = append(errs, fmt.Errorf("source: %w", err))
		}
	}
	var summary cycleSummary
	if err := json.Unmarshal([]byte(baseline.Summary), &summary); err != nil {
		errs = append(errs, fmt.Errorf("baseline summary: %w", err))
	} else {
		e.summaryBuildOptions(&summary)
		path := strings.TrimSpace(summary.Shellcode)
		switch {
		case path == "":
			errs = append(errs, fmt.Errorf("baseline has no shellcode path"))
		default:
			info, statErr := os.Stat(path)
			if statErr != nil {
				e.logClass(logging.ClassWarning, "restore shellcode %s: %v", path, statErr)
				errs = append(errs, fmt.Errorf("shellcode %s: %w", path, statErr))
				break
			}
			if !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("shellcode %s is not a regular file", path))
				break
			}
			e.shellcode = path
			e.shellcodeGenerated = summary.ShellcodeGenerated || e.initialShellcodeGenerated
			e.activeProducer = summary.Producer
			e.preservedShellcode = path
			e.logClass(logging.ClassEdit, "restored shellcode %s (producer %s)", path, headerOrNone(summary.Producer))
		}
	}
	e.restoreErr = errors.Join(errs...)
	return e.restoreErr
}

func (e *evolver) linkEdits(ctx context.Context, iteration int, payloadID int64) error {
	_, err := e.db.db.ExecContext(ctx, `
		UPDATE loop_edits SET next_payload_id = ?
		WHERE loop_id = ? AND iteration = ? AND next_payload_id IS NULL AND reverted = 0 AND kind = ?`,
		payloadID, e.cfg.LoopID, iteration, EditKindModel)
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

// executionHint makes a non-executing payload the first thing a resumed session
// sees, because its analyzer score is not evidence about evasion.
func (e *evolver) executionHint() string {
	if e.baselineFailure != "" {
		return "Baseline failure: " + e.baselineFailure +
			". Diagnose it before another cycle; a failed attempt does not consume the cycle budget."
	}
	if e.last != nil {
		var summary cycleSummary
		if json.Unmarshal([]byte(e.last.Summary), &summary) == nil && summary.InstrumentationChanged {
			hint := "Instrumentation gate: " + summary.InstrumentationNote + "."
			if summary.Execution == executionVerified {
				hint += " Compare only against cycles observed under the same delivered set; the source is kept, but this run does not replace the baseline until the next run confirms the same set."
			} else {
				hint += " The cycle did not execute; fix the execution path before editing detection code."
			}
			return hint
		}
	}
	if e.last != nil && e.last.Execution == executionOffline && e.lastExecuting == nil {
		return "Execution gate: the last cycle did not execute and no payload has checked in yet. Execution is unproven; do not compare these findings with an executing cycle. The guest debugger can inspect the sandbox; otherwise fix why the generated agent never checked in before changing detection code."
	}
	if e.last != nil && e.last.Execution == executionOffline && e.lastExecuting != nil {
		if e.restoreErr != nil {
			return fmt.Sprintf("Execution gate: the last cycle did not execute. The source was rolled back to payload %s, but the restore is incomplete: %s. Do not treat the restored state as executable; fix the shellcode or agent path, then run a test cycle.",
				shortPayloadKey(e.lastExecuting.PayloadKey), clip(e.restoreErr.Error(), 400))
		}
		return fmt.Sprintf("Execution gate: the last cycle did not execute. The host restored source and shellcode to payload %s; fix why the generated agent never checked in before changing detection code.",
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
	fmt.Fprintf(&b, "- build options: %s\n", formatBuildOptions(e.buildOptionsSnapshot()))
	if producer := strings.TrimSpace(e.activeProducer); producer != "" {
		fmt.Fprintf(&b, "- producer options (%s): %s\n", producer, formatBuildOptions(e.activeProducerOptions()))
	}
	if backlog := e.hygieneLines(); len(backlog) > 0 {
		fmt.Fprintf(&b, "- static hygiene backlog: %s\n", strings.Join(backlog, " | "))
	}
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
		fmt.Fprintf(&b, "- attempt %d cycle %d (global %d): mechanism=%s findings=%d high=%d medium=%d static=%d verdicts=%d execution=%s network=%d shellcode=%s files=%s\n",
			attempt, cycle.Iteration, global, headerOrNone(summary.Mechanism),
			cycle.Findings, summary.HighFindings, summary.MediumFindings, summary.StaticFindings, cycle.Verdicts,
			headerOrNone(summary.Execution), summary.NetworkEvents,
			headerOrNone(filepath.Base(summary.Shellcode)), joinOrNone(files))
		if len(summary.BuildOptions) > 0 || len(summary.ProducerOptions) > 0 {
			fmt.Fprintf(&b, "  build: %s; producer %s: %s\n",
				formatBuildOptions(summary.BuildOptions), headerOrNone(summary.Producer),
				formatBuildOptions(summary.ProducerOptions))
		}
		if len(summary.CoverageMissing) > 0 {
			fmt.Fprintf(&b, "  coverage: missing %s\n", clip(strings.Join(summary.CoverageMissing, "; "), 400))
		}
		if summary.RecoveredBy != "" {
			fmt.Fprintf(&b, "  recovered_by=%s cause=%s\n", summary.RecoveredBy, clip(sanitizeLine(summary.DebuggerCause), 240))
		}
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

func (e *evolver) needsMoreWork(ctx context.Context) bool {
	if e.last == nil {
		return true
	}
	if e.last.Execution == executionOffline {
		// An execution failure is an execution-gate problem, not a detection
		// result. The plan already restored the last clean baseline, and the
		// debugger policy decides whether the guest is inspected. Another
		// detection cycle cannot fix a payload that never ran.
		return false
	}
	var lastSummary cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &lastSummary) == nil && lastSummary.RecoveredBy != "" {
		// A debugger-recovered cycle proves execution but its sandbox
		// telemetry is not a clean detection baseline.
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
	if finding.Stage == StageTelemetry && actionableTelemetryRule(finding.Rule) {
		switch finding.Severity {
		case "critical", "high", "medium":
			return true
		}
	}
	if len(finding.Sources) == 0 {
		return false
	}
	return finding.Severity == "high" || finding.Severity == "critical" ||
		(finding.Stage == StageTelemetry && finding.Severity == "medium")
}

// actionableTelemetryRule names the RedEdr behaviors an EDR can act on. A
// generic analyzer summary or an instrumentation note is not in this set.
func actionableTelemetryRule(rule string) bool {
	switch strings.ToLower(strings.TrimSpace(rule)) {
	case "telemetry/cross-process-write",
		"telemetry/cross-process-protect",
		"telemetry/cross-process-alloc",
		"telemetry/self-protect",
		"telemetry/thread-suspend",
		"telemetry/remote-thread",
		"telemetry/child-process",
		"telemetry/process-access",
		"telemetry/thread-access",
		"telemetry/map-view",
		"telemetry/file-write",
		"telemetry/network",
		"telemetry/hook",
		"telemetry/memfd",
		"telemetry/ptrace",
		"telemetry/process-vm",
		"telemetry/exec-memory",
		"telemetry/kernel-module",
		"telemetry/namespace",
		"telemetry/writable-exec":
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(rule)), "falco/")
}

// hasActionableFindings reports whether another source edit could plausibly
// remove a remaining finding. Behavioral RedEdr findings are actionable even
// when a literal source match is unavailable; unmatched analyzer summaries
// are residuals rather than work.
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

func (e *evolver) detectionCycleTool() tool.CoreTool {
	description := "Rebuild the module from its current source and detonate the artifact in the sandbox. " +
		"The full feedback, build log, and telemetry are stored in SQLite; this returns a bounded summary. " +
		"The host checks the generated agent with AgentStatus and reports execution=verified, offline, or unverified. " +
		"Call it after a source or design change with one falsifiable prediction; a cycle with no source, build-option, producer, or agent change " +
		"is rejected. The mechanism must match the planner's mechanism. The note is stored in loop memory as the technique recipe, so make it " +
		"actionable: the rule it targets and the implementation detail a later cycle needs."
	mechanisms := []string{
		"baseline", "self-load", "remote-apc", "remote-thread",
		"section-map", "module-stomp", "pe-image", "producer", "producer-swap", "build-flags", "static-hygiene", "other",
	}
	if e.platform() == platformLinux {
		description = "Rebuild stager_linux and detonate its ELF in PenguinBox. " +
			"The C agent PIC and Tracee/Falco telemetry are stored in SQLite; this returns a bounded summary. " +
			"The host checks the generated agent with AgentStatus and reports execution=verified, offline, or unverified. " +
			"Call it after an edit to stager_linux or c_agent, a GenerateAgent rebuild, or a BuildOptions change, with one falsifiable prediction."
		mechanisms = []string{"baseline", "stager", "agent", "producer", "build-flags", "static-hygiene", "other"}
	}
	return tool.Build(tool.Spec{
		Name:        "DetectionCycle",
		Description: description,
		Prompt:      "Build and run one detection cycle.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mechanism": map[string]any{
					"type": "string",
					"enum": mechanisms,
					"description": "Execution mechanism or producer under test. " +
						"Use a different value when you change the loading path; reuse it only when refining the same mechanism. " +
						"producer edits the current producer source; producer-swap changes the wrapper and requires a different active producer. " +
						"Name the concrete mechanism, not an incidental file or import change.",
				},
				"note":       map[string]any{"type": "string", "description": "What this cycle is testing and the actionable recipe for the technique; the host stores it in loop memory."},
				"prediction": map[string]any{"type": "string", "description": "One falsifiable prediction for this cycle: the expected analyzer, event, verdict, or absence of one. The host records it with the observed result."},
			},
			"required": []string{"mechanism"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			if e.sessionCycles.Load() >= 1 {
				return tool.Errorf("one DetectionCycle per plan; return your result and let the planner choose the next hypothesis"), nil
			}
			var args struct {
				Mechanism  string `json:"mechanism"`
				Note       string `json:"note"`
				Prediction string `json:"prediction"`
			}
			_ = json.Unmarshal(raw, &args)
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf(fmt.Sprintf("iteration limit reached (%d); return the final JSON", e.cfg.Iterations)), nil
			}
			mechanism, err := e.bindCycleMechanism(args.Mechanism)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if err := e.cyclePreconditions(mechanism); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			cycle, err := e.runCycle(ctx, clip(args.Note, 500), mechanism, clip(args.Prediction, 500))
			if err != nil {
				e.setCycleError(err)
				if errors.Is(err, ErrSandboxUnreachable) {
					// The sandbox is down; another tool call in this session
					// only repeats the outage. The coordinator retries the same
					// plan after a bounded backoff.
					e.stopSessionAfterCycle()
				}
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			e.sessionCycles.Add(1)
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
					message = "the payload did not execute; the debugger will inspect the guest before the host restores the last executing source and shellcode. Fix agent check-in before changing detection code."
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
				"active_producer":  e.activeProducer,
				"build_options":    e.buildOptionsSnapshot(),
				"producer_options": e.activeProducerOptions(),
				"message":          message,
			}
			if prompts := e.takeOperatorPrompts(); len(prompts) > 0 {
				out["operator_prompts"] = prompts
			}
			data, _ := json.Marshal(out)
			e.stopSessionAfterCycle()
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) inspectFeedbackTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "InspectFeedback",
		Description: "Return the stored feedback for a payload or run: high/static finding counts, top findings " +
			"with source locations, pending stages, telemetry trace, and edits that produced it. The sandbox score is informational. Full feedback stays in SQLite.",
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
		Description: "List recent payloads with their per-payload SQLite view name, artifact hash, high/static finding counts, verdict count, parent payload, and the sandbox score for reference.",
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
		Description: "Replace one exact string in a module source file, or create a new file by passing an empty old_string. " +
			"module selects the payload module (default), a producer module (donut, crystal_pack), or an agent source root (c_agent, go_agent). " +
			"crystal_pack links postex-loader/src and rebuilds it on the next BuildShellcode; donut rebuilds src/. " +
			"The edit is atomic, stored in SQLite with before/after text, and takes effect on the next DetectionCycle.",
		Prompt: "Apply one source edit or create one source file.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":     map[string]any{"type": "string", "description": "Writable source root: the payload module (default), donut, crystal_pack, c_agent, or go_agent."},
				"file":       map[string]any{"type": "string", "description": "Path relative to the module root; its parent directory must already exist."},
				"old_string": map[string]any{"type": "string", "description": "Exact text to replace; must occur once. Empty creates file and requires it not to exist."},
				"new_string": map[string]any{"type": "string", "description": "Replacement text, or the full content when creating a file."},
				"reason":     map[string]any{"type": "string", "description": "Why this edit removes the finding."},
			},
			"required": []string{"file", "new_string"},
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
			if err := e.requireProducerContract(root.Name, args.File); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
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

// requireProducerContract enforces the reading a crystal_pack PICO edit needs
// before the first edit: the module README, the linker spec, and (when the
// knowledge cache is present) one Crystal Palace query. The model otherwise
// edits the resource contract from guesswork.
func (e *evolver) requireProducerContract(module, file string) error {
	if e == nil || !strings.EqualFold(strings.TrimSpace(module), "crystal_pack") {
		return nil
	}
	rel := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(strings.TrimSpace(file), "\\", "/"), "crystal_pack/"))
	if !crystalPICOContractFile(rel) {
		return nil
	}
	var missing []string
	for _, doc := range []string{"README.md", "postex-loader/loader.spec"} {
		if _, ok := e.producerReads.Load(module + "|" + strings.ToLower(doc)); !ok {
			missing = append(missing, "SourceRead module=crystal_pack path="+doc)
		}
	}
	if e.knowledge != nil {
		if _, ok := e.producerQueries.Load(module); !ok {
			missing = append(missing, `KnowledgeSearch "Crystal Palace PICO postex loader resource markers"`)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("crystal_pack PICO edits require the module contract first: %s", strings.Join(missing, "; "))
}

func crystalPICOContractFile(rel string) bool {
	switch rel {
	case "build.sh", "common.mk", "makefile":
		return true
	}
	return strings.HasPrefix(rel, "postex-loader/") || strings.HasPrefix(rel, "crystalpalace/")
}

func crystalPalaceQuery(query string) bool {
	query = strings.ToLower(query)
	if !strings.Contains(query, "crystal") {
		return false
	}
	return strings.Contains(query, "palace") || strings.Contains(query, "pico") || strings.Contains(query, "postex")
}

type editResult struct {
	Module  string `json:"module"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Bytes   int    `json:"bytes"`
	Created bool   `json:"created,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// forbiddenLoaderMechanisms name mechanisms that add an explicit detection
// surface instead of an anonymous mapping. A memfd is a named kernel object
// with its own sandbox verdict, so the host rejects an edit that introduces
// one even when the model's hypothesis says otherwise. Removal remains allowed.
var forbiddenLoaderMechanisms = []string{"sys_memfd_create", "memfd_create(", "__nr_memfd_create"}

func introducesForbiddenLoaderMechanism(oldText, newText string) string {
	oldLower := strings.ToLower(oldText)
	newLower := strings.ToLower(newText)
	for _, token := range forbiddenLoaderMechanisms {
		if strings.Contains(newLower, token) && !strings.Contains(oldLower, token) {
			return token
		}
	}
	return ""
}

func (e *evolver) applyEdit(ctx context.Context, root sourceRoot, file, oldText, newText, reason string) (editResult, error) {
	if newText == "" {
		return editResult{}, fmt.Errorf("new_string is required")
	}
	creating := oldText == ""
	if creating {
		if len(newText) > maxSourceFileBytes {
			return editResult{}, fmt.Errorf("new file exceeds the %d byte source bound", maxSourceFileBytes)
		}
	} else {
		if oldText == newText {
			return editResult{}, fmt.Errorf("old_string and new_string are identical")
		}
		if len(oldText) > 16<<10 || len(newText) > 16<<10 {
			return editResult{}, fmt.Errorf("edit text exceeds 16 KiB")
		}
	}
	if token := introducesForbiddenLoaderMechanism(oldText, newText); token != "" {
		return editResult{}, fmt.Errorf("refusing to introduce %s: a memfd is a named kernel object and an explicit detection signal, not an evasion win", token)
	}
	var updated sourceWrite
	var err error
	if creating {
		updated, err = createSourceFile(root, file, newText)
	} else {
		updated, err = writeSourceFile(root, file, oldText, newText)
	}
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
		if creating {
			if removeErr := os.Remove(updated.Path); removeErr != nil {
				return editResult{}, fmt.Errorf("save edit: %w (remove %s failed: %v)", err, file, removeErr)
			}
		} else if restoreErr := restoreSourceFile(updated.Path, updated.Original); restoreErr != nil {
			return editResult{}, fmt.Errorf("save edit: %w (restore %s failed: %v)", err, file, restoreErr)
		}
		return editResult{}, fmt.Errorf("save edit: %w", err)
	}
	e.logClass(logging.ClassEdit, "%s/%s:%d (%s): %s", root.Name, file, updated.Line, reason, clip(newText, 160))
	message := "edit applied; call DetectionCycle to rebuild and detonate"
	if creating {
		message = "file created; call DetectionCycle to rebuild and detonate"
	}
	return editResult{
		Module: root.Name, File: file, Line: updated.Line, Bytes: len(updated.Updated),
		Created: creating, Reason: reason, Message: message,
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
	file = sourceRelativeFile(root, file)
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

func sourceRelativeFile(root sourceRoot, file string) string {
	file = strings.TrimSpace(strings.ReplaceAll(file, "\\", "/"))
	if prefix, rest, ok := strings.Cut(file, "/"); ok && strings.EqualFold(prefix, root.Name) {
		file = rest
	}
	return file
}

// createSourceFile writes a new file inside a writable root. The file must not
// exist and its parent directory must already exist, so a create can never
// replace source.
func createSourceFile(root sourceRoot, file, content string) (sourceWrite, error) {
	if !root.Writable {
		return sourceWrite{}, fmt.Errorf("source root %s is read-only", root.Name)
	}
	file = sourceRelativeFile(root, file)
	path, err := newSourcePath(root, file)
	if err != nil {
		return sourceWrite{}, err
	}
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return sourceWrite{}, fmt.Errorf("%s already exists; edit it with old_string and new_string", file)
		}
		return sourceWrite{}, fmt.Errorf("create %s: %w", file, err)
	}
	removeOnError := func(cause error) (sourceWrite, error) {
		_ = handle.Close()
		_ = os.Remove(path)
		return sourceWrite{}, cause
	}
	if _, err := handle.WriteString(content); err != nil {
		return removeOnError(fmt.Errorf("write %s: %w", file, err))
	}
	if err := handle.Sync(); err != nil {
		return removeOnError(fmt.Errorf("sync %s: %w", file, err))
	}
	if err := handle.Close(); err != nil {
		_ = os.Remove(path)
		return sourceWrite{}, fmt.Errorf("close %s: %w", file, err)
	}
	return sourceWrite{Updated: content, Line: 1, Path: path}, nil
}

// newSourcePath resolves a not-yet-existing file inside the root. The parent
// directory is resolved through symlinks and checked against the root, so a
// create cannot escape it.
func newSourcePath(root sourceRoot, file string) (string, error) {
	if file == "" || !analystSourcePath.MatchString(file) {
		return "", fmt.Errorf("invalid source path")
	}
	rootReal, err := filepath.EvalSymlinks(root.Dir)
	if err != nil {
		return "", fmt.Errorf("resolve module directory: %w", err)
	}
	clean := filepath.Clean(filepath.FromSlash(file))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	parent := filepath.Dir(clean)
	parentReal, err := filepath.EvalSymlinks(filepath.Join(rootReal, parent))
	if err != nil {
		return "", fmt.Errorf("resolve source directory: %w", err)
	}
	rel, err := filepath.Rel(rootReal, parentReal)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	path := filepath.Join(parentReal, filepath.Base(clean))
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists; edit it with old_string and new_string", file)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat %s: %w", file, err)
	}
	return path, nil
}

// removeCreatedSourceFile deletes a file this loop created. It refuses when
// the file no longer matches the recorded content, so a hand edit is not lost.
func removeCreatedSourceFile(root sourceRoot, file, expected string) (string, error) {
	if !root.Writable {
		return "", fmt.Errorf("source root %s is read-only", root.Name)
	}
	file = sourceRelativeFile(root, file)
	path, err := analystPath(root.Dir, file)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", file, err)
	}
	if string(data) != expected {
		return "", fmt.Errorf("%s changed since it was created; refusing to delete it", file)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("remove %s: %w", file, err)
	}
	return path, nil
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
	counts := countFindings(feedback.Findings)
	out := map[string]any{
		"run_id": runID, "payload_key": payloadKey,
		"findings": len(feedback.Findings), "high_findings": counts.High,
		"medium_findings": counts.Medium, "static_findings": counts.Static,
		"detection_high": counts.DetectionHigh, "detection_medium": counts.DetectionMedium,
		"hygiene_high": counts.HygieneHigh, "hygiene_medium": counts.HygieneMedium,
		"hygiene_static": counts.HygieneStatic,
		"source_edits":   len(feedback.SourceEdits),
		"score":          feedback.Score, "level": feedback.Level,
	}
	if counts.HygieneStatic > 0 {
		out["hygiene"] = hygieneSummary(feedback.Findings)
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
