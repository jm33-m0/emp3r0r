package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
)

const (
	defaultEvolveIterations = 3
	defaultEvolveTurns      = 60
	maxEvolveEdits          = 12
	maxEvolveBuildLog       = 8 << 20
)

// EvolveConfig drives an autonomous detection -> feedback -> edit -> rebuild
// loop for one local payload module.
type EvolveConfig struct {
	LoopID     string
	Module     string
	ModuleDir  string
	Shellcode  string
	SandboxURL string
	StoreRoot  string
	// Process is passed to the loader build when non-empty. Leave it empty to
	// let the module's own default control the sacrificial process, so a source
	// edit to that default changes the next build.
	Process    string
	Format     string
	Inject     string
	SMW        string
	Stages     []string
	Iterations int
	Turns      int
	// Provider and Model override the environment; tests use a scripted
	// provider, production uses EMP3R0R_DETECTION_* and the usual API key.
	Provider llm.Provider
	Model    string
	// RetryBase is the first recovery delay; it backs off to 30 seconds.
	RetryBase time.Duration
	Logf      func(string)
	// Build overrides the module build; tests use it to avoid the C toolchain.
	Build func(moduleDir string, flags map[string]string) (string, error)
}

// EvolveResult is the final answer plus the cycles the agent ran.
type EvolveResult struct {
	LoopID string          `json:"loop_id"`
	Answer json.RawMessage `json:"answer"`
	Report string          `json:"report"`
	Cycles []Cycle         `json:"cycles"`
	Last   *Cycle          `json:"last,omitempty"`
}

type evolver struct {
	cfg    EvolveConfig
	loop   *Loop
	db     *TelemetryDB
	logf   func(string)
	iter   int
	edits  int
	last   *Cycle
	cycles []Cycle
}

func (e *evolver) log(format string, args ...any) {
	e.logf(fmt.Sprintf(format, args...))
}

func (e *evolver) waitSandbox(ctx context.Context) (Health, error) {
	for attempt := 0; ; attempt++ {
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
		if !e.recover(ctx, attempt, "sandbox", fmt.Errorf("%s is unreachable: %s", health.URL, reason)) {
			return Health{}, ctx.Err()
		}
	}
}

// recover logs a failure and waits before the caller retries. It returns false
// only when the context is done; the loop never exits on a transient failure.
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
	e.log("%s failed (attempt %d): %v; retrying in %s", what, attempt+1, err, delay)
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
	e := &evolver{cfg: cfg, loop: loop, db: loop.Telemetry, logf: cfg.Logf}
	if e.logf == nil {
		e.logf = func(string) {}
	}
	e.log("detection loop %s: module=%s model=%s shellcode=%s", cfg.LoopID, cfg.Module, model, cfg.Shellcode)
	provider = &loggingProvider{next: provider, logf: e.logf}

	var baseline Cycle
	for attempt := 0; ; attempt++ {
		baseline, err = e.runCycle(ctx, "baseline")
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !e.recover(ctx, attempt, "baseline", err) {
			return nil, ctx.Err()
		}
	}
	e.last = &baseline
	baselineJSON, _ := json.Marshal(baseline)

	system := evolveSystemPrompt
	prompt := fmt.Sprintf(`Loop ID: %s
Module: %s
Module source: %s
Shellcode: %s
Baseline cycle: %s

Continue the loop. The full feedback, builds, and telemetry are in SQLite.
Use InspectFeedback, Payloads, ComparePayloads, TelemetryQuery, and the source
tools. Apply minimal source edits with EditSource, then call DetectionCycle.
A zero Defender verdict count is not success. Minimize the remaining finding
count and risk score as far as possible. High static findings (for example
.rdata entropy), medium telemetry findings (child process, network, unbacked
execute), and import findings all count. Do not stop just because verdicts are
zero, and do not game static checks with size-inflating encoding or padding.

Use every telemetry source, not only Defender verdicts. The events table now
carries ETW, ETW-TI memory operations, kernel callbacks, ntdll hooks, PEB and
loaded-DLL queries, and Defender behavior. Each row has actor_pid, target_pid,
operation, category, signal, payload_role, src/dst endpoints, protection,
status, and the top kernel stack frames. payload_role is payload,
payload-child, payload-target, payload-scan, ambient, or unknown. Treat
signal='noise' and signal='baseline' as evidence only, not as findings. Query
the findings table for the deterministic result and the payload view for the
raw events, then compare payloads after every edit. If coverage.missing is not
empty, say which source degraded. Stop only at the iteration limit, or when no
actionable high/medium finding remains and every residual is explained with
evidence. Return the final JSON object.`,
		cfg.LoopID, cfg.Module, cfg.ModuleDir, cfg.Shellcode, baselineJSON)

	var (
		text     string
		answer   map[string]any
		parseErr error
	)
	for attempt := 0; ; attempt++ {
		text, err = agentcore.Run(ctx, agentcore.Options{
			Provider:               provider,
			SystemPrompt:           []string{system},
			Tools:                  e.tools(),
			PermissionMode:         permission.ModeDontAsk,
			Hooks:                  e.hooks(),
			WorkingDir:             cfg.ModuleDir,
			MaxTurns:               cfg.Turns,
			MaxTokens:              4096,
			DisableBackgroundTasks: true,
			Compaction:             &compaction.Config{ContextWindow: 200000, MaxOutputTokens: 4096, KeepRecent: 8},
			OnWarn:                 e.logf,
		}, prompt)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if !e.recover(ctx, attempt, "agent session", err) {
				return nil, ctx.Err()
			}
			prompt = e.resumePrompt(cfg, "the previous agent session failed")
			continue
		}
		e.log("agent final text: %s", clip(text, 8000))
		answer, parseErr = parseAnalystAnswer(text)
		if parseErr == nil {
			if e.iter < cfg.Iterations && e.needsMoreWork(ctx) {
				e.log("agent stopped with work remaining; resuming")
				prompt = e.resumePrompt(cfg, "real verdicts or high telemetry findings remain")
				continue
			}
			break
		}
		if e.iter < cfg.Iterations {
			e.log("agent stopped without the required JSON; resuming")
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
	answer["cycles"] = e.cycles
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, fmt.Errorf("encode loop answer: %w", err)
	}
	edits := e.loopEdits(ctx, cfg.LoopID)
	report := RenderLoopReport(answer, e.cycles, edits)
	reportPath, reportErr := writeLoopReport(cfg.StoreRoot, cfg.LoopID, report)
	if reportErr != nil {
		e.log("write report: %v", reportErr)
	} else {
		e.log("final report: %s", reportPath)
	}
	e.log("%s", report)
	if _, err := e.db.db.ExecContext(ctx, `
		INSERT INTO loop_results(loop_id, answer, report, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(loop_id) DO UPDATE SET answer = excluded.answer, report = excluded.report, created_at = excluded.created_at`,
		cfg.LoopID, string(encoded), report, time.Now().UTC().UnixMilli()); err != nil {
		return nil, fmt.Errorf("save loop result: %w", err)
	}
	return &EvolveResult{LoopID: cfg.LoopID, Answer: encoded, Report: report, Cycles: e.cycles, Last: e.last}, nil
}

func normalizeEvolveConfig(cfg *EvolveConfig) error {
	cfg.Module = strings.ToLower(strings.TrimSpace(cfg.Module))
	if cfg.Module == "" {
		cfg.Module = "loader_windows"
	}
	if !Covered(cfg.Module) {
		return fmt.Errorf("module %q is not covered by the detection loop", cfg.Module)
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
	if cfg.Inject == "" {
		cfg.Inject = "apc"
	}
	if cfg.SMW == "" {
		cfg.SMW = "on"
	}
	if len(cfg.Stages) == 0 {
		cfg.Stages = []string{"static", "dynamic"}
	}
	static, dynamic, err := parseEvolveStages(cfg.Stages)
	if err != nil {
		return err
	}
	if !dynamic {
		return fmt.Errorf("the autonomous loop requires the dynamic stage for per-payload telemetry")
	}
	_ = static
	if cfg.Iterations <= 0 {
		cfg.Iterations = defaultEvolveIterations
	}
	if cfg.Iterations > 10 {
		cfg.Iterations = 10
	}
	if cfg.Turns <= 0 {
		cfg.Turns = defaultEvolveTurns
	}
	if cfg.Turns > 120 {
		cfg.Turns = 120
	}
	return nil
}

func parseEvolveStages(stages []string) (static, dynamic bool, err error) {
	for _, stage := range stages {
		switch strings.ToLower(strings.TrimSpace(stage)) {
		case "static":
			static = true
		case "dynamic":
			dynamic = true
		case "":
		default:
			return false, false, fmt.Errorf("unknown stage %q", stage)
		}
	}
	return static, dynamic, nil
}

type cycleSummary struct {
	LoopID       string          `json:"loop_id"`
	Iteration    int             `json:"iteration"`
	PayloadKey   string          `json:"payload_key"`
	PayloadTable string          `json:"payload_table"`
	RunID        string          `json:"run_id"`
	SHA256       string          `json:"sha256"`
	Score        float64         `json:"score"`
	Level        string          `json:"level,omitempty"`
	Findings     int             `json:"findings"`
	Verdicts     []string        `json:"verdicts,omitempty"`
	TraceID      int64           `json:"trace_id,omitempty"`
	Events       int             `json:"telemetry_events"`
	Telemetry    *TelemetryStats `json:"telemetry,omitempty"`
	SourceEdits  int             `json:"source_edits"`
	TopFindings  []string        `json:"top_findings,omitempty"`
	BuildTail    []string        `json:"build_tail,omitempty"`
	Edits        []EditRecord    `json:"edits,omitempty"`
	Note         string          `json:"note,omitempty"`
}

func (e *evolver) runCycle(ctx context.Context, note string) (Cycle, error) {
	iteration := e.iter + 1
	e.edits = 0

	if _, err := e.waitSandbox(ctx); err != nil {
		return Cycle{}, err
	}

	flags := map[string]string{
		"shellcode": e.cfg.Shellcode,
		"format":    e.cfg.Format,
		"arch":      "x64",
		"inject":    e.cfg.Inject,
		"smw":       e.cfg.SMW,
	}
	if e.cfg.Process != "" {
		flags["process"] = e.cfg.Process
	}
	e.log("cycle %d: building %s", iteration, e.cfg.Module)
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
	e.log("%s", buildLog)
	if buildErr != nil {
		return Cycle{}, fmt.Errorf("build %s: %w", e.cfg.Module, buildErr)
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
	if err := e.loop.Store.RecordArtifact(e.cfg.Module, artifact); err != nil {
		return Cycle{}, err
	}
	plan, err := e.loop.CreatePlan(ctx, Request{
		Module: e.cfg.Module, ModuleDir: e.cfg.ModuleDir,
		ArtifactPath: artifact.Path,
	})
	if err != nil {
		return Cycle{}, err
	}
	static, dynamic, _ := parseEvolveStages(e.cfg.Stages)
	parentKey := ""
	if e.last != nil {
		parentKey = e.last.PayloadKey
	}
	var (
		run    Run
		runErr error
	)
	for attempt := 0; ; attempt++ {
		runCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		run, runErr = e.loop.RunPlan(runCtx, plan, RunOptions{
			Static: static, Dynamic: dynamic, ApproveExecution: true,
			Timeout: 10 * time.Minute, ParentKey: parentKey,
		})
		cancel()
		if runErr == nil && run.Telemetry != nil && run.Telemetry.Attribution != "unknown" {
			break
		}
		if ctx.Err() != nil {
			return Cycle{}, ctx.Err()
		}
		reason := runErr
		if reason == nil {
			var stageErrors []string
			for _, stage := range run.Stages {
				if stage.Status == "error" || stage.Error != "" {
					stageErrors = append(stageErrors, stage.Tool+": "+stage.Error)
				}
			}
			if run.Telemetry != nil && run.Telemetry.Attribution == "unknown" {
				reason = fmt.Errorf("telemetry has no payload PEB (%s) notes=%v",
					strings.Join(stageErrors, "; "), run.Notes)
			} else {
				reason = fmt.Errorf("dynamic run produced no telemetry (%s) notes=%v",
					strings.Join(stageErrors, "; "), run.Notes)
			}
		}
		if !e.recover(ctx, attempt, "detection run", reason) {
			return Cycle{}, ctx.Err()
		}
	}
	feedback := BuildFeedback(run)
	if err := e.linkEdits(ctx, iteration, run.Telemetry.PayloadID); err != nil {
		e.log("link edits: %v", err)
	}
	e.iter = iteration
	summary := summarizeCycle(e.cfg.LoopID, iteration, run, feedback, buildLog, note)
	summaryJSON, _ := json.Marshal(summary)
	cycle := Cycle{
		LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: run.Telemetry.PayloadID,
		PayloadKey: run.Telemetry.PayloadKey, RunID: run.ID, Score: feedback.Score,
		Level: feedback.Level, Findings: len(feedback.Findings),
		Verdicts: len(summary.Verdicts), TraceID: run.Telemetry.TraceID,
		Summary: string(summaryJSON), CreatedAt: time.Now().UTC(),
	}
	if _, err := e.db.SaveCycle(ctx, cycle); err != nil {
		return Cycle{}, err
	}
	if body, err := json.Marshal(feedback); err == nil {
		if err := e.db.SaveFeedback(ctx, FeedbackRecord{
			LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: run.Telemetry.PayloadID,
			RunID: run.ID, Body: body,
		}); err != nil {
			e.log("save feedback: %v", err)
		}
	}
	if err := e.db.SaveBuild(ctx, BuildRecord{
		LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: run.Telemetry.PayloadID,
		Artifact: artifact.Path, SHA256: artifact.SHA256, Log: buildLog,
	}); err != nil {
		e.log("save build: %v", err)
	}
	e.last = &cycle
	e.cycles = append(e.cycles, cycle)
	e.log("cycle %d: payload=%s sha=%s score=%.2f verdicts=%v findings=%d",
		iteration, cycle.PayloadKey, shortSHA(artifact.SHA256), cycle.Score, summary.Verdicts, cycle.Findings)
	return cycle, nil
}

func summarizeCycle(loopID string, iteration int, run Run, feedback Feedback, buildLog, note string) cycleSummary {
	summary := cycleSummary{
		LoopID: loopID, Iteration: iteration, RunID: run.ID,
		SHA256: run.Plan.Artifact.SHA256, Score: feedback.Score, Level: sanitizeLine(feedback.Level),
		Findings: len(feedback.Findings), SourceEdits: len(feedback.SourceEdits),
		Note: note,
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
			}
		}
	}
	for _, finding := range feedback.Findings {
		summary.TopFindings = append(summary.TopFindings,
			fmt.Sprintf("%s %s %s", sanitizeLine(finding.Severity), sanitizeLine(finding.Rule),
				sanitizeLine(finding.Indicator)))
		if len(summary.TopFindings) >= 8 {
			break
		}
	}
	lines := strings.Split(strings.TrimSpace(buildLog), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	summary.BuildTail = lines
	return summary
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func (e *evolver) linkEdits(ctx context.Context, iteration int, payloadID int64) error {
	_, err := e.db.db.ExecContext(ctx, `
		UPDATE loop_edits SET next_payload_id = ?
		WHERE loop_id = ? AND iteration = ? AND next_payload_id IS NULL`,
		payloadID, e.cfg.LoopID, iteration)
	return err
}

func (e *evolver) loopEdits(ctx context.Context, loopID string) []EditRecord {
	rows, err := e.db.db.QueryContext(ctx, `
		SELECT loop_id, iteration, COALESCE(payload_id, 0), file, old, new, reason, created_at
		FROM loop_edits WHERE loop_id = ? ORDER BY id`, loopID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []EditRecord
	for rows.Next() {
		var record EditRecord
		var created int64
		if err := rows.Scan(&record.LoopID, &record.Iteration, &record.PayloadID,
			&record.File, &record.Old, &record.New, &record.Reason, &created); err != nil {
			return out
		}
		record.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, record)
	}
	return out
}

func writeLoopReport(storeRoot, loopID, report string) (string, error) {
	if strings.TrimSpace(storeRoot) == "" {
		return "", fmt.Errorf("store root is empty")
	}
	dir := filepath.Join(storeRoot, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := sanitizeName(loopID)
	if name == "" {
		name = "loop"
	}
	path := filepath.Join(dir, name+".md")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
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
Full feedback, builds, and telemetry are in SQLite. Inspect the latest payload,
apply any remaining source edit, and call DetectionCycle. Do not repeat work
that is already done. Keep reducing actionable findings; zero verdicts alone is
not completion. Return the required JSON object when the loop is complete.`,
		cfg.LoopID, reason, latest)
}

func (e *evolver) needsMoreWork(ctx context.Context) bool {
	if e.last == nil {
		return true
	}
	if e.last.Verdicts > 0 {
		return true
	}
	var body string
	if err := e.db.db.QueryRowContext(ctx, `
		SELECT body FROM loop_feedback WHERE loop_id = ? AND iteration = ?
		ORDER BY id DESC LIMIT 1`, e.last.LoopID, e.last.Iteration).Scan(&body); err != nil {
		return false
	}
	var feedback Feedback
	if json.Unmarshal([]byte(body), &feedback) != nil {
		return false
	}
	for _, finding := range feedback.Findings {
		if finding.Severity == "high" || finding.Severity == "critical" {
			return true
		}
		if finding.Stage == StageTelemetry && finding.Severity == "medium" {
			return true
		}
	}
	return false
}

// --- Norma agent -----------------------------------------------------------

func (e *evolver) hooks() *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, event hook.Event) hook.Result {
		switch event.ToolName {
		case "SourceList", "SourceRead", "SourceSearch", "TelemetryQuery",
			"InspectFeedback", "Payloads", "ComparePayloads", "DetectionCycle", "EditSource":
			return hook.Result{}
		}
		return hook.Result{Decision: "block", Message: "tool is not part of the detection loop"}
	})
}

func (e *evolver) tools() []tool.CoreTool {
	tools := []tool.CoreTool{
		analystListTool(e.cfg.ModuleDir),
		analystReadTool(e.cfg.ModuleDir),
		analystSearchTool(e.cfg.ModuleDir),
		analystTelemetryTool(e.db),
		e.detectionCycleTool(),
		e.inspectFeedbackTool(),
		e.payloadsTool(),
		e.comparePayloadsTool(),
		e.editSourceTool(),
	}
	return tools
}

func (e *evolver) detectionCycleTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "DetectionCycle",
		Description: "Rebuild the module from its current source and detonate the artifact in LitterBox. " +
			"The full feedback, build log, and telemetry are stored in SQLite; this returns a bounded summary. " +
			"Call it after applying source edits.",
		Prompt: "Build and run one detection cycle.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"note": map[string]any{"type": "string", "description": "What this cycle is testing."},
			},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Note string `json:"note"`
			}
			_ = json.Unmarshal(raw, &args)
			if e.iter >= e.cfg.Iterations {
				return tool.Errorf(fmt.Sprintf("iteration limit reached (%d); return the final JSON", e.cfg.Iterations)), nil
			}
			cycle, err := e.runCycle(ctx, clip(args.Note, 500))
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			edits, _ := e.editsForPayload(ctx, cycle.PayloadKey)
			payload, _ := e.db.PayloadByKey(ctx, cycle.PayloadKey)
			var summary any
			_ = json.Unmarshal([]byte(cycle.Summary), &summary)
			out := map[string]any{
				"cycle":   cycle,
				"summary": summary,
				"payload": payload,
				"edits":   edits,
				"message": "full feedback and build log are in SQLite; use InspectFeedback or TelemetryQuery",
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
			edits, _ := e.editsForPayload(ctx, payloadKey)
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
			"The edit is atomic, stored in SQLite with before/after text, and takes effect on the next DetectionCycle.",
		Prompt: "Apply one source edit.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
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
				File      string `json:"file"`
				OldString string `json:"old_string"`
				NewString string `json:"new_string"`
				Reason    string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.iter >= e.cfg.Iterations {
				return tool.Errorf("iteration limit reached; the edit could not be built or tested"), nil
			}
			if e.edits >= maxEvolveEdits {
				return tool.Errorf("edit limit reached for this cycle"), nil
			}
			result, err := e.applyEdit(ctx, args.File, args.OldString, args.NewString, args.Reason)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(result)
			return tool.Text(string(data)), nil
		},
	})
}

type editResult struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Bytes   int    `json:"bytes"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

func (e *evolver) applyEdit(ctx context.Context, file, oldText, newText, reason string) (editResult, error) {
	if oldText == "" || newText == "" {
		return editResult{}, fmt.Errorf("old_string and new_string are required")
	}
	if oldText == newText {
		return editResult{}, fmt.Errorf("old_string and new_string are identical")
	}
	if len(oldText) > 16<<10 || len(newText) > 16<<10 {
		return editResult{}, fmt.Errorf("edit text exceeds 16 KiB")
	}
	path, err := analystPath(e.cfg.ModuleDir, file)
	if err != nil {
		return editResult{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return editResult{}, fmt.Errorf("read %s: %w", file, err)
	}
	if strings.Count(string(data), oldText) != 1 {
		return editResult{}, fmt.Errorf("%s: old_string must occur exactly once", file)
	}
	index := strings.Index(string(data), oldText)
	line := strings.Count(string(data[:index]), "\n") + 1
	updated := strings.Replace(string(data), oldText, newText, 1)
	info, err := os.Stat(path)
	if err != nil {
		return editResult{}, fmt.Errorf("stat %s: %w", file, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".detect-edit-*")
	if err != nil {
		return editResult{}, fmt.Errorf("create edit file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return editResult{}, fmt.Errorf("chmod edit file: %w", err)
	}
	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return editResult{}, fmt.Errorf("write edit file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return editResult{}, fmt.Errorf("sync edit file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return editResult{}, fmt.Errorf("close edit file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return editResult{}, fmt.Errorf("replace %s: %w", file, err)
	}
	payloadID := int64(0)
	if e.last != nil {
		payloadID = e.last.PayloadID
	}
	iteration := e.iter + 1
	if err := e.db.SaveEdit(ctx, EditRecord{
		LoopID: e.cfg.LoopID, Iteration: iteration, PayloadID: payloadID,
		File: file, Old: oldText, New: newText, Reason: reason,
	}); err != nil {
		e.log("save edit: %v", err)
	}
	e.edits++
	e.log("edit %s:%d (%s): %s", file, line, reason, clip(newText, 160))
	return editResult{
		File: file, Line: line, Bytes: len(updated), Reason: reason,
		Message: "edit applied; call DetectionCycle to rebuild and detonate",
	}, nil
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

func (e *evolver) editsForPayload(ctx context.Context, payloadKey string) ([]EditRecord, error) {
	if payloadKey == "" {
		return nil, nil
	}
	id, err := payloadIDByKey(ctx, e.db.db, payloadKey)
	if err != nil || id == 0 {
		return nil, err
	}
	rows, err := e.db.db.QueryContext(ctx, `
		SELECT loop_id, iteration, COALESCE(payload_id, 0), file, old, new, reason, created_at
		FROM loop_edits WHERE next_payload_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EditRecord
	for rows.Next() {
		var record EditRecord
		var created int64
		if err := rows.Scan(&record.LoopID, &record.Iteration, &record.PayloadID,
			&record.File, &record.Old, &record.New, &record.Reason, &created); err != nil {
			return nil, err
		}
		record.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, record)
	}
	return out, rows.Err()
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
- Attribution columns matter: actor_pid performed the operation, pid is the
  subject, target_pid is the target or child, payload_role says whether the
  event belongs to the payload, a child, the payload as a target, a Defender
  scan, or ambient traffic. signal is signal/verdict/scan/info/baseline/noise.
- Categories include process, image, file, network, audit, thread, defender,
  query, module, hook, and memory (ETW-TI). ETW-TI rows carry operation,
  protection, size, bytes, status, and stack. Hook rows carry the intercepted
  Nt* API. Ambient MsMpEng events are stored but are not payload actions.

Work loop:
1. Inspect the baseline and identify a real defender verdict or a high/medium
   telemetry finding that maps to module source. Use the findings table first,
   then the payload view for the events behind a finding.
2. Read the relevant source and trace the detection to its cause. Prefer a
   minimal, grounded EditSource call when that removes the detection. A design
   change is allowed and expected when the current design is what the sandbox
   detects: add, remove, split, merge, or replace source files and components,
   restructure data flow, change the loading or call path, and rewrite the
   implementation. Do not preserve a detected design just because it already
   exists, and do not settle for renaming, reordering, or hiding the same
   behavior. Update every default that controls the behavior, not a dead copy.
   Use multiple EditSource calls when a redesign needs them.
3. Call DetectionCycle. It rebuilds from the current source and returns a
   bounded summary plus the new payload key.
4. ComparePayloads the previous and new payloads. If the real verdict is gone,
   check for replacement findings; otherwise iterate.
5. Do not edit tests, generated artifacts, or files outside the module. Do not
   remove externally required functionality or invalidate config.json, the
   documented flags, opsec metadata, or the build entrypoint. Internal APIs,
   file layout, and component boundaries may change. A redesign that preserves
   required behavior is not a weakened build contract. Do not stop at the first
   lower score: the sandbox risk score has known false positives; read the SQL
   verdict rows.

Stop when no real defender verdict remains and no high or medium telemetry
finding remains, or when the iteration limit is reached. Return one JSON object:
{"summary":"what changed and why","verdicts_before":["..."],"verdicts_after":["..."],"edits":[{"file":"...","reason":"..."}],"residual":["..."],"cycles":<number>}

The host will store your answer. Be concise.`

// loggingProvider forwards Norma's normalized stream events unchanged while
// writing model text, thinking, and tool calls to the loop log. agentcore.Run
// itself returns only the final assistant text, so without this wrapper the log
// shows tools' side effects but no model output.
type loggingProvider struct {
	next     llm.Provider
	logf     func(string)
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
	if text := strings.TrimSpace(p.text.String()); text != "" {
		p.logf("[model] " + text)
	}
	p.text.Reset()
}

func (p *loggingProvider) flushThinking() {
	if text := strings.TrimSpace(p.think.String()); text != "" {
		p.logf("[thinking] " + text)
	}
	p.think.Reset()
}

func (p *loggingProvider) flushTool() {
	if p.toolName == "" {
		p.tool.Reset()
		return
	}
	args := strings.TrimSpace(p.tool.String())
	if args == "" {
		p.logf("[tool] " + p.toolName)
	} else {
		p.logf("[tool] " + p.toolName + " " + args)
	}
	p.toolName = ""
	p.tool.Reset()
}
