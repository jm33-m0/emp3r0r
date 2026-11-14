package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	maxDetectionArtifactPath = 4096
	maxDetectionRunID        = 160
	maxDetectionProfile      = 128
	maxDetectionSQL          = 20 << 10
	maxDetectionTelemetryURL = 4096
	// detectionBuildBudget bounds the passive test that runs inline after a
	// loader_windows or stager_linux build.
	detectionBuildBudget = 3 * time.Minute
	// detectionAnalyzeBudget bounds one analyst review.
	detectionAnalyzeBudget = 4 * time.Minute
)

// detectionTools returns the detection planning, run, and feedback tools.
func (a *Actions) detectionTools() map[string]Tool {
	return map[string]Tool{
		"detection_plan": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_plan",
					Description: "Build the detection test plan for a loader_windows or stager_linux artifact without running anything. Returns the artifact hash and size, the sandbox capabilities, every static/dynamic/EDR stage with its scanner, whether it executes the payload, whether it needs approval, and the module source files feedback can point at. The artifact must come from a recorded build of that module; omit artifact to use the newest one.",
					Parameters: ObjectSchema(map[string]any{
						"module":   StringProp("Module name: loader_windows or stager_linux"),
						"artifact": StringProp("Artifact path from a recorded build. Omit to use the newest recorded artifact."),
					}, "module"),
				},
			},
			ReadOnly: true,
			Run:      a.detectionPlan,
		},
		"detection_run": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_run",
					Description: "Upload a recorded module artifact to the LitterBox sandbox and run the selected stages. stages defaults to static; static is passive, dynamic and EDR detonate the payload and require approve_execution=true. Returns the plan, stage statuses, risk score, and source-mapped feedback. Screened and audited; no stage touches a target.",
					Parameters: ObjectSchema(map[string]any{
						"module":   StringProp("Module name: loader_windows or stager_linux"),
						"artifact": StringProp("Artifact path from a recorded build. Omit to use the newest recorded artifact."),
						"stages": map[string]any{
							"type":        "array",
							"items":       map[string]any{"type": "string", "enum": []string{"static", "dynamic", "edr"}},
							"description": "Stages to run. Default static.",
						},
						"edr_profile":       StringProp("EDR profile name from detection_plan. Omit to run every configured profile."),
						"approve_execution": BooleanProp("Allow dynamic and EDR stages to execute the payload in the sandbox."),
					}, "module"),
				},
			},
			Destructive: true,
			Run:         a.detectionRun,
		},
		"detection_feedback": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_feedback",
					Description: "Return the detection feedback for a recorded run: risk score, per-indicator findings, the module source file and line each indicator maps to, and the pending stages that make the feedback partial. With analyze=true, a configured detection analyst reviews the feedback with a read-only agent and returns proposed source edits; this sends module source excerpts and sandbox findings to the configured model endpoint.",
					Parameters: ObjectSchema(map[string]any{
						"run_id":  StringProp("Run ID from detection_run or a build result. Omit to use the newest run for module."),
						"module":  StringProp("Module name used when run_id is omitted."),
						"analyze": BooleanProp("Run the configured detection analyst and return proposed edits."),
					}),
				},
			},
			ReadOnly: true,
			Run:      a.detectionFeedback,
		},
		"detection_telemetry_import": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_telemetry_import",
					Description: "Import ETW/Defender telemetry into the detection SQLite database. Reads a RedEdr JSON array or JSONL, a LitterBox dynamic result (merging findings.events and raw_output, including kernel callbacks, ntdll hooks, PEB/loaded-DLL queries, and ETW-TI), or DefenderObserver JSONL from path or url. A url must use the configured sandbox origin; redirects may not leave it. Associate it with a recorded module build with module and optional artifact; returns the trace id, payload attribution, source coverage, normalized event counts, and deterministic findings. Query the result with detection_query.",
					Parameters: ObjectSchema(map[string]any{
						"path":     StringProp("Local telemetry file. Mutually exclusive with url."),
						"url":      StringProp("HTTP(S) telemetry URL on the configured sandbox origin. Mutually exclusive with path."),
						"module":   StringProp("Optional module name (loader_windows or stager_linux) to associate with the trace."),
						"artifact": StringProp("Optional recorded module artifact; defaults to the newest build when module is set."),
						"run_id":   StringProp("Optional detection run ID to associate with the trace."),
						"source":   StringProp("Format hint: rededr, defender_observer, or litterbox-rededr. Auto-detected by default."),
					}),
				},
			},
			Run: a.detectionImport,
		},
		"detection_query": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_query",
					Description: "Run one read-only SQL SELECT or WITH statement against the detection telemetry database. Tables: payloads (one row per artifact, with table_name a per-payload view), traces, events (payload_id, trace_pk, event_key, ts_ns, type, source, event, provider, event_id, pid, tid, actor_pid, target_pid, target_tid, parent_pid, operation, process, target_image, path, image, address, size, protection, access, status, command, proto, src_addr, src_port, dst_addr, dst_port, bytes, stack, category, severity, signal, payload_role, attrs JSON), findings, loop_cycles, loop_feedback, loop_results, loop_builds, and loop_edits. Query payloads.table_name for one payload, filter by trace_pk or payload_id, and use json_extract(attrs,'$.field') for raw fields. Categories include memory (ETW-TI), hook, and module; payload_role separates the payload, its children, targets, scans, and ambient Defender events. Returns columns, rows, and a truncation flag; at most 500 rows.",
					Parameters: ObjectSchema(map[string]any{
						"sql":   StringProp("One SELECT or WITH statement. No comments, PRAGMAs, writes, or multiple statements."),
						"limit": IntegerProp("Maximum rows. Default 200, at most 500."),
					}, "sql"),
				},
			},
			ReadOnly: true,
			Run:      a.detectionQuery,
		},
		"detection_runs": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_runs",
					Description: "List recorded detection runs, newest first, with run ID, module, artifact, hashes, timestamps, whether any stage executed, and the run error. Takes an optional module filter and limit.",
					Parameters: ObjectSchema(map[string]any{
						"module": StringProp("Optional module name filter"),
						"limit":  IntegerProp("Maximum runs to return. Default 20, at most 100."),
					}),
				},
			},
			ReadOnly: true,
			Run:      a.detectionRuns,
		},
		"detection_loop": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_loop",
					Description: "Run the autonomous Norma detection loop: build loader_windows from a source directory, detonate it in LitterBox, import every saved analyzer result (RedEdr, Moneta, pe-sieve, HollowsHunter, HSB, Patriot, Blender, YARA, CheckPlz, HolyGrail, and EDR profiles) into SQLite, edit module source, rebuild, and compare payloads. When telemetry shows the loader, shellcode producer, wrapper, or injection path is detected, Norma may choose another mechanism. Full feedback, build logs, and per-payload telemetry stay in SQLite. Requires approve_execution=true. This edits module source on the operator host.",
					Parameters: ObjectSchema(map[string]any{
						"module_dir":        StringProp("loader_windows source directory."),
						"shellcode":         StringProp("Go agent shellcode path. Generate it first with generate --type windows_executable."),
						"iterations":        IntegerProp("Maximum cycles including baseline. Default 3, at most 10."),
						"stages":            map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"static", "dynamic"}}, "description": "Stages; dynamic is required."},
						"process":           StringProp("Sacrificial process override; omit to let the source default control it."),
						"format":            StringProp("Loader host format: exe, service, or dll."),
						"inject":            StringProp("apc or ct."),
						"smw":               StringProp("on or off."),
						"turns":             IntegerProp("Maximum Norma turns. Default 30, at most 60."),
						"approve_execution": BooleanProp("Allow the loop to detonate the payload and edit module source."),
					}, "module_dir", "shellcode", "approve_execution"),
				},
			},
			Destructive: true,
			Run:         a.detectionLoop,
		},
		"detection_report": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_report",
					Description: "Return the human-readable Markdown report for one completed detection loop, including outcome, achieved objectives, cycles, source edits, and residual findings.",
					Parameters: ObjectSchema(map[string]any{
						"loop_id": StringProp("Loop ID from detection_loop or the loop log."),
					}, "loop_id"),
				},
			},
			ReadOnly: true,
			Run:      a.detectionReport,
		},
		"detection_payloads": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_payloads",
					Description: "List payloads with their per-payload SQLite view (payload_<hash>), artifact SHA-256, parent payload, latest score, and verdict count. Use detection_compare to diff two payloads.",
					Parameters: ObjectSchema(map[string]any{
						"limit": IntegerProp("Maximum payloads. Default 20, at most 100."),
					}),
				},
			},
			ReadOnly: true,
			Run:      a.detectionPayloads,
		},
		"detection_compare": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "detection_compare",
					Description: "Diff two payloads' telemetry views. Returns the largest added and removed event signatures (category, event, path, image, pid, count), showing what a source edit changed.",
					Parameters: ObjectSchema(map[string]any{
						"from": StringProp("Previous payload key."),
						"to":   StringProp("Current payload key."),
					}, "from", "to"),
				},
			},
			ReadOnly: true,
			Run:      a.detectionCompare,
		},
	}
}

type detectionArgs struct {
	Module           string   `json:"module"`
	Artifact         string   `json:"artifact"`
	Stages           []string `json:"stages"`
	EDRProfile       string   `json:"edr_profile"`
	ApproveExecution bool     `json:"approve_execution"`
	RunID            string   `json:"run_id"`
	Analyze          bool     `json:"analyze"`
	Limit            int      `json:"limit"`
	Path             string   `json:"path"`
	URL              string   `json:"url"`
	Source           string   `json:"source"`
	SQL              string   `json:"sql"`
	LoopID           string   `json:"loop_id"`
	ModuleDir        string   `json:"module_dir"`
	Shellcode        string   `json:"shellcode"`
	Iterations       int      `json:"iterations"`
	Process          string   `json:"process"`
	Format           string   `json:"format"`
	Inject           string   `json:"inject"`
	SMW              string   `json:"smw"`
	Turns            int      `json:"turns"`
	From             string   `json:"from"`
	To               string   `json:"to"`
}

func (a *Actions) detectionPlan(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	mod, artifact, err := a.resolveDetectionArtifact(args.Module, args.Artifact)
	if err != nil {
		return nil, err
	}
	if a.Detection == nil {
		return nil, fmt.Errorf("detection loop is not configured")
	}
	plan, err := a.Detection.CreatePlan(ctx, detection.Request{
		Module:       mod.Name,
		ModuleDir:    mod.Path,
		Platform:     mod.Platform,
		ArtifactPath: artifact.Path,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan}, nil
}

func (a *Actions) detectionRun(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	mod, artifact, err := a.resolveDetectionArtifact(args.Module, args.Artifact)
	if err != nil {
		return nil, err
	}
	if a.Detection == nil {
		return nil, fmt.Errorf("detection loop is not configured")
	}
	opts, err := detectionRunOptions(args)
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("detection_run %s %s stages=%s", mod.Name, artifact.SHA256, strings.Join(stageNames(opts), ","))
	review := def.OpsecReview{
		Noise:      "low",
		Reversible: true,
		Reasons:    []string{"local detection sandbox; no target execution"},
		Artifacts:  []string{"sandbox upload"},
	}
	if opts.Dynamic || opts.EDR {
		review.Noise = "high"
		review.Rules = []string{"process-creation"}
		review.Reasons = append(review.Reasons, "dynamic and EDR stages detonate the uploaded payload in the sandbox")
		review.Artifacts = append(review.Artifacts, "sandbox detonation")
	}
	decision, auditErr := a.screenWithFlags("detection_run", mod.Name, command, map[string]string{
		"module": mod.Name, "artifact": artifact.Path, "stages": strings.Join(stageNames(opts), ","),
	}, nil, review)
	if !decision.Allowed {
		return actionBlocked("detection_run", command, mod.Name, nil, review, decision, auditErr), nil
	}

	plan, err := a.Detection.CreatePlan(ctx, detection.Request{
		Module:       mod.Name,
		ModuleDir:    mod.Path,
		Platform:     mod.Platform,
		ArtifactPath: artifact.Path,
	})
	if err != nil {
		return a.actionResultWithFlags("detection_run", command, mod.Name, nil, nil, review, decision, auditErr, "", err, false), nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	run, runErr := a.Detection.RunPlan(runCtx, plan, opts)
	detection.SanitizeRisk(&run.Risk)
	feedback := detection.BuildFeedback(run)
	detection.SanitizeFeedback(&feedback)
	result := a.actionResultWithFlags("detection_run", command, mod.Name, nil, nil, review, decision, auditErr, "", runErr, run.Executed)
	result["run_id"] = run.ID
	result["artifact"] = run.Plan.Artifact
	result["risk"] = run.Risk
	result["stages"] = stageSummaries(run)
	result["feedback"] = feedback
	if feedback.Telemetry != nil {
		result["telemetry"] = feedback.Telemetry
	}
	if len(feedback.Pending) > 0 {
		result["partial"] = true
	}
	if runErr != nil {
		result["error"] = runErr.Error()
	}
	return result, nil
}

func (a *Actions) detectionFeedback(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	runID := strings.TrimSpace(args.RunID)
	if len(runID) > maxDetectionRunID {
		return nil, fmt.Errorf("run_id is too long")
	}
	if a.Detection == nil {
		return nil, fmt.Errorf("detection loop is not configured")
	}
	var (
		feedback detection.Feedback
		err      error
	)
	if runID != "" {
		feedback, err = a.Detection.Feedback(runID)
	} else {
		module := strings.TrimSpace(args.Module)
		if module == "" {
			return nil, fmt.Errorf("run_id or module is required")
		}
		var ok bool
		feedback, ok, err = a.Detection.LatestFeedback(module)
		if err == nil && !ok {
			return nil, fmt.Errorf("no detection run recorded for module %q", module)
		}
	}
	if err != nil {
		return nil, err
	}
	detection.SanitizeFeedback(&feedback)
	result := map[string]any{"run_id": feedback.RunID, "feedback": feedback}
	if feedback.Telemetry != nil {
		result["telemetry"] = map[string]any{
			"trace_id": feedback.Telemetry.TraceID,
			"events":   feedback.Telemetry.Events,
			"source":   feedback.Telemetry.Source,
			"note":     "query raw events with detection_query using trace_pk = trace_id",
		}
	}
	if a.Detection != nil {
		if comparison, compareErr := a.Detection.Compare(feedback.RunID); compareErr != nil {
			result["comparison_error"] = compareErr.Error()
		} else if comparison != nil {
			result["comparison"] = comparison
		}
	}
	if args.Analyze {
		if !a.Detection.AnalystConfigured() {
			result["analysis_error"] = "detection analyst is not configured; set EMP3R0R_DETECTION_MODEL and a provider API key"
			return result, nil
		}
		analyzeCtx, cancel := context.WithTimeout(ctx, detectionAnalyzeBudget)
		defer cancel()
		analyzed, analyzeErr := a.Detection.Analyze(analyzeCtx, feedback)
		if a.Audit != nil {
			reason := "analyst review of " + feedback.RunID
			if analyzeErr != nil {
				reason += ": " + analyzeErr.Error()
			}
			if err := a.Audit.Log(AuditRecord{
				Operator: a.Operator, Tool: "detection_feedback",
				Command: "analyst review", Module: feedback.Module,
				Allowed: analyzeErr == nil, Reason: reason,
			}); err != nil {
				result["audit_error"] = err.Error()
			}
		}
		if analyzeErr != nil {
			result["analysis_error"] = analyzeErr.Error()
			return result, nil
		}
		detection.SanitizeFeedback(&analyzed)
		result["feedback"] = analyzed
		result["analysis"] = detection.RedactAnalysis(analyzed)
	}
	return result, nil
}

func (a *Actions) detectionRuns(_ context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if a.Detection == nil {
		return nil, fmt.Errorf("detection loop is not configured")
	}
	runs, err := a.Detection.Store.List()
	if err != nil {
		return nil, err
	}
	module := strings.ToLower(strings.TrimSpace(args.Module))
	if module != "" {
		filtered := runs[:0]
		for _, run := range runs {
			if strings.EqualFold(run.Module, module) {
				filtered = append(filtered, run)
			}
		}
		runs = filtered
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if len(runs) > limit {
		runs = runs[:limit]
	}
	return map[string]any{"runs": runs}, nil
}

// attachDetection plans and passively tests a fresh build. It never fails the
// build result: every error is reported inside the detection block.
func (a *Actions) attachDetection(ctx context.Context, mod *def.ModuleConfig, buildLog string) map[string]any {
	if a.Detection == nil || mod == nil || !detection.Covered(mod.Name) {
		return nil
	}
	payloads := detection.ParseGeneratedPayloads(buildLog)
	if len(payloads) == 0 {
		return map[string]any{"error": "no generated payload was reported by the build"}
	}
	artifactPath := payloads[len(payloads)-1].Path
	artifact, err := detection.InspectArtifact(artifactPath)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	if err := a.Detection.Store.RecordArtifact(mod.Name, artifact); err != nil {
		return map[string]any{"error": err.Error()}
	}
	planCtx, cancelPlan := context.WithTimeout(ctx, 15*time.Second)
	plan, err := a.Detection.CreatePlan(planCtx, detection.Request{
		Module:       mod.Name,
		ModuleDir:    mod.Path,
		Platform:     mod.Platform,
		ArtifactPath: artifact.Path,
	})
	cancelPlan()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	block := map[string]any{"plan": plan}
	if !plan.Sandbox.Available {
		block["status"] = "sandbox-unavailable"
		block["note"] = "detection_plan rebuilds this plan when the sandbox is reachable"
		return block
	}
	if !plan.StageRunnable(detection.StageStatic) {
		block["status"] = "no-passive-stage"
		return block
	}
	runCtx, cancel := context.WithTimeout(ctx, detectionBuildBudget)
	defer cancel()
	run, runErr := a.Detection.RunPlan(runCtx, plan, detection.DefaultRunOptions())
	feedback := detection.BuildFeedback(run)
	block["run_id"] = run.ID
	block["status"] = runStatus(run)
	block["score"] = feedback.Score
	block["level"] = feedback.Level
	block["findings"] = len(feedback.Findings)
	block["source_edits"] = feedback.SourceEdits
	block["pending"] = feedback.Pending
	if runErr != nil {
		block["error"] = runErr.Error()
	}
	return block
}

func runStatus(run detection.Run) string {
	for _, stage := range run.Stages {
		if stage.Status == "completed" {
			return "completed"
		}
	}
	if run.Error != "" {
		return "error"
	}
	return "no-completed-stage"
}

func (a *Actions) resolveDetectionArtifact(module, artifact string) (*def.ModuleConfig, detection.Artifact, error) {
	name := strings.TrimSpace(module)
	if name == "" {
		return nil, detection.Artifact{}, fmt.Errorf("module is required")
	}
	if len(name) > 256 {
		return nil, detection.Artifact{}, fmt.Errorf("module name is too long")
	}
	mod, ok := def.GetModule(name)
	if !ok || mod == nil {
		return nil, detection.Artifact{}, fmt.Errorf("module %q is not installed", name)
	}
	if !detection.Covered(mod.Name) {
		return nil, detection.Artifact{}, fmt.Errorf("module %q has no detection plan; supported: loader_windows, stager_linux", mod.Name)
	}
	if a.Detection == nil {
		return nil, detection.Artifact{}, fmt.Errorf("detection loop is not configured")
	}
	path := strings.TrimSpace(artifact)
	if len(path) > maxDetectionArtifactPath {
		return nil, detection.Artifact{}, fmt.Errorf("artifact path is too long")
	}
	var recorded detection.Artifact
	if path == "" {
		latest, ok := a.Detection.Store.LatestArtifact(mod.Name)
		if !ok {
			return nil, detection.Artifact{}, fmt.Errorf("no artifact recorded for module %q; run it first", mod.Name)
		}
		recorded = latest
	} else {
		clean := filepath.Clean(path)
		known, ok := a.Detection.Store.KnownArtifact(mod.Name, clean)
		if !ok {
			return nil, detection.Artifact{}, fmt.Errorf("artifact %q is not a recorded %s build output", path, mod.Name)
		}
		recorded = known
	}
	if info, err := os.Stat(recorded.Path); err != nil || !info.Mode().IsRegular() {
		return nil, detection.Artifact{}, fmt.Errorf("artifact %q is no longer readable", recorded.Path)
	}
	current, err := detection.InspectArtifact(recorded.Path)
	if err != nil {
		return nil, detection.Artifact{}, err
	}
	if current.SHA256 != recorded.SHA256 {
		return nil, detection.Artifact{}, fmt.Errorf("artifact %q changed after the build; rebuild the module", recorded.Path)
	}
	return mod, current, nil
}

func detectionRunOptions(args detectionArgs) (detection.RunOptions, error) {
	opts := detection.RunOptions{
		EDRProfile:       strings.TrimSpace(args.EDRProfile),
		ApproveExecution: args.ApproveExecution,
	}
	if len(opts.EDRProfile) > maxDetectionProfile {
		return opts, fmt.Errorf("edr_profile is too long")
	}
	if len(args.Stages) == 0 {
		opts.Static = true
		return opts, nil
	}
	if len(args.Stages) > 3 {
		return opts, fmt.Errorf("too many stages")
	}
	for _, stage := range args.Stages {
		switch strings.ToLower(strings.TrimSpace(stage)) {
		case "static":
			opts.Static = true
		case "dynamic":
			opts.Dynamic = true
		case "edr":
			opts.EDR = true
		default:
			return opts, fmt.Errorf("unknown stage %q; use static, dynamic, or edr", stage)
		}
	}
	if (opts.Dynamic || opts.EDR) && !opts.ApproveExecution {
		return opts, fmt.Errorf("dynamic and EDR stages detonate the payload; pass approve_execution=true")
	}
	return opts, nil
}

func stageNames(opts detection.RunOptions) []string {
	var out []string
	if opts.Static {
		out = append(out, "static")
	}
	if opts.Dynamic {
		out = append(out, "dynamic")
	}
	if opts.EDR {
		out = append(out, "edr")
	}
	return out
}

func stageSummaries(run detection.Run) []map[string]any {
	out := make([]map[string]any, 0, len(run.Stages))
	for _, stage := range run.Stages {
		row := map[string]any{
			"kind": string(stage.Kind), "tool": sanitize.SanitizeOneLine(stage.Tool),
			"status": stage.Status, "executes": stage.Executes,
		}
		if stage.Reason != "" {
			row["reason"] = sanitize.SanitizeText(stage.Reason)
		}
		if stage.Error != "" {
			row["error"] = sanitize.SanitizeText(stage.Error)
		}
		out = append(out, row)
	}
	return out
}

func (a *Actions) detectionImport(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection telemetry is not configured")
	}
	path := strings.TrimSpace(args.Path)
	rawURL := strings.TrimSpace(args.URL)
	if (path == "") == (rawURL == "") {
		return nil, fmt.Errorf("pass exactly one of path or url")
	}
	if rawURL != "" && a.Detection.Client == nil {
		return nil, fmt.Errorf("detection sandbox is not configured")
	}
	if len(path) > maxDetectionArtifactPath || len(rawURL) > maxDetectionTelemetryURL {
		return nil, fmt.Errorf("telemetry location is too long")
	}
	source := strings.ToLower(strings.TrimSpace(args.Source))
	switch source {
	case "", "rededr", "defender_observer", "litterbox-rededr":
	default:
		return nil, fmt.Errorf("unknown source %q; use rededr, defender_observer, or litterbox-rededr", args.Source)
	}
	opts := detection.ImportOptions{
		RunID:  strings.TrimSpace(args.RunID),
		Source: source,
		Path:   path,
	}
	if len(opts.RunID) > maxDetectionRunID {
		return nil, fmt.Errorf("run_id is too long")
	}
	module := strings.TrimSpace(args.Module)
	if module != "" {
		mod, ok := def.GetModule(module)
		if !ok || mod == nil {
			return nil, fmt.Errorf("module %q is not installed", module)
		}
		if !detection.Covered(mod.Name) {
			return nil, fmt.Errorf("module %q has no detection plan", mod.Name)
		}
		opts.Module = mod.Name
		if strings.TrimSpace(args.Artifact) != "" {
			_, artifact, err := a.resolveDetectionArtifact(mod.Name, args.Artifact)
			if err != nil {
				return nil, err
			}
			opts.ArtifactSHA256 = artifact.SHA256
		} else if latest, ok := a.Detection.Store.LatestArtifact(mod.Name); ok {
			opts.ArtifactSHA256 = latest.SHA256
		}
	}
	command := "detection_telemetry_import " + sanitize.SanitizeOneLine(firstNonEmpty(path, rawURL))
	review := def.OpsecReview{
		Noise:      "low",
		Reversible: true,
		Reasons:    []string{"reads operator-local telemetry into the detection database"},
	}
	decision, auditErr := a.screenWithFlags("detection_telemetry_import", opts.Module, command, nil, nil, review)
	if !decision.Allowed {
		return actionBlocked("detection_telemetry_import", command, opts.Module, nil, review, decision, auditErr), nil
	}
	importCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var (
		trace detection.TelemetryTrace
		err   error
	)
	if path != "" {
		trace, err = a.Detection.Telemetry.ImportFile(importCtx, filepath.Clean(path), opts)
	} else {
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 90*time.Second)
		var data []byte
		data, err = detection.FetchTelemetry(fetchCtx, rawURL, a.Detection.Client.URL())
		fetchCancel()
		if err == nil {
			opts.Path = rawURL
			trace, err = a.Detection.Telemetry.Import(importCtx, data, opts)
		}
	}
	if err != nil {
		return a.actionResultWithFlags("detection_telemetry_import", command, opts.Module, nil, nil, review, decision, auditErr, "", err, false), nil
	}
	findings, findErr := a.Detection.Telemetry.Findings(importCtx, trace.ID)
	result := a.actionResultWithFlags("detection_telemetry_import", command, opts.Module, nil, nil, review, decision, auditErr, "", findErr, false)
	detection.SanitizeTelemetryTrace(&trace)
	result["trace"] = trace
	result["findings"] = findings
	result["note"] = "query raw events with detection_query using trace_pk = trace.id"
	return result, nil
}

func (a *Actions) detectionQuery(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if len(args.SQL) > maxDetectionSQL {
		return nil, fmt.Errorf("sql is too long")
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection telemetry is not configured")
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result, err := a.Detection.Telemetry.Query(queryCtx, args.SQL, args.Limit)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *Actions) detectionLoop(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection loop is not configured")
	}
	if !args.ApproveExecution {
		return nil, fmt.Errorf("detection_loop detonates the payload and edits source; pass approve_execution=true")
	}
	moduleDir := strings.TrimSpace(args.ModuleDir)
	if len(moduleDir) > maxDetectionArtifactPath {
		return nil, fmt.Errorf("module_dir is too long")
	}
	shellcode := strings.TrimSpace(args.Shellcode)
	if shellcode == "" {
		return nil, fmt.Errorf("shellcode path is required")
	}
	if len(shellcode) > maxDetectionArtifactPath {
		return nil, fmt.Errorf("shellcode path is too long")
	}
	module := strings.ToLower(strings.TrimSpace(args.Module))
	if module == "" {
		module = "loader_windows"
	}
	if moduleDir == "" {
		if mod, ok := def.GetModule(module); ok && mod != nil {
			moduleDir = mod.Path
		}
	}
	command := fmt.Sprintf("detection_loop %s %s", sanitize.SanitizeOneLine(module), sanitize.SanitizeOneLine(shellcode))
	review := def.OpsecReview{
		Noise:      "high",
		Reversible: false,
		Rules:      []string{"process-creation", "local-code-edit"},
		Reasons:    []string{"detonates the payload in LitterBox and edits module source"},
	}
	decision, auditErr := a.screenWithFlags("detection_loop", module, command, nil, nil, review)
	if !decision.Allowed {
		return actionBlocked("detection_loop", command, module, nil, review, decision, auditErr), nil
	}
	loopCtx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	result, err := detection.RunEvolve(loopCtx, detection.EvolveConfig{
		Module: module, ModuleDir: moduleDir, Shellcode: shellcode,
		SandboxURL: a.Detection.Client.URL(), StoreRoot: a.Detection.Store.Root,
		Process: args.Process, Format: args.Format, Inject: args.Inject, SMW: args.SMW,
		Stages: args.Stages, Iterations: args.Iterations, Turns: args.Turns,
		Logf: func(line string) {},
	})
	if err != nil {
		return a.actionResultWithFlags("detection_loop", command, module, nil, nil, review, decision, auditErr, "", err, true), nil
	}
	var answer any
	_ = json.Unmarshal(result.Answer, &answer)
	return map[string]any{
		"loop_id": result.LoopID, "answer": answer, "report": result.Report,
		"cycles": result.Cycles, "last": result.Last, "executed": true,
		"note": "full feedback and per-payload telemetry are in SQLite; use detection_payloads, detection_compare, or detection_query",
	}, nil
}

func (a *Actions) detectionPayloads(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection telemetry is not configured")
	}
	payloads, err := a.Detection.Telemetry.ListPayloads(ctx, args.Limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{"payloads": payloads}, nil
}

func (a *Actions) detectionCompare(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection telemetry is not configured")
	}
	diff, err := a.Detection.Telemetry.ComparePayloads(ctx, args.From, args.To)
	if err != nil {
		return nil, err
	}
	return diff, nil
}

func (a *Actions) detectionReport(ctx context.Context, raw json.RawMessage) (any, error) {
	var args detectionArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	loopID := strings.TrimSpace(args.LoopID)
	if loopID == "" {
		return nil, fmt.Errorf("loop_id is required")
	}
	if len(loopID) > maxDetectionRunID {
		return nil, fmt.Errorf("loop_id is too long")
	}
	if a.Detection == nil || a.Detection.Telemetry == nil {
		return nil, fmt.Errorf("detection telemetry is not configured")
	}
	report, err := a.Detection.Telemetry.LoopReport(ctx, loopID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"loop_id": loopID, "report": report}, nil
}
