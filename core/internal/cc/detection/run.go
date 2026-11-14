package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// maxStageResultBytes bounds one persisted sandbox result.
	maxStageResultBytes = 2 << 20
	// defaultStageTimeout bounds one waited static or dynamic analysis.
	defaultStageTimeout = 10 * time.Minute
	// defaultEDRTimeout bounds EDR alert correlation.
	defaultEDRTimeout = 4 * time.Minute
)

// RunOptions selects stages and gates execution.
type RunOptions struct {
	Static           bool
	Dynamic          bool
	EDR              bool
	EDRProfile       string
	ApproveExecution bool
	Timeout          time.Duration
	EDRTimeout       time.Duration
	// ParentKey links the artifact's telemetry payload to the payload it
	// replaced, so per-payload diffs show the effect of the edit.
	ParentKey string
}

// DefaultRunOptions runs every passive stage.
func DefaultRunOptions() RunOptions {
	return RunOptions{Static: true}
}

func (o RunOptions) anySelected() bool { return o.Static || o.Dynamic || o.EDR }

// StageResult is the persisted outcome of one planned test.
type StageResult struct {
	Kind     StageKind       `json:"kind"`
	Tool     string          `json:"tool"`
	Status   string          `json:"status"` // completed, skipped, error
	Executes bool            `json:"executes"`
	Reason   string          `json:"reason,omitempty"`
	Raw      json.RawMessage `json:"raw,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Run is one detection test execution.
type Run struct {
	ID         string          `json:"id"`
	Module     string          `json:"module"`
	Plan       Plan            `json:"plan"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Upload     *Upload         `json:"upload,omitempty"`
	Stages     []StageResult   `json:"stages,omitempty"`
	Risk       Risk            `json:"risk,omitempty"`
	Info       json.RawMessage `json:"info,omitempty"`
	Executed   bool            `json:"executed"`
	Telemetry  *TelemetryRun   `json:"telemetry,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// RunSummary is one row of the run index.
type RunSummary struct {
	ID         string    `json:"id"`
	Module     string    `json:"module"`
	Artifact   string    `json:"artifact,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Executed   bool      `json:"executed"`
	Telemetry  int64     `json:"telemetry_trace,omitempty"`
	Payload    string    `json:"payload_key,omitempty"`
	Table      string    `json:"payload_table,omitempty"`
	Events     int       `json:"telemetry_events,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Summary reduces a run for listing.
func (r Run) Summary() RunSummary {
	return RunSummary{
		ID:         r.ID,
		Module:     r.Module,
		Artifact:   r.Plan.Artifact.Name,
		SHA256:     r.Plan.Artifact.SHA256,
		StartedAt:  r.StartedAt,
		FinishedAt: r.FinishedAt,
		Executed:   r.Executed,
		Telemetry:  telemetryTraceID(r.Telemetry),
		Payload:    telemetryPayloadKey(r.Telemetry),
		Table:      telemetryPayloadTable(r.Telemetry),
		Events:     telemetryEventCount(r.Telemetry),
		Error:      r.Error,
	}
}

// RunPlan executes the selected stages of a plan. Passive stages run by
// default; an executing stage is skipped unless ApproveExecution is set.
func (l *Loop) RunPlan(ctx context.Context, plan Plan, opts RunOptions) (Run, error) {
	if !opts.anySelected() {
		opts.Static = true
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultStageTimeout
	}
	if opts.EDRTimeout <= 0 {
		opts.EDRTimeout = defaultEDRTimeout
	}
	run := Run{
		ID:        newRunID(plan.Module, plan.Artifact.SHA256),
		Module:    plan.Module,
		Plan:      plan,
		StartedAt: time.Now().UTC(),
	}
	fail := func(err error) (Run, error) {
		run.Error = err.Error()
		run.FinishedAt = time.Now().UTC()
		saved, saveErr := l.Store.Save(run)
		if saveErr != nil {
			return saved, fmt.Errorf("%w; save run: %v", err, saveErr)
		}
		return saved, err
	}

	selected := make([]Stage, 0, len(plan.Stages))
	for _, stage := range plan.Stages {
		if !stageSelected(stage, opts) {
			run.Stages = append(run.Stages, StageResult{
				Kind: stage.Kind, Tool: stage.Tool, Executes: stage.Executes,
				Status: "skipped", Reason: "stage not selected",
			})
			continue
		}
		if !stage.Runnable {
			reason := stage.Reason
			if reason == "" {
				reason = "stage is not available"
			}
			run.Stages = append(run.Stages, StageResult{
				Kind: stage.Kind, Tool: stage.Tool, Executes: stage.Executes,
				Status: "skipped", Reason: reason,
			})
			continue
		}
		if stage.Executes && !opts.ApproveExecution {
			run.Stages = append(run.Stages, StageResult{
				Kind: stage.Kind, Tool: stage.Tool, Executes: true,
				Status: "skipped", Reason: "execution requires approve_execution",
			})
			continue
		}
		selected = append(selected, stage)
	}
	if len(selected) == 0 {
		run.Notes = append(run.Notes, "no runnable stage was selected")
		run.FinishedAt = time.Now().UTC()
		return l.Store.Save(run)
	}

	upload, err := l.Client.Upload(ctx, plan.Artifact.Path)
	if err != nil {
		return fail(fmt.Errorf("upload artifact: %w", err))
	}
	run.Upload = &upload

	// One static or dynamic analysis returns the result block for every
	// scanner in that group. Run it once and attach it to each planned stage so
	// feedback never parses the same findings twice.
	var (
		staticRaw, dynamicRaw   json.RawMessage
		staticErr, dynamicErr   error
		staticDone, dynamicDone bool
	)
	for _, stage := range selected {
		result := StageResult{Kind: stage.Kind, Tool: stage.Tool, Executes: stage.Executes}
		var raw json.RawMessage
		var stageErr error
		switch stage.Kind {
		case StageStatic:
			if !staticDone {
				stageCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
				staticRaw, staticErr = l.Client.Analyze(stageCtx, upload.MD5, StageStatic, true)
				cancel()
				staticDone = true
			}
			raw, stageErr = staticRaw, staticErr
		case StageDynamic:
			run.Executed = true
			if !dynamicDone {
				stageCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
				dynamicRaw, dynamicErr = l.Client.Analyze(stageCtx, upload.MD5, StageDynamic, true)
				cancel()
				dynamicDone = true
			}
			raw, stageErr = dynamicRaw, dynamicErr
		case StageEDR:
			run.Executed = true
			stageCtx, cancel := context.WithTimeout(ctx, opts.EDRTimeout+30*time.Second)
			raw, stageErr = l.Client.AnalyzeEDR(stageCtx, stage.Tool, upload.MD5, opts.EDRTimeout)
			cancel()
		default:
			stageErr = fmt.Errorf("unknown stage %q", stage.Kind)
		}
		if stageErr != nil {
			result.Status = "error"
			result.Error = stageErr.Error()
		} else {
			result.Status = "completed"
			result.Raw = trimRaw(raw)
		}
		run.Stages = append(run.Stages, result)
	}

	if info, err := l.Client.Info(ctx, upload.MD5); err == nil {
		run.Info = trimRaw(info)
	}
	if risk, err := l.Client.Risk(ctx, upload.MD5); err == nil {
		run.Risk = risk
	}
	if dynamicDone && dynamicErr == nil && len(dynamicRaw) > 0 && l.Telemetry != nil {
		trace, importErr := l.Telemetry.Import(ctx, dynamicRaw, ImportOptions{
			RunID:          run.ID,
			Module:         plan.Module,
			ArtifactSHA256: plan.Artifact.SHA256,
			Source:         "litterbox-rededr",
			ParentKey:      opts.ParentKey,
		})
		if importErr != nil {
			run.Notes = append(run.Notes, "telemetry: "+importErr.Error())
		} else {
			run.Telemetry = &TelemetryRun{
				TraceID: trace.ID, PayloadID: trace.PayloadID,
				PayloadKey: trace.PayloadKey, PayloadTable: trace.PayloadTable,
				Source: trace.Source, Events: trace.Events,
				First: trace.First, Last: trace.Last,
				PayloadPID: trace.PayloadPID, PayloadImage: trace.PayloadImage,
				Attribution: trace.Attribution, Coverage: trace.Coverage,
			}
			if findings, findErr := l.Telemetry.Findings(ctx, trace.ID); findErr != nil {
				run.Notes = append(run.Notes, "telemetry findings: "+findErr.Error())
			} else {
				run.Telemetry.Findings = findings
			}
			if stats, statErr := l.Telemetry.Stats(ctx, trace.ID); statErr != nil {
				run.Notes = append(run.Notes, "telemetry stats: "+statErr.Error())
			} else {
				run.Telemetry.Stats = &stats
			}
			if trace.Attribution == "unknown" {
				run.Notes = append(run.Notes, "telemetry: no payload PEB was captured; the trace cannot be attributed to the sample")
			}
			if len(trace.Coverage.Missing) > 0 {
				run.Notes = append(run.Notes,
					"telemetry coverage missing: "+strings.Join(trace.Coverage.Missing, ", "))
			}
		}
	}
	sort.SliceStable(run.Stages, func(i, j int) bool {
		if run.Stages[i].Kind == run.Stages[j].Kind {
			return run.Stages[i].Tool < run.Stages[j].Tool
		}
		return run.Stages[i].Kind < run.Stages[j].Kind
	})
	run.FinishedAt = time.Now().UTC()
	return l.Store.Save(run)
}

func stageSelected(stage Stage, opts RunOptions) bool {
	switch stage.Kind {
	case StageStatic:
		return opts.Static
	case StageDynamic:
		return opts.Dynamic
	case StageEDR:
		if !opts.EDR {
			return false
		}
		profile := strings.TrimSpace(opts.EDRProfile)
		return profile == "" || strings.EqualFold(profile, stage.Tool)
	}
	return false
}

// trimRaw bounds a sandbox result before it is persisted.
func trimRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) <= maxStageResultBytes {
		return raw
	}
	replacement, _ := json.Marshal(map[string]any{
		"truncated":      true,
		"original_bytes": len(raw),
		"note":           "sandbox result exceeded the persistence bound",
	})
	return replacement
}

func telemetryTraceID(run *TelemetryRun) int64 {
	if run == nil {
		return 0
	}
	return run.TraceID
}

func telemetryPayloadKey(run *TelemetryRun) string {
	if run == nil {
		return ""
	}
	return run.PayloadKey
}

func telemetryPayloadTable(run *TelemetryRun) string {
	if run == nil {
		return ""
	}
	return run.PayloadTable
}

func telemetryEventCount(run *TelemetryRun) int {
	if run == nil {
		return 0
	}
	return run.Events
}
