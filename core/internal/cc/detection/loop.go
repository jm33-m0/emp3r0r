package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// LoopConfig configures one detection loop instance.
type LoopConfig struct {
	SandboxURL string
	StoreRoot  string
	// AnalystFactory builds an analyst rooted at one module directory. It may
	// return (nil, nil) when no model is configured.
	AnalystFactory func(workingDir string, telemetry *TelemetryDB) (*Analyst, error)
}

// Loop owns the sandbox client, the run store, and the optional analyst.
type Loop struct {
	Client         *Client
	Store          *Store
	Telemetry      *TelemetryDB
	AnalystFactory func(workingDir string, telemetry *TelemetryDB) (*Analyst, error)
}

// NewLoop validates the sandbox URL and prepares the store.
func NewLoop(cfg LoopConfig) (*Loop, error) {
	client, err := NewClient(cfg.SandboxURL)
	if err != nil {
		return nil, err
	}
	loop := &Loop{
		Client:         client,
		Store:          NewStore(cfg.StoreRoot),
		AnalystFactory: cfg.AnalystFactory,
	}
	if strings.TrimSpace(cfg.StoreRoot) != "" {
		telemetry, err := OpenTelemetryDB(filepath.Join(cfg.StoreRoot, "telemetry.db"))
		if err != nil {
			return nil, err
		}
		loop.Telemetry = telemetry
	}
	return loop, nil
}

// Available probes the sandbox and returns its current capability set.
func (l *Loop) Available(ctx context.Context) Health {
	return l.Client.Probe(ctx)
}

// CreatePlan probes the sandbox and builds the deterministic plan.
func (l *Loop) CreatePlan(ctx context.Context, req Request) (Plan, error) {
	health := l.Client.Probe(ctx)
	return BuildPlan(req, health)
}

// CreateAndRun plans and executes a passive run in one call.
func (l *Loop) CreateAndRun(ctx context.Context, req Request, opts RunOptions) (Plan, Run, error) {
	plan, err := l.CreatePlan(ctx, req)
	if err != nil {
		return Plan{}, Run{}, err
	}
	run, err := l.RunPlan(ctx, plan, opts)
	return plan, run, err
}

// Feedback loads a run and maps it to module source.
func (l *Loop) Feedback(runID string) (Feedback, error) {
	run, err := l.Store.Load(runID)
	if err != nil {
		return Feedback{}, err
	}
	return BuildFeedback(run), nil
}

// LatestFeedback loads the newest run for a module and maps it to source.
func (l *Loop) LatestFeedback(module string) (Feedback, bool, error) {
	run, ok, err := l.Store.Latest(module)
	if err != nil || !ok {
		return Feedback{}, ok, err
	}
	return BuildFeedback(run), true, nil
}

// AnalystConfigured reports whether an analyst factory is installed.
func (l *Loop) AnalystConfigured() bool { return l.AnalystFactory != nil }

// Analyze runs the norma analyst over feedback and attaches its answer. The
// analyst is rooted at the feedback's module directory.
func (l *Loop) Analyze(ctx context.Context, feedback Feedback) (Feedback, error) {
	if l.AnalystFactory == nil {
		return feedback, fmt.Errorf("detection analyst is not configured")
	}
	analyst, err := l.AnalystFactory(feedback.ModuleDir, l.Telemetry)
	if err != nil {
		return feedback, err
	}
	if analyst == nil {
		return feedback, fmt.Errorf("detection analyst is not configured")
	}
	answer, err := analyst.Analyze(ctx, feedback)
	if err != nil {
		return feedback, err
	}
	feedback.Analysis = answer
	return feedback, nil
}

// RedactAnalysis returns the analyst answer as a value for MCP results.
func RedactAnalysis(feedback Feedback) any {
	if len(feedback.Analysis) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(feedback.Analysis, &value); err != nil {
		return nil
	}
	return value
}

// Comparison is the delta between the newest run and an earlier run of the
// same module with a different artifact. It is what the resubmit loop reports.
type Comparison struct {
	PreviousRunID string    `json:"previous_run_id"`
	PreviousSHA   string    `json:"previous_sha256,omitempty"`
	CurrentSHA    string    `json:"current_sha256,omitempty"`
	PreviousScore float64   `json:"previous_score"`
	CurrentScore  float64   `json:"current_score"`
	ScoreDelta    float64   `json:"score_delta"`
	PreviousTrace int64     `json:"previous_telemetry_trace,omitempty"`
	CurrentTrace  int64     `json:"current_telemetry_trace,omitempty"`
	Resolved      []Finding `json:"resolved,omitempty"`
	Added         []Finding `json:"added,omitempty"`
	Unchanged     int       `json:"unchanged"`
}

// Compare finds the newest earlier run with a different artifact and reports
// which indicators were resolved or introduced.
func (l *Loop) Compare(runID string) (*Comparison, error) {
	current, err := l.Store.Load(runID)
	if err != nil {
		return nil, err
	}
	runs, err := l.Store.List()
	if err != nil {
		return nil, err
	}
	var previous *Run
	for _, summary := range runs {
		if summary.ID == current.ID || !strings.EqualFold(summary.Module, current.Module) {
			continue
		}
		if summary.SHA256 == current.Plan.Artifact.SHA256 {
			continue
		}
		if !summary.StartedAt.Before(current.StartedAt) {
			continue
		}
		loaded, loadErr := l.Store.Load(summary.ID)
		if loadErr != nil {
			continue
		}
		previous = &loaded
		break
	}
	if previous == nil {
		return nil, nil
	}
	currentFeedback := BuildFeedback(current)
	previousFeedback := BuildFeedback(*previous)
	previousKeys := findingKeys(previousFeedback.Findings)
	currentKeys := findingKeys(currentFeedback.Findings)
	comparison := &Comparison{
		PreviousRunID: previous.ID,
		PreviousSHA:   previous.Plan.Artifact.SHA256,
		CurrentSHA:    current.Plan.Artifact.SHA256,
		PreviousScore: previousFeedback.Score,
		CurrentScore:  currentFeedback.Score,
		ScoreDelta:    currentFeedback.Score - previousFeedback.Score,
		PreviousTrace: telemetryTraceID(previous.Telemetry),
		CurrentTrace:  telemetryTraceID(current.Telemetry),
	}
	seenResolved := map[string]struct{}{}
	for _, finding := range previousFeedback.Findings {
		key := findingKey(finding)
		if _, ok := currentKeys[key]; ok {
			continue
		}
		if _, ok := seenResolved[key]; ok {
			continue
		}
		seenResolved[key] = struct{}{}
		comparison.Resolved = append(comparison.Resolved, finding)
	}
	seenAdded := map[string]struct{}{}
	for _, finding := range currentFeedback.Findings {
		key := findingKey(finding)
		if _, ok := previousKeys[key]; ok {
			comparison.Unchanged++
			continue
		}
		if _, ok := seenAdded[key]; ok {
			continue
		}
		seenAdded[key] = struct{}{}
		comparison.Added = append(comparison.Added, finding)
	}
	return comparison, nil
}

func findingKey(finding Finding) string {
	return finding.Rule + "|" + finding.Indicator
}

func findingKeys(findings []Finding) map[string]struct{} {
	keys := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		keys[findingKey(finding)] = struct{}{}
	}
	return keys
}
