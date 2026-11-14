package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

const (
	defaultAnalystTurns = 12
	maxAnalystTokens    = 4096
	maxAnalystPrompt    = 48 << 10
	maxAnalystReadLines = 400
	maxAnalystHits      = 40
)

// AnalystConfig configures the norma-based feedback analyst.
type AnalystConfig struct {
	Provider   llm.Provider
	Model      string
	WorkingDir string
	MaxTurns   int
	Telemetry  *TelemetryDB
	Logger     func(string)
}

// Analyst reviews detection feedback with a read-only norma agent and returns
// concrete source edit proposals. The agent never writes: the module owner
// applies the edits after review.
type Analyst struct {
	provider   llm.Provider
	model      string
	workingDir string
	maxTurns   int
	telemetry  *TelemetryDB
	tools      []tool.CoreTool
	hooks      *hook.Registry
	logf       func(string)
}

var analystSourcePath = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,240}$`)

// NewAnalyst builds the read-only agent session components.
func NewAnalyst(cfg AnalystConfig) (*Analyst, error) {
	if cfg.Provider == nil {
		return nil, fmt.Errorf("analyst provider is required")
	}
	dir := strings.TrimSpace(cfg.WorkingDir)
	if dir == "" {
		return nil, fmt.Errorf("analyst working directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve analyst directory: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("analyst directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("analyst directory is not a directory")
	}
	logf := cfg.Logger
	if logf == nil {
		logf = func(string) {}
	}
	maxTurns := cfg.MaxTurns
	if maxTurns <= 0 {
		maxTurns = defaultAnalystTurns
	}
	analyst := &Analyst{
		provider:   cfg.Provider,
		model:      cfg.Model,
		workingDir: abs,
		maxTurns:   maxTurns,
		telemetry:  cfg.Telemetry,
		logf:       logf,
	}
	analyst.tools = []tool.CoreTool{
		analystListTool(abs),
		analystReadTool(abs),
		analystSearchTool(abs),
	}
	if cfg.Telemetry != nil {
		analyst.tools = append(analyst.tools, analystTelemetryTool(cfg.Telemetry))
	}
	analyst.hooks = hook.NewRegistry().On(hook.PreToolUse, func(_ context.Context, event hook.Event) hook.Result {
		switch event.ToolName {
		case "SourceList", "SourceRead", "SourceSearch", "TelemetryQuery":
			return hook.Result{}
		}
		return hook.Result{Decision: "block", Message: "only the read-only source and telemetry tools are available"}
	})
	return analyst, nil
}

// ConfiguredAnalyst builds the analyst from environment variables. It returns
// (nil, nil) when no model is configured, so detection feedback still works
// without an LLM.
func ConfiguredAnalyst(workingDir string, telemetry *TelemetryDB, logf func(string)) (*Analyst, error) {
	llmProvider, model, err := configuredProvider()
	if err != nil {
		return nil, err
	}
	if llmProvider == nil {
		return nil, nil
	}
	return NewAnalyst(AnalystConfig{
		Provider:   llmProvider,
		Model:      model,
		WorkingDir: workingDir,
		Telemetry:  telemetry,
		Logger:     logf,
	})
}

// configuredProvider builds the model backend from the detection environment.
// A missing model or credential returns (nil, "", nil).
func configuredProvider() (llm.Provider, string, error) {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("EMP3R0R_DETECTION_PROVIDER")))
	if provider == "" {
		provider = "anthropic"
	}
	model := strings.TrimSpace(os.Getenv("EMP3R0R_DETECTION_MODEL"))
	switch provider {
	case "anthropic":
		if model == "" {
			model = strings.TrimSpace(os.Getenv("ANTHROPIC_MODEL"))
		}
		if model == "" || os.Getenv("ANTHROPIC_API_KEY") == "" {
			return nil, "", nil
		}
	case "openai", "openai-responses":
		if model == "" {
			model = strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
		}
		if model == "" || os.Getenv("OPENAI_API_KEY") == "" {
			return nil, "", nil
		}
	default:
		return nil, "", fmt.Errorf("unknown EMP3R0R_DETECTION_PROVIDER %q", provider)
	}
	format := llm.FormatAnthropic
	switch provider {
	case "openai":
		format = llm.FormatOpenAI
	case "openai-responses":
		format = llm.FormatOpenAIResponses
	}
	llmProvider, err := llm.NewProvider(llm.Config{
		Format:  format,
		BaseURL: strings.TrimSpace(os.Getenv("EMP3R0R_DETECTION_BASE_URL")),
		Model:   model,
	})
	if err != nil {
		return nil, "", fmt.Errorf("analyst provider: %w", err)
	}
	return llmProvider, model, nil
}

// ModelConfigured reports whether the environment has a usable detection
// provider and credential. It performs no network request.
func ModelConfigured() bool {
	provider, _, err := configuredProvider()
	return err == nil && provider != nil
}

// Model returns the configured model name.
func (a *Analyst) Model() string { return a.model }

// Analyze turns feedback into source edit proposals. It streams the agent loop
// and returns the final JSON answer.
func (a *Analyst) Analyze(ctx context.Context, feedback Feedback) (json.RawMessage, error) {
	prompt, err := analystPrompt(feedback)
	if err != nil {
		return nil, err
	}
	text, err := agentcore.Run(ctx, agentcore.Options{
		Provider:               a.provider,
		SystemPrompt:           []string{analystSystemPrompt},
		Tools:                  a.tools,
		PermissionMode:         permission.ModePlan,
		Hooks:                  a.hooks,
		WorkingDir:             a.workingDir,
		MaxTurns:               a.maxTurns,
		MaxTokens:              maxAnalystTokens,
		DisableBackgroundTasks: true,
		OnWarn:                 a.logf,
	}, prompt)
	if err != nil {
		return nil, fmt.Errorf("analyst run: %w", err)
	}
	analysis, err := parseAnalystAnswer(text)
	if err != nil {
		return nil, err
	}
	analysis["model"] = a.model
	out, err := json.Marshal(analysis)
	if err != nil {
		return nil, fmt.Errorf("encode analyst answer: %w", err)
	}
	if len(out) > maxAnalystPrompt {
		return trimRaw(out), nil
	}
	return out, nil
}

const analystSystemPrompt = `You are a detection-engineering reviewer for payload module source.

Input is a JSON detection feedback report: sandbox scanners, EDR alerts, and the
module source locations each indicator maps to. Your job is to propose minimal,
concrete module source edits that remove the detected indicators without
breaking the build contract or the module's behavior.

Rules:
- Inspect source with the read-only tools before proposing an edit.
- Never propose a change that adds project, module, technique, or author names to
  shipped artifacts.
- Prefer deriving literals at runtime, splitting signatures, or removing a
  behavior the scanner keys on over deleting functionality.
- Keep the module's flags, config.json schema, and build entrypoint unchanged.
- If a feedback report carries telemetry, run TelemetryQuery before proposing
  an edit. Use the findings table for the deterministic result, then the events
  table for evidence. Events carry actor_pid, target_pid, operation, process,
  target_image, path, image, protection, status, proto, endpoints, stack,
  category, signal, and payload_role. Categories include memory (ETW-TI), hook,
  and module. Filter with trace_pk, ignore signal='noise'/'baseline' unless
  corroborating another finding, and use json_extract(attrs,'$.field') for raw
  ETW fields. Only one SELECT or WITH statement is allowed.
- If an indicator has no source match, say so; it may come from a dependency or
  a build input.
- Answer with one JSON object and nothing else:
  {"summary":"one paragraph","edits":[{"file":"relative/path","line":123,"reason":"why","change":"what to change"}]}
- Omit edits you cannot ground in source you read.`

func analystPrompt(feedback Feedback) (string, error) {
	data, err := json.MarshalIndent(feedback, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode feedback: %w", err)
	}
	if len(data) > maxAnalystPrompt {
		feedback.Findings = feedback.Findings[:min(24, len(feedback.Findings))]
		feedback.SourceEdits = feedback.SourceEdits[:min(24, len(feedback.SourceEdits))]
		feedback.Notes = append(feedback.Notes, "feedback was trimmed before the analyst review")
		data, err = json.MarshalIndent(feedback, "", "  ")
		if err != nil {
			return "", fmt.Errorf("encode trimmed feedback: %w", err)
		}
	}
	return "Detection feedback:\n```json\n" + string(data) + "\n```\nPropose source edits as instructed.", nil
}

func parseAnalystAnswer(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("analyst answer is not a JSON object")
	}
	var answer map[string]any
	if err := json.Unmarshal([]byte(text[start:end+1]), &answer); err != nil {
		return nil, fmt.Errorf("decode analyst answer: %w", err)
	}
	if _, ok := answer["summary"]; !ok {
		answer["summary"] = text
	}
	if _, ok := answer["edits"]; !ok {
		answer["edits"] = []any{}
	}
	return answer, nil
}

// --- read-only source tools ------------------------------------------------

var analystSchemaPath = map[string]any{
	"type":        "string",
	"description": "Path relative to the module source root.",
}

func analystListTool(root string) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "SourceList",
		Description: "List the module source files. Takes no arguments.",
		Prompt:      "List module source files.",
		Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			index := newSourceIndex(root)
			names := make([]string, 0, len(index.files))
			for _, file := range index.files {
				names = append(names, file.rel)
			}
			return tool.Text(strings.Join(names, "\n")), nil
		},
	})
}

func analystReadTool(root string) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "SourceRead",
		Description: "Read one module source file, optionally a line range.",
		Prompt:      "Read a module source file.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":       analystSchemaPath,
				"start_line": map[string]any{"type": "integer", "description": "First line, 1-based."},
				"end_line":   map[string]any{"type": "integer", "description": "Last line, inclusive."},
			},
			"required": []string{"path"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			path, err := analystPath(root, args.Path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
			}
			if len(data) > maxSourceFileBytes {
				return tool.Errorf(fmt.Sprintf("%s exceeds the read bound", args.Path)), nil
			}
			lines := strings.Split(string(data), "\n")
			start := args.StartLine
			if start <= 0 {
				start = 1
			}
			end := args.EndLine
			if end <= 0 || end > len(lines) {
				end = len(lines)
			}
			if end < start {
				return tool.Errorf("end_line is before start_line"), nil
			}
			if end-start+1 > maxAnalystReadLines {
				end = start + maxAnalystReadLines - 1
			}
			var b strings.Builder
			for lineNo := start; lineNo <= end && lineNo <= len(lines); lineNo++ {
				fmt.Fprintf(&b, "%d: %s\n", lineNo, clipUTF8(lines[lineNo-1], 400))
			}
			return tool.Text(b.String()), nil
		},
	})
}

func analystSearchTool(root string) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "SourceSearch",
		Description: "Search module source with a regular expression.",
		Prompt:      "Search module source.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern": map[string]any{"type": "string", "description": "Go regular expression."},
				"path":    map[string]any{"type": "string", "description": "Optional file to search; default all source files."},
			},
			"required": []string{"pattern"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Pattern string `json:"pattern"`
				Path    string `json:"path"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if len(args.Pattern) > 200 {
				return tool.Errorf("pattern is too long"), nil
			}
			re, err := regexp.Compile(args.Pattern)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("invalid pattern: %v", err)), nil
			}
			files := newSourceIndex(root).files
			if args.Path != "" {
				path, err := analystPath(root, args.Path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("%v", err)), nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
				}
				rel, _ := filepath.Rel(root, path)
				files = []sourceFile{{rel: filepath.ToSlash(rel), lines: strings.Split(string(data), "\n")}}
			}
			var b strings.Builder
			hits := 0
			for _, file := range files {
				for lineNo, line := range file.lines {
					if !re.MatchString(line) {
						continue
					}
					hits++
					fmt.Fprintf(&b, "%s:%d: %s\n", file.rel, lineNo+1, clipUTF8(strings.TrimSpace(line), 300))
					if hits >= maxAnalystHits {
						return tool.Text(b.String()), nil
					}
				}
			}
			if hits == 0 {
				return tool.Text("no match"), nil
			}
			return tool.Text(b.String()), nil
		},
	})
}

func analystPath(root, supplied string) (string, error) {
	supplied = strings.TrimSpace(supplied)
	if supplied == "" || !analystSourcePath.MatchString(supplied) {
		return "", fmt.Errorf("invalid source path")
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve module directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(rootReal, filepath.FromSlash(supplied)))
	if err != nil {
		return "", fmt.Errorf("resolve source path: %w", err)
	}
	rel, err := filepath.Rel(rootReal, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	if !sourceExtensions[strings.ToLower(filepath.Ext(resolved))] {
		return "", fmt.Errorf("source path has an unsupported extension")
	}
	return resolved, nil
}

func clipUTF8(text string, limit int) string {
	if limit <= 0 || len(text) <= limit {
		return text
	}
	text = text[:limit]
	for !utf8.ValidString(text) && len(text) > 0 {
		text = text[:len(text)-1]
	}
	return text
}

const telemetrySchemaHint = `Tables:
payloads(id, payload_key, sha256, module, label, artifact_path, table_name,
  parent_id, created_at) — one row per build; table_name is a view containing
  that payload's events only.
traces(id, payload_id, run_id, external_id, module, artifact_sha256, source,
  captured_at, path, meta JSON, payload_pid, payload_image, attribution,
  coverage JSON, event_count, findings_count)
events(id, payload_id, trace_pk, event_key, ts_ns, type, source, event,
  provider, event_id, pid, tid, actor_pid, target_pid, target_tid, parent_pid,
  operation, process, target_image, path, image, address, size, protection,
  access, status, command, proto, src_addr, src_port, dst_addr, dst_port, bytes,
  stack, category, severity, signal, payload_role, attrs JSON)
findings(id, trace_pk, payload_id, stage, tool, severity, rule, indicator,
  detail, signal, created_at)
loop_cycles(loop_id, iteration, payload_id, run_id, score, level, findings,
  verdicts, trace_id, summary JSON), loop_feedback(loop_id, iteration,
  payload_id, run_id, body JSON), loop_results(loop_id, answer JSON),
  loop_builds(loop_id, iteration, payload_id,
  artifact, sha256, log), loop_edits(loop_id, iteration, payload_id,
  next_payload_id, file, old, new, reason)
Categories: process, image, module, file, network, audit, thread, defender,
query, hook, memory (ETW-TI), other.
payload_role: payload, payload-child, payload-target, payload-scan, ambient, unknown.
signal: signal, verdict, scan, info, baseline, noise.
Use trace_pk to scope one trace, or query payloads.table_name for one payload.
Use findings for the deterministic result and events for evidence; ignore
signal='noise' and signal='baseline' unless corroborating another finding.
json_extract(attrs,'$.field') reads raw ETW fields that have no column.`

func analystTelemetryTool(db *TelemetryDB) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "TelemetryQuery",
		Description: "Run one read-only SQL SELECT against the detection telemetry database. " +
			telemetrySchemaHint,
		Prompt: "Query the sandbox telemetry database.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"sql":   map[string]any{"type": "string", "description": "One SELECT or WITH statement."},
				"limit": map[string]any{"type": "integer", "description": "Maximum rows, at most 500."},
			},
			"required": []string{"sql"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				SQL   string `json:"sql"`
				Limit int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			result, err := db.Query(queryCtx, args.SQL, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, err := json.Marshal(result)
			if err != nil {
				return tool.Errorf("encode query result"), nil
			}
			return tool.Text(string(data)), nil
		},
	})
}
