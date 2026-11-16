package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
)

const (
	// maxProducerShellcodeBytes bounds one producer module artifact.
	maxProducerShellcodeBytes = 32 << 20
	// maxRevertEdits bounds one revert operation.
	maxRevertEdits = 60
)

// buildShellcodeTool runs a configured shellcode producer module with validated
// options and makes its artifact the shellcode for the next loader build.
func (e *evolver) buildShellcodeTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "BuildShellcode",
		Description: "Run a configured shellcode producer module (donut or crystal_pack) with validated options. " +
			"The output is written under the detection store and becomes the shellcode every later DetectionCycle loads. " +
			"Call GenerateAgent first when a dynamic cycle needs a fresh agent UUID; reusing a shellcode violates TOFU. " +
			"Editing the producer module first (module=\"donut\") changes how the generator itself behaves. " +
			"crystal_pack requires a DLL: call GenerateAgent with agent_type=windows_dll and pass its artifact_path as the dll option.",
		Prompt: "Build shellcode with a producer module.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"producer": map[string]any{
					"type":        "string",
					"description": "Producer module name: donut or crystal_pack.",
				},
				"options": map[string]any{
					"type":                 "object",
					"description":          "Producer parameters declared in its config.json; values are strings.",
					"additionalProperties": map[string]any{"type": "string"},
				},
				"note": map[string]any{"type": "string", "description": "What this producer change is testing."},
			},
			"required": []string{"producer"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Producer string            `json:"producer"`
				Options  map[string]string `json:"options"`
				Note     string            `json:"note"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			artifact, flags, buildLog, err := e.buildShellcodeWithProducer(ctx, args.Producer, args.Options, args.Note)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			out := map[string]any{
				"producer":   e.activeProducer,
				"path":       artifact.Path,
				"sha256":     artifact.SHA256,
				"size":       artifact.Size,
				"active":     true,
				"message":    "the next DetectionCycle builds the loader with this shellcode",
				"options":    sanitizeProducerOptions(flags),
				"build_tail": lastLines(buildLog, 12),
			}
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}

func validateProducerOptions(producer string, declared def.ModOptions, supplied map[string]string, deferred string) (map[string]string, error) {
	flags := map[string]string{}
	for name, value := range supplied {
		opt, ok := declared[name]
		if !ok || opt == nil {
			return nil, fmt.Errorf("%s has no option %q; available: %s", producer, name, producerOptionNames(declared))
		}
		if opt.Internal {
			return nil, fmt.Errorf("%s option %q is filled in by the C2", producer, name)
		}
		if err := modconfig.ValidateOption(opt, value); err != nil {
			return nil, fmt.Errorf("%s option %q: %w", producer, name, err)
		}
		flags[name] = value
	}
	for name, opt := range declared {
		if opt == nil || opt.Internal || !opt.Required {
			continue
		}
		// The input parameter is resolved by the host, not the model, so its
		// required check runs after producerInput fills it.
		if name == deferred {
			continue
		}
		if strings.TrimSpace(flags[name]) == "" {
			return nil, fmt.Errorf("%s requires option %q", producer, name)
		}
	}
	return flags, nil
}

func producerOptionNames(declared def.ModOptions) string {
	names := make([]string, 0, len(declared))
	for name, opt := range declared {
		if opt == nil || opt.Internal {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// producerInputName finds the parameter that receives the input PE.
func producerInputName(producer string, declared def.ModOptions) (string, error) {
	if _, ok := declared["input"]; ok {
		return "input", nil
	}
	if _, ok := declared["dll"]; ok {
		return "dll", nil
	}
	for name, opt := range declared {
		if opt != nil && opt.Required && !opt.Internal {
			return name, nil
		}
	}
	return "", fmt.Errorf("%s declares no input parameter", producer)
}

// validateProducerPathOption keeps every file-path option a producer accepts
// inside the operator payload directory. An option such as donut's decoy is
// embedded into the generated shellcode, so it must not read arbitrary host
// files; symlinks and non-regular files are rejected.
func validateProducerPathOption(name, value, baseDir string) error {
	switch name {
	case "input", "dll", "decoy":
	default:
		return nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return fmt.Errorf("resolve %s %q: %w", name, value, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("inspect %s %q: %w", name, value, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %q is a symlink", name, value)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %q is not a regular file", name, value)
	}
	if err := ensureWithin(baseDir, abs); err != nil {
		return fmt.Errorf("%s %q is outside the operator payload directory", name, value)
	}
	return nil
}

// producerInput validates the input PE. The host-built agent is the only
// default, so the model cannot point a producer at an arbitrary file.
func (e *evolver) producerInput(producer, inputName, value string) (string, error) {
	input := strings.TrimSpace(value)
	if input == "" {
		// Rotation and the default producer run use the agent the host just
		// built. A producer that needs a DLL gets the same artifact.
		input = e.agentArtifact
		if input == "" {
			input = strings.TrimSuffix(e.activeShellcode(), ".bin")
		}
	}
	if input == "" {
		return "", fmt.Errorf("%s requires %q", producer, inputName)
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return "", fmt.Errorf("resolve input: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("input %q is not a regular file", input)
	}
	switch strings.ToLower(filepath.Ext(abs)) {
	case ".exe", ".dll", ".bin":
	default:
		return "", fmt.Errorf("input %q must be a PE or shellcode file", input)
	}
	base, err := filepath.Abs(e.payloadDir())
	if err != nil {
		return "", fmt.Errorf("resolve payload directory: %w", err)
	}
	if err := ensureWithin(base, abs); err != nil {
		return "", fmt.Errorf("input %q is outside the operator payload directory", input)
	}
	return abs, nil
}

func ensureWithin(root, path string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("path escapes the root")
	}
	return nil
}

func producerArtifact(buildLog, want string) (Artifact, error) {
	payloads := ParseGeneratedPayloads(buildLog)
	wantAbs, _ := filepath.Abs(want)
	reported := false
	for _, payload := range payloads {
		if abs, err := filepath.Abs(payload.Path); err == nil && abs == wantAbs {
			reported = true
			break
		}
	}
	if !reported {
		// Some producers print their own output line, for example
		// "[+] PICO shellcode written to ...", instead of the generated-payload
		// marker. The requested path still has to appear in the build log.
		reported = strings.Contains(buildLog, wantAbs)
	}
	if !reported {
		return Artifact{}, fmt.Errorf("producer did not report %s as its generated payload", want)
	}
	artifact, err := InspectArtifact(wantAbs)
	if err != nil {
		return Artifact{}, err
	}
	if artifact.Size <= 0 || artifact.Size > maxProducerShellcodeBytes {
		return Artifact{}, fmt.Errorf("producer output size %d is out of bounds", artifact.Size)
	}
	artifact.Kind = "shellcode"
	return artifact, nil
}

// buildShellcodeWithProducer validates the producer options, runs the
// producer, records the output, and makes it the active shellcode. The model
// tool and automatic agent rotation share this path.
func (e *evolver) buildShellcodeWithProducer(ctx context.Context, producerName string, supplied map[string]string, note string) (Artifact, map[string]string, string, error) {
	producer, dir, err := e.producer(producerName)
	if err != nil {
		return Artifact{}, nil, "", err
	}
	configs, err := modconfig.ReadConfigs(filepath.Join(dir, "config.json"))
	if err != nil {
		return Artifact{}, nil, "", fmt.Errorf("read %s module config: %w", producer, err)
	}
	var options def.ModOptions
	for _, cfg := range configs {
		if cfg != nil && strings.EqualFold(cfg.Name, producer) {
			options = cfg.Options
			break
		}
	}
	if options == nil {
		return Artifact{}, nil, "", fmt.Errorf("%s is not defined in %s/config.json", producer, dir)
	}
	inputName, err := producerInputName(producer, options)
	if err != nil {
		return Artifact{}, nil, "", err
	}
	flags, err := validateProducerOptions(producer, options, supplied, inputName)
	if err != nil {
		return Artifact{}, nil, "", err
	}
	payloadDir, err := filepath.Abs(e.payloadDir())
	if err != nil {
		return Artifact{}, nil, "", fmt.Errorf("resolve payload directory: %w", err)
	}
	for name, value := range flags {
		if err := validateProducerPathOption(name, value, payloadDir); err != nil {
			return Artifact{}, nil, "", err
		}
	}
	input, err := e.producerInput(producer, inputName, flags[inputName])
	if err != nil {
		return Artifact{}, nil, "", err
	}
	flags[inputName] = input
	e.shellSeq++
	outDir := filepath.Join(e.cfg.StoreRoot, "shellcode", sanitizeName(e.cfg.LoopID))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Artifact{}, nil, "", fmt.Errorf("create shellcode directory: %w", err)
	}
	output := filepath.Join(outDir, fmt.Sprintf("%s-%d.bin", producer, e.shellSeq))
	flags["output"] = output
	e.logClass(logging.ClassBuild, "producer %s: building %s -> %s", producer, input, output)
	build := e.cfg.BuildProducer
	if build == nil {
		build = modules.BuildLocalModuleAt
	}
	buildLog, buildErr := build(dir, producer, flags)
	if len(buildLog) > maxEvolveBuildLog {
		buildLog = buildLog[:maxEvolveBuildLog] + "\n[build log truncated]\n"
	}
	e.logClass(logging.ClassBuild, "%s", buildLog)
	if buildErr != nil {
		return Artifact{}, nil, buildLog, fmt.Errorf("producer %s build failed: %w", producer, buildErr)
	}
	artifact, err := producerArtifact(buildLog, output)
	if err != nil {
		return Artifact{}, nil, buildLog, err
	}
	if artifact.Size < minAgentShellcodeBytes {
		return Artifact{}, nil, buildLog, fmt.Errorf("producer output is only %d bytes; a real agent shellcode is larger", artifact.Size)
	}
	if err := ensureWithin(filepath.Join(e.cfg.StoreRoot, "shellcode"), artifact.Path); err != nil {
		return Artifact{}, nil, buildLog, fmt.Errorf("producer output escapes the detection store")
	}
	if err := e.saveShellcode(ctx, producer, artifact, flags, note); err != nil {
		return Artifact{}, nil, buildLog, fmt.Errorf("record shellcode: %w", err)
	}
	oldShellcode := e.shellcode
	e.shellcode = artifact.Path
	e.cleanupShellcode(oldShellcode)
	e.activeProducer = producer
	return artifact, flags, buildLog, nil
}

func (e *evolver) saveShellcode(ctx context.Context, producer string, artifact Artifact, options map[string]string, note string) error {
	encoded, _ := json.Marshal(sanitizeProducerOptions(options))
	if e.db != nil && e.db.db != nil {
		if _, err := e.db.db.ExecContext(ctx, `
			INSERT INTO loop_shellcodes(loop_id, iteration, producer, path, sha256, size, options, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			e.cfg.LoopID, e.iter+1, producer, artifact.Path, artifact.SHA256, artifact.Size,
			string(encoded), time.Now().UTC().UnixMilli()); err != nil {
			return err
		}
	}
	e.logClass(logging.ClassEdit, "shellcode: %s %s (%d bytes) note=%s", producer, shortSHA(artifact.SHA256), artifact.Size, clip(sanitizeLine(note), 200))
	return nil
}

func sanitizeProducerOptions(options map[string]string) map[string]string {
	out := make(map[string]string, len(options))
	for key, value := range options {
		if key == "output" {
			continue
		}
		out[key] = clip(value, 300)
	}
	return out
}

func lastLines(text string, n int) []string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// revertPayloadTool undoes every source edit that produced payloads newer than
// the selected one. It is the rollback path when a redesign regresses.
func (e *evolver) revertPayloadTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "RevertToPayload",
		Description: "Undo every recorded source edit made after the selected payload, restoring the source and producer " +
			"state that produced it. Use it after a cycle regresses before trying another hypothesis. Then call DetectionCycle.",
		Prompt: "Revert source edits to an earlier payload.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"payload_key": map[string]any{"type": "string", "description": "Payload key (sha256:...) to restore."},
			},
			"required": []string{"payload_key"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				PayloadKey string `json:"payload_key"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			reverted, err := e.revertToPayload(ctx, args.PayloadKey)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(map[string]any{
				"payload":  args.PayloadKey,
				"reverted": reverted,
				"message":  "source restored; call DetectionCycle to verify",
			})
			return tool.Text(string(data)), nil
		},
	})
}

type revertEdit struct {
	id     int64
	module string
	file   string
	old    string
	new    string
}

func (e *evolver) revertToPayload(ctx context.Context, payloadKey string) (int, error) {
	payloadKey = strings.TrimSpace(payloadKey)
	id, err := payloadIDByKey(ctx, e.db.db, payloadKey)
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return 0, fmt.Errorf("payload %q is not recorded", payloadKey)
	}
	rows, err := e.db.db.QueryContext(ctx, `
		SELECT id, COALESCE(module, ''), file, old, new FROM loop_edits
		WHERE loop_id = ? AND next_payload_id IS NOT NULL AND next_payload_id > ?
		ORDER BY id DESC LIMIT ?`, e.cfg.LoopID, id, maxRevertEdits+1)
	if err != nil {
		return 0, fmt.Errorf("read edit history: %w", err)
	}
	edits, err := scanRevertEdits(rows)
	if err != nil {
		return 0, err
	}
	if len(edits) == 0 {
		return 0, fmt.Errorf("no recorded edits were made after payload %q", payloadKey)
	}
	if len(edits) > maxRevertEdits {
		return 0, fmt.Errorf("more than %d edits were made after payload %q; revert in smaller steps", maxRevertEdits, payloadKey)
	}
	return e.applyRevertEdits(ctx, edits, e.lastPayloadID(), payloadKey)
}

// revertCycleEdits undoes only the edits linked to one failed payload. The
// automatic execution gate uses this so a later failed cycle does not replay
// the source edits that an earlier auto-revert already undid.
func (e *evolver) revertCycleEdits(ctx context.Context, payloadID int64, label string) (int, error) {
	if payloadID == 0 {
		return 0, fmt.Errorf("failed payload id is required")
	}
	rows, err := e.db.db.QueryContext(ctx, `
		SELECT id, COALESCE(module, ''), file, old, new FROM loop_edits
		WHERE loop_id = ? AND next_payload_id = ?
		ORDER BY id DESC LIMIT ?`, e.cfg.LoopID, payloadID, maxRevertEdits+1)
	if err != nil {
		return 0, fmt.Errorf("read failed-cycle edits: %w", err)
	}
	edits, err := scanRevertEdits(rows)
	if err != nil {
		return 0, err
	}
	if len(edits) == 0 {
		return 0, nil
	}
	if len(edits) > maxRevertEdits {
		return 0, fmt.Errorf("more than %d edits produced payload %s; revert in smaller steps", maxRevertEdits, label)
	}
	return e.applyRevertEdits(ctx, edits, payloadID, label)
}

func scanRevertEdits(rows *sql.Rows) ([]revertEdit, error) {
	defer rows.Close()
	var edits []revertEdit
	for rows.Next() {
		var item revertEdit
		if err := rows.Scan(&item.id, &item.module, &item.file, &item.old, &item.new); err != nil {
			return nil, err
		}
		edits = append(edits, item)
	}
	return edits, rows.Err()
}

func (e *evolver) lastPayloadID() int64 {
	if e.last == nil {
		return 0
	}
	return e.last.PayloadID
}

func (e *evolver) applyRevertEdits(ctx context.Context, edits []revertEdit, payloadID int64, label string) (int, error) {
	for _, item := range edits {
		root, err := e.roots.pick(item.module)
		if err != nil {
			return 0, err
		}
		if !root.Writable {
			return 0, fmt.Errorf("source root %s is read-only", root.Name)
		}
		write, err := writeSourceFile(root, item.file, item.new, item.old)
		if err != nil {
			return 0, fmt.Errorf("revert %s/%s: %w", root.Name, item.file, err)
		}
		if err := e.db.SaveEdit(ctx, EditRecord{
			LoopID: e.cfg.LoopID, Iteration: e.iter + 1, PayloadID: payloadID,
			Module: root.Name, File: item.file, Old: item.new, New: item.old,
			Reason: "revert to payload " + label,
		}); err != nil {
			if restoreErr := restoreSourceFile(write.Path, write.Original); restoreErr != nil {
				return 0, fmt.Errorf("save revert: %w (restore %s failed: %v)", err, item.file, restoreErr)
			}
			return 0, fmt.Errorf("save revert: %w", err)
		}
		e.logClass(logging.ClassEdit, "revert %s/%s", root.Name, item.file)
	}
	return len(edits), nil
}

// ------------------------------------------------------------------ knowledge

func (e *evolver) knowledgeSearchTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "KnowledgeSearch",
		Description: "Search the offline offensive-security reference cache (maldev, edrdev, redteam, amsi, " +
			"staticanalysis, vulndrivers, crystalstardust, com, lsass, defender, mynotebook). Query with two or " +
			"three concrete tokens: the mechanism plus the exact detector, API, event, or analyzer. Title and " +
			"summary rank above content. A hit locates a document; its snippet is not evidence of detection " +
			"behavior. Hits are deduplicated by URL across notebooks. Trusted reference; verify each technique " +
			"against this payload's telemetry.",
		Prompt: "Search the reference cache before choosing or editing a mechanism.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query":    map[string]any{"type": "string", "description": "Two or three concrete tokens, for example module stomping pe-sieve."},
				"notebook": map[string]any{"type": "string", "description": "Optional exact notebook filter; omit it unless the surface is ambiguous."},
				"limit":    map[string]any{"type": "integer", "description": "Maximum hits, default 10, at most 20; start with 5."},
			},
			"required": []string{"query"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Query    string `json:"query"`
				Notebook string `json:"notebook"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.knowledge == nil {
				return tool.Errorf("knowledge cache is empty; ask the operator to run detect_loop knowledge-sync"), nil
			}
			hits, err := e.knowledge.Search(ctx, args.Query, args.Notebook, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if len(hits) == 0 {
				return tool.Text("no cached document matched"), nil
			}
			data, _ := json.Marshal(map[string]any{
				"query": args.Query, "hits": hits,
				"note": "reference material; verify against the module before relying on it",
			})
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) knowledgeReadTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "KnowledgeRead",
		Description: "Read one cached document by document_ref from KnowledgeSearch. Start with summary. When the " +
			"summary names the detector or API under test, read content for implementation and telemetry detail; " +
			"content is cached only for documents synced with --content. If content is not cached, the summary is " +
			"returned with fallback=true. Page with offset and next_offset, request only what is needed, and stop " +
			"when the mechanism is clear.",
		Prompt: "Read the summary, then the content only for the detail the edit needs.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"document_ref": map[string]any{"type": "string", "description": "document_ref from KnowledgeSearch."},
				"artifact":     map[string]any{"type": "string", "description": "summary (default) or content; content may be uncached."},
				"offset":       map[string]any{"type": "integer", "description": "Byte offset into the artifact."},
				"limit":        map[string]any{"type": "integer", "description": "Maximum bytes, at most 512 KiB; default 8 KiB."},
			},
			"required": []string{"document_ref"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				DocumentRef string `json:"document_ref"`
				Artifact    string `json:"artifact"`
				Offset      int    `json:"offset"`
				Limit       int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.knowledge == nil {
				return tool.Errorf("knowledge cache is empty; ask the operator to run detect_loop knowledge-sync"), nil
			}
			doc, err := e.knowledge.Read(ctx, args.DocumentRef, args.Artifact, args.Offset, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(doc)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) knowledgeStatsTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "KnowledgeStats",
		Description: "Return cache coverage by notebook: document counts, summaries, and full-content counts. " +
			"Use it before searching when the right notebook or content coverage is unclear.",
		Prompt:     "Check which notebooks and content are cached.",
		Schema:     map[string]any{"type": "object", "properties": map[string]any{}},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, _ json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			if e.knowledge == nil {
				return tool.Errorf("knowledge cache is empty; ask the operator to run detect_loop knowledge-sync"), nil
			}
			stats, err := e.knowledge.Stats(ctx)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(stats)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) knowledgeListTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "KnowledgeList",
		Description: "List cached document references, titles, URLs, and whether summary or content is available. " +
			"Optionally filter by notebook. Use KnowledgeRead only on the selected documents.",
		Prompt: "List cached documents when search terms are not yet clear.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"notebook": map[string]any{"type": "string", "description": "Optional exact notebook filter."},
				"limit":    map[string]any{"type": "integer", "description": "Maximum documents, default 100, at most 200."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Notebook string `json:"notebook"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.knowledge == nil {
				return tool.Errorf("knowledge cache is empty; ask the operator to run detect_loop knowledge-sync"), nil
			}
			docs, err := e.knowledge.List(ctx, args.Notebook, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(map[string]any{"documents": docs, "count": len(docs)})
			return tool.Text(string(data)), nil
		},
	})
}
