package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// Loop memory is the loop's own knowledge base, separate from the remotely
// synced knowledge cache. A verified cycle records the technique it tested,
// the detection findings that changed, the score, and a link to the exact
// source edits, so a later planner can ask "what worked for this rule before".

type memoryFinding struct {
	Rule      string
	Indicator string
	Stage     string
	Severity  string
	Direction string
}

func (f memoryFinding) key() string {
	if f.Rule != "" {
		return f.Rule + "\x00" + f.Indicator
	}
	return "\x00" + f.Indicator
}

// parseMemoryFinding splits a stored top-finding line such as
// "high pe/checksum PE checksum" into severity, rule, and indicator.
func parseMemoryFinding(text string) (memoryFinding, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return memoryFinding{}, false
	}
	fields := strings.Fields(text)
	severity := ""
	rest := text
	if len(fields) > 0 {
		switch strings.ToLower(fields[0]) {
		case "critical", "high", "medium", "low", "info":
			severity = strings.ToLower(fields[0])
			rest = strings.TrimSpace(strings.TrimPrefix(text, fields[0]))
		}
	}
	rule := ""
	indicator := rest
	if parts := strings.Fields(rest); len(parts) > 0 && strings.Contains(parts[0], "/") {
		rule = parts[0]
		indicator = strings.TrimSpace(strings.TrimPrefix(rest, parts[0]))
	}
	if rule == "" && indicator == "" {
		return memoryFinding{}, false
	}
	stage := ""
	switch {
	case strings.HasPrefix(rule, "telemetry/"):
		stage = string(StageTelemetry)
	case strings.HasPrefix(rule, "pe/"), strings.HasPrefix(rule, "analyzer/static"):
		stage = string(StageStatic)
	case strings.HasPrefix(rule, "analyzer/dynamic"):
		stage = string(StageDynamic)
	}
	return memoryFinding{Rule: rule, Indicator: indicator, Stage: stage, Severity: severity}, true
}

func memoryFindings(summary cycleSummary) map[string]memoryFinding {
	out := map[string]memoryFinding{}
	for _, top := range summary.TopFindings {
		finding, ok := parseMemoryFinding(top)
		if !ok {
			continue
		}
		if existing, ok := out[finding.key()]; !ok || memorySeverityRank(finding.Severity) > memorySeverityRank(existing.Severity) {
			out[finding.key()] = finding
		}
	}
	return out
}

func memorySeverityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// memoryStaticFindings returns the static hygiene surface of a cycle: the
// dedicated hygiene backlog plus any static finding that reached the top list.
// Some deterministic rules (pe/checksum, pe/sections) never enter the top
// eight, so the backlog is the authoritative source for them.
func memoryStaticFindings(summary cycleSummary) map[string]memoryFinding {
	out := map[string]memoryFinding{}
	for _, item := range summary.Hygiene {
		finding, ok := parseMemoryFinding(item.Rule + " " + item.Indicator)
		if !ok {
			continue
		}
		if strings.TrimSpace(item.Severity) != "" {
			finding.Severity = strings.ToLower(item.Severity)
		}
		finding.Stage = string(StageStatic)
		out[finding.key()] = finding
	}
	for _, top := range summary.TopFindings {
		finding, ok := parseMemoryFinding(top)
		if !ok || finding.Stage != string(StageStatic) {
			continue
		}
		if existing, ok := out[finding.key()]; !ok || memorySeverityRank(finding.Severity) > memorySeverityRank(existing.Severity) {
			out[finding.key()] = finding
		}
	}
	return out
}

// memoryDynamicFindings returns the stable dynamic/telemetry rules. Analyzer
// summaries with no rule and address-specific lines ("Base: 0x...", size,
// protection) are not usable technique targets: they change every run.
func memoryDynamicFindings(summary cycleSummary) map[string]memoryFinding {
	out := map[string]memoryFinding{}
	for _, top := range summary.TopFindings {
		finding, ok := parseMemoryFinding(top)
		if !ok || finding.Rule == "" {
			continue
		}
		if finding.Stage != string(StageTelemetry) && finding.Stage != string(StageDynamic) &&
			!strings.HasPrefix(finding.Rule, "analyzer/dynamic") {
			continue
		}
		if memoryVolatileFinding(finding) {
			continue
		}
		out[finding.key()] = finding
	}
	return out
}

func memoryVolatileFinding(finding memoryFinding) bool {
	text := strings.ToLower(finding.Rule + " " + finding.Indicator)
	for _, marker := range []string{"base:", "protection:", "size:", "at base"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	for _, field := range strings.Fields(text) {
		if len(field) >= 10 && strings.HasPrefix(field, "0x") {
			return true
		}
	}
	return false
}

// diffMemoryFindings returns the findings a cycle removed and added relative
// to its comparison baseline. A static-hygiene cycle only claims static rules;
// a dynamic change under a static edit is not the edit's effect.
func diffMemoryFindings(previous, current cycleSummary, mechanism string) (removed, added []memoryFinding) {
	before := memoryStaticFindings(previous)
	after := memoryStaticFindings(current)
	if !strings.EqualFold(strings.TrimSpace(mechanism), "static-hygiene") {
		for key, finding := range memoryDynamicFindings(previous) {
			before[key] = finding
		}
		for key, finding := range memoryDynamicFindings(current) {
			after[key] = finding
		}
	}
	for key, finding := range before {
		if _, ok := after[key]; !ok {
			finding.Direction = "removed"
			removed = append(removed, finding)
		}
	}
	for key, finding := range after {
		if _, ok := before[key]; !ok {
			finding.Direction = "added"
			added = append(added, finding)
		}
	}
	sortMemoryFindings(removed)
	sortMemoryFindings(added)
	return removed, added
}

func sortMemoryFindings(findings []memoryFinding) {
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := memorySeverityRank(findings[i].Severity), memorySeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		return findings[i].Indicator < findings[j].Indicator
	})
}

// memoryScore weights a verified change by the metric it improves. A removal
// is positive; an addition is negative. High findings dominate hygiene, which
// dominates static signatures, matching the loop's comparison order.
func memoryScore(previous, current findingCounts) float64 {
	high := previous.DetectionHigh - current.DetectionHigh
	hygieneHigh := previous.HygieneHigh - current.HygieneHigh
	medium := previous.DetectionMedium - current.DetectionMedium
	hygieneMedium := previous.HygieneMedium - current.HygieneMedium
	static := previous.Static - current.Static
	return 4*float64(high) + 3*float64(hygieneHigh) + 2*float64(medium) + 1*float64(hygieneMedium) + 1*float64(static)
}

func memoryTechniqueName(mechanism string, target memoryFinding, direction string, files []string) string {
	if mechanism == "" {
		mechanism = "other"
	}
	label := target.Rule
	if label == "" {
		label = target.Indicator
	}
	if label == "" {
		label = "finding"
	}
	name := mechanism + "|" + direction + ":" + label
	if len(files) > 0 {
		name += "|" + strings.Join(files, ",")
	}
	return clipUTF8(name, 180)
}

// recordTechniqueMemory persists a verified observation after the execution
// gate has accepted or rejected the cycle. Invalid observations (offline,
// incomplete coverage, first sighting of a changed instrumentation set) are
// not learned from, so the memory cannot teach the loop noise.
func (e *evolver) recordTechniqueMemory(ctx context.Context, cycle Cycle, summary cycleSummary, gate executionGate) {
	if e == nil || e.db == nil || e.db.db == nil {
		return
	}
	if summary.Execution != executionVerified || !coverageComplete(summary) {
		return
	}
	if gate != gateExecuting && gate != gateRegressed {
		return
	}
	previous := e.lastComparison
	if previous == nil {
		previous = e.comparisonBaselineFor(&cycle, &summary)
	}
	if previous == nil {
		return
	}
	var previousSummary cycleSummary
	if json.Unmarshal([]byte(previous.Summary), &previousSummary) != nil {
		return
	}
	previousCounts := cycleFindingCounts(previous)
	currentCounts := summaryFindingCounts(summary, cycle.Findings)
	mechanism := strings.TrimSpace(summary.Mechanism)
	removed, added := diffMemoryFindings(previousSummary, summary, mechanism)
	if len(removed) == 0 && len(added) == 0 {
		return
	}
	target := memoryFinding{Rule: "finding", Indicator: "no top-finding change"}
	direction := "removed"
	if len(removed) > 0 {
		target = removed[0]
	} else {
		target = added[0]
		direction = "added"
	}

	loopID := strings.TrimSpace(cycle.LoopID)
	if loopID == "" {
		loopID = e.cfg.LoopID
	}
	tx, err := e.db.db.BeginTx(ctx, nil)
	if err != nil {
		e.logClass(logging.ClassWarning, "loop memory: begin: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	editRows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(module, ''), file, reason
		FROM loop_edits
		WHERE loop_id = ? AND iteration = ? AND kind = ? AND reverted = 0
		ORDER BY id`, loopID, cycle.Iteration, EditKindModel)
	if err != nil {
		e.logClass(logging.ClassWarning, "loop memory: read edits: %v", err)
		return
	}
	type memoryEdit struct {
		id     int64
		module string
		file   string
		reason string
	}
	var edits []memoryEdit
	for editRows.Next() {
		var item memoryEdit
		if err := editRows.Scan(&item.id, &item.module, &item.file, &item.reason); err != nil {
			_ = editRows.Close()
			return
		}
		edits = append(edits, item)
	}
	_ = editRows.Close()
	if err := editRows.Err(); err != nil {
		return
	}

	fileSet := map[string]bool{}
	var files []string
	var reasons []string
	module := ""
	for _, edit := range edits {
		path := edit.file
		if edit.module != "" {
			path = edit.module + "/" + edit.file
			if module == "" {
				module = edit.module
			}
		}
		if !fileSet[path] {
			fileSet[path] = true
			files = append(files, path)
		}
		if strings.TrimSpace(edit.reason) != "" {
			reasons = append(reasons, strings.TrimSpace(edit.reason))
		}
	}
	sort.Strings(files)
	note := strings.TrimSpace(summary.Note)
	if len(reasons) > 0 {
		if note != "" {
			note += " | "
		}
		note += strings.Join(reasons, " | ")
	}
	note = clipUTF8(note, 4000)
	name := memoryTechniqueName(mechanism, target, direction, files)
	score := memoryScore(previousCounts, currentCounts)
	win, loss := 0, 0
	if score > 0 {
		win = 1
	} else if score < 0 {
		loss = 1
	}
	now := time.Now().UnixMilli()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loop_memory_techniques
			(mechanism, name, module, files, note, samples, wins, losses, avg_score, best_score, last_score, last_loop, last_iteration, last_trace, updated_at)
		VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mechanism, name) DO UPDATE SET
			samples = samples + 1,
			wins = wins + excluded.wins,
			losses = losses + excluded.losses,
			avg_score = (avg_score * samples + excluded.last_score) / (samples + 1),
			best_score = MAX(best_score, excluded.last_score),
			last_score = excluded.last_score,
			note = CASE WHEN note = '' OR excluded.last_score >= last_score THEN excluded.note ELSE note END,
			module = CASE WHEN excluded.module <> '' THEN excluded.module ELSE module END,
			files = CASE WHEN excluded.files <> '' THEN excluded.files ELSE files END,
			last_loop = excluded.last_loop,
			last_iteration = excluded.last_iteration,
			last_trace = excluded.last_trace,
			updated_at = excluded.updated_at`,
		mechanism, name, module, strings.Join(files, ","), note, win, loss, score, score, score, loopID, cycle.Iteration, cycle.TraceID, now); err != nil {
		e.logClass(logging.ClassWarning, "loop memory: upsert technique: %v", err)
		return
	}
	var techniqueID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM loop_memory_techniques WHERE mechanism = ? AND name = ?`,
		mechanism, name).Scan(&techniqueID); err != nil {
		e.logClass(logging.ClassWarning, "loop memory: technique id: %v", err)
		return
	}

	link := func(findings []memoryFinding) {
		for _, finding := range findings {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO loop_memory_findings
					(rule, indicator, stage, severity, occurrences, first_loop, last_loop, updated_at)
				VALUES(?, ?, ?, ?, 1, ?, ?, ?)
				ON CONFLICT(rule, indicator) DO UPDATE SET
					occurrences = occurrences + 1,
					severity = CASE WHEN excluded.severity <> '' THEN excluded.severity ELSE severity END,
					stage = CASE WHEN excluded.stage <> '' THEN excluded.stage ELSE stage END,
					last_loop = excluded.last_loop,
					updated_at = excluded.updated_at`,
				finding.Rule, finding.Indicator, finding.Stage, finding.Severity, loopID, loopID, now); err != nil {
				return
			}
			var findingID int64
			if err := tx.QueryRowContext(ctx,
				`SELECT id FROM loop_memory_findings WHERE rule = ? AND indicator = ?`,
				finding.Rule, finding.Indicator).Scan(&findingID); err != nil {
				return
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO loop_memory_links(technique_id, finding_id, direction, count, last_loop, last_iteration)
				VALUES(?, ?, ?, 1, ?, ?)
				ON CONFLICT(technique_id, finding_id, direction) DO UPDATE SET
					count = count + 1,
					last_loop = excluded.last_loop,
					last_iteration = excluded.last_iteration`,
				techniqueID, findingID, finding.Direction, loopID, cycle.Iteration); err != nil {
				return
			}
		}
	}
	link(removed)
	link(added)

	delivered := ""
	if summary.Telemetry != nil {
		delivered = strings.Join(summary.Telemetry.Coverage.Delivered, ",")
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO loop_memory_evidence
			(technique_id, loop_id, iteration, trace_id, score, execution, coverage, note, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		techniqueID, loopID, cycle.Iteration, cycle.TraceID, score, summary.Execution,
		delivered, note, now); err != nil {
		e.logClass(logging.ClassWarning, "loop memory: evidence: %v", err)
		return
	}
	for _, edit := range edits {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO loop_memory_edits(technique_id, edit_id) VALUES(?, ?)`,
			techniqueID, edit.id); err != nil {
			return
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM loop_memory_evidence
		WHERE technique_id = ? AND id NOT IN (
			SELECT id FROM loop_memory_evidence WHERE technique_id = ? ORDER BY id DESC LIMIT 20
		)`, techniqueID, techniqueID); err != nil {
		return
	}
	if err := tx.Commit(); err != nil {
		e.logClass(logging.ClassWarning, "loop memory: commit: %v", err)
	}
}

// memoryTechnique is one row returned by the LoopMemory tool and brief.
type memoryTechnique struct {
	ID            int64           `json:"id"`
	Mechanism     string          `json:"mechanism"`
	Name          string          `json:"name"`
	Module        string          `json:"module,omitempty"`
	Files         string          `json:"files,omitempty"`
	Note          string          `json:"note,omitempty"`
	Samples       int             `json:"samples"`
	Wins          int             `json:"wins"`
	Losses        int             `json:"losses"`
	AvgScore      float64         `json:"avg_score"`
	BestScore     float64         `json:"best_score"`
	LastLoop      string          `json:"last_loop,omitempty"`
	LastIteration int             `json:"last_iteration,omitempty"`
	Direction     string          `json:"direction,omitempty"`
	Count         int             `json:"count,omitempty"`
	Examples      []memoryExample `json:"examples,omitempty"`
}

type memoryExample struct {
	File   string `json:"file"`
	Reason string `json:"reason,omitempty"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
}

// memorySearch returns verified techniques for a rule, a free-text query, or
// the highest-scoring techniques when neither is given.
func (e *evolver) memorySearch(ctx context.Context, rule, mechanism, query string, limit int) ([]memoryTechnique, error) {
	if e == nil || e.db == nil || e.db.db == nil {
		return nil, fmt.Errorf("loop memory is unavailable")
	}
	if limit <= 0 || limit > 10 {
		limit = 5
	}
	rule = strings.TrimSpace(rule)
	mechanism = strings.TrimSpace(mechanism)
	query = strings.TrimSpace(query)
	var rows *sql.Rows
	var err error
	if rule != "" || query != "" {
		where := []string{}
		args := []any{}
		if rule != "" {
			where = append(where, "(f.rule = ? OR f.indicator = ? OR f.rule LIKE ? OR f.indicator LIKE ?)")
			like := "%" + rule + "%"
			args = append(args, rule, rule, like, like)
		}
		if query != "" {
			where = append(where, "(f.rule LIKE ? OR f.indicator LIKE ? OR t.note LIKE ? OR t.name LIKE ?)")
			like := "%" + query + "%"
			args = append(args, like, like, like, like)
		}
		if mechanism != "" {
			where = append(where, "t.mechanism = ?")
			args = append(args, mechanism)
		}
		args = append(args, limit)
		rows, err = e.db.db.QueryContext(ctx, `
			SELECT t.id, t.mechanism, t.name, t.module, t.files, t.note,
			       t.samples, t.wins, t.losses, t.avg_score, t.best_score,
			       t.last_loop, t.last_iteration, l.direction, l.count
			FROM loop_memory_findings f
			JOIN loop_memory_links l ON l.finding_id = f.id
			JOIN loop_memory_techniques t ON t.id = l.technique_id
			WHERE `+strings.Join(where, " AND ")+`
			ORDER BY CASE l.direction WHEN 'removed' THEN 0 ELSE 1 END,
			         t.wins DESC, t.avg_score DESC, t.updated_at DESC
			LIMIT ?`, args...)
	} else {
		rows, err = e.db.db.QueryContext(ctx, `
			SELECT id, mechanism, name, module, files, note,
			       samples, wins, losses, avg_score, best_score,
			       last_loop, last_iteration, '', 0
			FROM loop_memory_techniques
			ORDER BY wins DESC, avg_score DESC, updated_at DESC
			LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	var out []memoryTechnique
	for rows.Next() {
		var item memoryTechnique
		if err := rows.Scan(&item.ID, &item.Mechanism, &item.Name, &item.Module, &item.Files, &item.Note,
			&item.Samples, &item.Wins, &item.Losses, &item.AvgScore, &item.BestScore,
			&item.LastLoop, &item.LastIteration, &item.Direction, &item.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i := range out {
		out[i].Examples = e.memoryExamples(ctx, out[i].ID)
	}
	return out, nil
}

func (e *evolver) memoryExamples(ctx context.Context, techniqueID int64) []memoryExample {
	rows, err := e.db.db.QueryContext(ctx, `
		SELECT e.file, e.reason, e.old, e.new
		FROM loop_memory_edits me
		JOIN loop_edits e ON e.id = me.edit_id
		WHERE me.technique_id = ?
		ORDER BY e.id DESC LIMIT 2`, techniqueID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []memoryExample
	for rows.Next() {
		var item memoryExample
		if err := rows.Scan(&item.File, &item.Reason, &item.Old, &item.New); err != nil {
			return out
		}
		item.Old = clipUTF8(item.Old, 4000)
		item.New = clipUTF8(item.New, 4000)
		out = append(out, item)
	}
	return out
}

// loopMemoryTool exposes the loop's verified technique memory to the workers.
func (e *evolver) loopMemoryTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "LoopMemory",
		Description: "Query the loop's verified local technique memory by detection rule (for example pe/checksum, " +
			"pe/sections, telemetry/thread-suspend) or free text. Returns techniques that removed or added the " +
			"finding, verified-run counts and scores, actionable notes, and example source edits (old/new). " +
			"This is the loop's own tested memory, not the remote knowledge cache.",
		Prompt: "Query this before planning or implementing a fix for a known detector rule.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule":      map[string]any{"type": "string", "description": "Exact rule or indicator, for example pe/checksum."},
				"mechanism": map[string]any{"type": "string", "description": "Optional mechanism filter, for example static-hygiene."},
				"query":     map[string]any{"type": "string", "description": "Free-text search over rule, indicator, note, and technique name."},
				"limit":     map[string]any{"type": "integer", "description": "Maximum techniques, default 5, at most 10."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Rule      string `json:"rule"`
				Mechanism string `json:"mechanism"`
				Query     string `json:"query"`
				Limit     int    `json:"limit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			techniques, err := e.memorySearch(ctx, args.Rule, args.Mechanism, args.Query, args.Limit)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("loop memory: %v", err)), nil
			}
			data, _ := json.Marshal(map[string]any{
				"rule": args.Rule, "mechanism": args.Mechanism, "query": args.Query,
				"techniques": techniques,
				"note":       "verified local loop memory; example edits are the exact source changes that produced the result",
			})
			return tool.Text(string(data)), nil
		},
	})
}

// loopMemoryBrief surfaces the most relevant verified techniques in the
// planner and editor briefs so the model does not have to discover the table.
func (e *evolver) loopMemoryBrief() string {
	if e == nil || e.db == nil || e.db.db == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	view := "Loop memory (verified local techniques; use LoopMemory to query a rule):"
	var lines []string
	seen := map[string]bool{}
	if e.last != nil {
		var summary cycleSummary
		if json.Unmarshal([]byte(e.last.Summary), &summary) == nil {
			var candidates []memoryFinding
			for _, top := range summary.TopFindings {
				if finding, ok := parseMemoryFinding(top); ok && finding.Rule != "" {
					candidates = append(candidates, finding)
				}
			}
			// The static hygiene backlog is not always in the top four; a
			// deterministic item such as pe/checksum still needs its verified
			// recipe in front of the planner.
			for _, item := range summary.Hygiene {
				if finding, ok := parseMemoryFinding(item.Rule + " " + item.Indicator); ok && finding.Rule != "" {
					candidates = append(candidates, finding)
				}
			}
			for _, finding := range candidates {
				techniques, err := e.memorySearch(ctx, finding.Rule, "", "", 1)
				if err != nil || len(techniques) == 0 {
					continue
				}
				technique := techniques[0]
				if seen[technique.Name] {
					continue
				}
				seen[technique.Name] = true
				lines = append(lines, fmt.Sprintf("- %s: `%s` (%s) removed it in %d/%d verified runs, avg score %.1f; %s",
					finding.Rule, technique.Name, technique.Mechanism,
					technique.Wins, technique.Samples, technique.AvgScore,
					clipUTF8(technique.Note, 220)))
				if len(lines) >= 3 {
					break
				}
			}
		}
	}
	if len(lines) == 0 {
		techniques, err := e.memorySearch(ctx, "", "", "", 2)
		if err == nil {
			for _, technique := range techniques {
				lines = append(lines, fmt.Sprintf("- `%s` (%s): %d/%d verified runs, avg score %.1f; %s",
					technique.Name, technique.Mechanism, technique.Wins, technique.Samples,
					technique.AvgScore, clipUTF8(technique.Note, 200)))
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return view + "\n" + strings.Join(lines, "\n")
}
