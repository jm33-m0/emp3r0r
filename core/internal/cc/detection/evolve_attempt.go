package detection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ErrCycleBudgetExhausted means the logical loop has used its whole budget
// across attempts and a restart cannot run another baseline.
var ErrCycleBudgetExhausted = errors.New("detection loop cycle budget exhausted")

// loadAttemptState seeds a restart with the prior attempts' cycles, answer,
// pending edits, and last executing payload. Without this, every restart looks
// like cycle 1 of a fresh 20-cycle experiment.
func (e *evolver) loadAttemptState(ctx context.Context) error {
	prior, err := e.db.CyclesForLogicalLoop(ctx, e.baseLoopID, e.cfg.LoopID, e.attempt)
	if err != nil {
		return err
	}
	e.priorCycles = prior
	e.globalUsed = len(prior)
	for i := range e.priorCycles {
		e.priorCycles[i].Attempt = logicalAttempt(e.baseLoopID, e.priorCycles[i].LoopID)
		e.priorCycles[i].GlobalIteration = i + 1
		var summary cycleSummary
		if json.Unmarshal([]byte(e.priorCycles[i].Summary), &summary) == nil {
			if summary.Shellcode != "" {
				e.testedShellcodes[summary.Shellcode] = struct{}{}
			}
			if summary.SourceTreeHash != "" {
				e.priorSourceHash = summary.SourceTreeHash
			}
		}
	}
	for i := len(prior) - 1; i >= 0; i-- {
		if prior[i].Execution == executionVerified || (prior[i].Execution == "" && prior[i].Executed) {
			e.priorLastGood = &prior[i]
			break
		}
	}

	loopIDs := uniqueLoopIDs(prior)
	if len(loopIDs) > 0 {
		answer, err := e.db.LastAnswerForLoops(ctx, loopIDs)
		if err != nil {
			e.logClass(logging.ClassWarning, "read prior attempt answer: %v", err)
		} else if answer != nil {
			e.priorAnswer = answer
			if uuid, ok := answer["expected_agent_uuid"].(string); ok && strings.TrimSpace(uuid) != "" {
				e.testedAgentUUIDs[uuid] = struct{}{}
			}
		}
	}

	for _, loopID := range loopIDs {
		edits, err := e.db.UncycledEdits(ctx, loopID)
		if err != nil {
			e.logClass(logging.ClassWarning, "read pending edits for %s: %v", loopID, err)
			continue
		}
		e.pendingEdits = append(e.pendingEdits, edits...)
	}
	sort.SliceStable(e.pendingEdits, func(i, j int) bool {
		return e.pendingEdits[i].CreatedAt.After(e.pendingEdits[j].CreatedAt)
	})
	e.log("attempt %d (%s): carried %d prior cycles, %d pending edits, last executing payload %s",
		e.attempt, attemptLabel(e.attempt), len(e.priorCycles), len(e.pendingEdits), lastGoodRef(e.priorLastGood))
	return nil
}

func (e *evolver) usedCycles() int {
	return e.globalUsed + e.iter
}

func (e *evolver) recentCycles(limit int) []Cycle {
	all := make([]Cycle, 0, len(e.priorCycles)+len(e.cycles))
	all = append(all, e.priorCycles...)
	all = append(all, e.cycles...)
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all
}

func (e *evolver) pendingEditLines(limit int) []string {
	if len(e.pendingEdits) == 0 {
		return nil
	}
	lines := make([]string, 0, min(limit, len(e.pendingEdits)))
	for _, edit := range e.pendingEdits {
		path := edit.File
		if edit.Module != "" {
			path = edit.Module + "/" + edit.File
		}
		reason := strings.TrimSpace(sanitizeLine(edit.Reason))
		label := "pending source edit"
		if strings.HasPrefix(strings.ToLower(reason), "revert to payload") {
			label = "pending revert"
		}
		line := fmt.Sprintf("%s: %s", label, path)
		if reason != "" {
			line += " — " + reason
		}
		line += "; no cycle recorded"
		lines = append(lines, clipUTF8(line, 300))
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

// computeSourceTreeHash hashes the editable source and dependency roots. It
// records the state that produced a payload without storing the tree itself.
func (e *evolver) computeSourceTreeHash() string {
	if e.roots == nil {
		return ""
	}
	names := append([]string(nil), e.roots.names...)
	sort.Strings(names)
	h := sha256.New()
	wrote := false
	for _, name := range names {
		root, ok := e.roots.roots[name]
		if !ok {
			continue
		}
		_ = filepath.WalkDir(root.Dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, err := filepath.Rel(root.Dir, path)
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if rel != "." && skipSourceDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() || !sourceTreeFile(entry.Name()) {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Size() > 2<<20 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			fmt.Fprintf(h, "%s/%s\x00", name, filepath.ToSlash(rel))
			_, _ = h.Write(data)
			_, _ = h.Write([]byte{0})
			wrote = true
			return nil
		})
	}
	if !wrote {
		return ""
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func skipSourceDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".cache",
		"build", "dist", "out", "target", "bin", "obj":
		return true
	}
	return false
}

func sourceTreeFile(name string) bool {
	switch strings.ToLower(name) {
	case "makefile", "dockerfile", "vagrantfile", "cmakelists.txt":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".c", ".h", ".cc", ".cpp", ".hpp", ".go", ".s", ".asm", ".sh", ".py",
		".json", ".md", ".txt", ".mk", ".cmake", ".ld", ".rc", ".bat", ".ps1",
		".yml", ".yaml", ".toml", ".mod", ".sum":
		return true
	}
	return false
}

func logicalAttempt(base, loopID string) int {
	if loopID == base {
		return 1
	}
	prefix := base + "-r"
	if !strings.HasPrefix(loopID, prefix) {
		return 1
	}
	value, err := strconv.Atoi(strings.TrimPrefix(loopID, prefix))
	if err != nil || value < 1 {
		return 1
	}
	return value
}

func attemptLabel(attempt int) string {
	if attempt <= 1 {
		return "base"
	}
	return fmt.Sprintf("r%d", attempt)
}

func lastGoodRef(cycle *Cycle) string {
	if cycle == nil {
		return "none"
	}
	if cycle.PayloadKey != "" {
		return cycle.PayloadKey
	}
	return shortSHA(cycle.RunID)
}

func uniqueLoopIDs(cycles []Cycle) []string {
	seen := make(map[string]bool, len(cycles))
	var out []string
	for _, cycle := range cycles {
		if cycle.LoopID == "" || seen[cycle.LoopID] {
			continue
		}
		seen[cycle.LoopID] = true
		out = append(out, cycle.LoopID)
	}
	return out
}

// CyclesForLogicalLoop returns cycles from attempts before current, ordered by
// when they ran. Attempts are derived from the loop ID suffix, so older
// databases need no schema change.
func (t *TelemetryDB) CyclesForLogicalLoop(ctx context.Context, base, current string, currentAttempt int) ([]Cycle, error) {
	if strings.TrimSpace(base) == "" {
		return nil, nil
	}
	pattern := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(base) + "-r%"
	rows, err := t.db.QueryContext(ctx, `
		SELECT c.id, c.loop_id, c.iteration, c.payload_id, c.run_id, c.score, c.level,
		       c.findings, c.verdicts, COALESCE(c.trace_id, 0), c.executed, c.execution,
		       c.agent_online, c.network_events, c.summary, c.created_at,
		       COALESCE(p.payload_key, ''), COALESCE(p.table_name, '')
		FROM loop_cycles c LEFT JOIN payloads p ON p.id = c.payload_id
		WHERE (c.loop_id = ? OR c.loop_id LIKE ? ESCAPE '\') AND c.loop_id <> ?
		ORDER BY c.created_at, c.id`, base, pattern, current)
	if err != nil {
		return nil, fmt.Errorf("read logical loop cycles: %w", err)
	}
	defer rows.Close()
	var out []Cycle
	for rows.Next() {
		var cycle Cycle
		var created int64
		var online sql.NullInt64
		if err := rows.Scan(&cycle.ID, &cycle.LoopID, &cycle.Iteration, &cycle.PayloadID,
			&cycle.RunID, &cycle.Score, &cycle.Level, &cycle.Findings, &cycle.Verdicts,
			&cycle.TraceID, &cycle.Executed, &cycle.Execution, &online,
			&cycle.NetworkEvents, &cycle.Summary, &created, &cycle.PayloadKey, &cycle.PayloadTable); err != nil {
			return nil, err
		}
		if currentAttempt > 1 && logicalAttempt(base, cycle.LoopID) >= currentAttempt {
			continue
		}
		if online.Valid {
			value := online.Int64 != 0
			cycle.AgentOnline = &value
		}
		cycle.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, cycle)
	}
	return out, rows.Err()
}

// LastAnswerForLoops returns the newest persisted answer among prior attempts.
func (t *TelemetryDB) LastAnswerForLoops(ctx context.Context, loopIDs []string) (map[string]any, error) {
	if len(loopIDs) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(loopIDs)), ",")
	args := make([]any, len(loopIDs))
	for i, id := range loopIDs {
		args[i] = id
	}
	var raw string
	err := t.db.QueryRowContext(ctx,
		`SELECT answer FROM loop_results WHERE loop_id IN (`+placeholders+`) ORDER BY created_at DESC LIMIT 1`,
		args...).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read prior attempt answer: %w", err)
	}
	var answer map[string]any
	if err := json.Unmarshal([]byte(raw), &answer); err != nil {
		return nil, fmt.Errorf("decode prior attempt answer: %w", err)
	}
	return answer, nil
}

// UncycledEdits returns edits that were made after the last recorded cycle.
func (t *TelemetryDB) UncycledEdits(ctx context.Context, loopID string) ([]EditRecord, error) {
	rows, err := t.db.QueryContext(ctx, `SELECT `+editColumns+`
		FROM loop_edits WHERE loop_id = ? AND next_payload_id IS NULL
		ORDER BY id DESC LIMIT 8`, loopID)
	if err != nil {
		return nil, fmt.Errorf("read pending edits: %w", err)
	}
	return scanEdits(rows)
}
