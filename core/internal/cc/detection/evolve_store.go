package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Cycle is one build-and-detonate step of a detection loop.
type Cycle struct {
	ID              int64     `json:"id,omitempty"`
	LoopID          string    `json:"loop_id"`
	Iteration       int       `json:"iteration"`
	Attempt         int       `json:"attempt,omitempty"`
	GlobalIteration int       `json:"global_iteration,omitempty"`
	PayloadID       int64     `json:"payload_id"`
	PayloadKey      string    `json:"payload_key,omitempty"`
	RunID           string    `json:"run_id"`
	Score           float64   `json:"score"`
	Level           string    `json:"level,omitempty"`
	Findings        int       `json:"findings"`
	Verdicts        int       `json:"verdicts"`
	TraceID         int64     `json:"trace_id,omitempty"`
	PayloadTable    string    `json:"payload_table,omitempty"`
	Executed        bool      `json:"executed"`
	Execution       string    `json:"execution,omitempty"`
	AgentOnline     *bool     `json:"agent_online,omitempty"`
	NetworkEvents   int       `json:"network_events,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// FeedbackRecord is the full feedback JSON, stored outside the model context.
type FeedbackRecord struct {
	LoopID    string
	Iteration int
	PayloadID int64
	RunID     string
	Body      json.RawMessage
}

// BuildRecord is one full build log, stored outside the model context.
type BuildRecord struct {
	LoopID    string
	Iteration int
	PayloadID int64
	Artifact  string
	SHA256    string
	Log       string
}

// EditRecord is one source edit with its before and after text.
type EditRecord struct {
	LoopID    string `json:"loop_id"`
	Iteration int    `json:"iteration"`
	PayloadID int64  `json:"payload_id"`
	Module    string `json:"module,omitempty"`
	File      string `json:"file"`
	Old       string `json:"old"`
	New       string `json:"new"`
	Reason    string `json:"reason,omitempty"`
	// Kind distinguishes a model edit from a host rollback. A restore must not
	// be linked to the next payload or reported as the next cycle's change.
	Kind      string    `json:"kind,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const (
	// EditKindModel is a source change the editor worker made.
	EditKindModel = "model"
	// EditKindRestore is a host rollback to the last executing payload.
	EditKindRestore = "restore"
)

// cycleColumns and cycleFrom are the shared projection for cycle readers. All
// of them join payloads so the payload key and view name come from one place.
const cycleColumns = `c.id, c.loop_id, c.iteration, c.payload_id, c.run_id, c.score, c.level,
	c.findings, c.verdicts, COALESCE(c.trace_id, 0), c.executed, c.execution,
	c.agent_online, c.network_events, c.summary, c.created_at,
	COALESCE(p.payload_key, ''), COALESCE(p.table_name, '')`

const cycleFrom = `FROM loop_cycles c LEFT JOIN payloads p ON p.id = c.payload_id`

func scanCycleRows(rows *sql.Rows) ([]Cycle, error) {
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
			return nil, fmt.Errorf("scan cycle: %w", err)
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

func payloadIDByKey(ctx context.Context, db *sql.DB, key string) (int64, error) {
	if key == "" {
		return 0, nil
	}
	var id int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM payloads WHERE payload_key = ?`, key).Scan(&id); err != nil {
		return 0, fmt.Errorf("payload %q: %w", key, err)
	}
	return id, nil
}

// SaveCycle records one iteration and returns its row ID.
func (t *TelemetryDB) SaveCycle(ctx context.Context, cycle Cycle) (int64, error) {
	if cycle.PayloadID == 0 {
		id, err := payloadIDByKey(ctx, t.db, cycle.PayloadKey)
		if err != nil {
			return 0, err
		}
		cycle.PayloadID = id
	}
	if cycle.PayloadID == 0 {
		return 0, fmt.Errorf("cycle has no payload")
	}
	if cycle.CreatedAt.IsZero() {
		cycle.CreatedAt = time.Now().UTC()
	}
	result, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_cycles(loop_id, iteration, payload_id, run_id, score, level,
			findings, verdicts, trace_id, executed, execution, agent_online,
			network_events, summary, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cycle.LoopID, cycle.Iteration, cycle.PayloadID, cycle.RunID, cycle.Score,
		cycle.Level, cycle.Findings, cycle.Verdicts, nullableInt(cycle.TraceID),
		boolInt(cycle.Executed), cycle.Execution, nullableBool(cycle.AgentOnline),
		cycle.NetworkEvents, cycle.Summary, cycle.CreatedAt.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("save cycle: %w", err)
	}
	return result.LastInsertId()
}

// SaveFeedback stores the full feedback body for one payload.
func (t *TelemetryDB) SaveFeedback(ctx context.Context, record FeedbackRecord) error {
	if record.PayloadID == 0 {
		return fmt.Errorf("feedback has no payload")
	}
	if len(record.Body) > maxTelemetryBytes {
		return fmt.Errorf("feedback exceeds %d bytes", maxTelemetryBytes)
	}
	if _, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_feedback(loop_id, iteration, payload_id, run_id, body, created_at)
		VALUES(?, ?, ?, ?, ?, ?)`,
		record.LoopID, record.Iteration, record.PayloadID, record.RunID,
		string(record.Body), time.Now().UTC().UnixMilli()); err != nil {
		return fmt.Errorf("save feedback: %w", err)
	}
	return nil
}

// SaveBuild stores the full build log for one payload.
func (t *TelemetryDB) SaveBuild(ctx context.Context, record BuildRecord) error {
	if record.PayloadID == 0 {
		return fmt.Errorf("build has no payload")
	}
	if _, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_builds(loop_id, iteration, payload_id, artifact, sha256, log, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`,
		record.LoopID, record.Iteration, record.PayloadID, record.Artifact,
		record.SHA256, record.Log, time.Now().UTC().UnixMilli()); err != nil {
		return fmt.Errorf("save build: %w", err)
	}
	return nil
}

// SaveEdit stores one source edit, including the replaced text. An edit made
// before the loop has a payload (a failed baseline) is kept with a NULL
// payload_id and linked to the next payload by linkEdits.
func (t *TelemetryDB) SaveEdit(ctx context.Context, record EditRecord) error {
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	var payloadID any
	if record.PayloadID != 0 {
		payloadID = record.PayloadID
	}
	if _, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_edits(loop_id, iteration, payload_id, module, file, old, new, reason, kind, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.LoopID, record.Iteration, payloadID, record.Module, record.File,
		record.Old, record.New, clip(record.Reason, 1000),
		editKind(record.Kind), record.CreatedAt.UnixMilli()); err != nil {
		return fmt.Errorf("save edit: %w", err)
	}
	return nil
}

func editKind(kind string) string {
	if strings.TrimSpace(kind) == EditKindRestore {
		return EditKindRestore
	}
	return EditKindModel
}

const editColumns = `loop_id, iteration, COALESCE(payload_id, 0), module, file, old, new, reason, kind, created_at`

func scanEdits(rows *sql.Rows) ([]EditRecord, error) {
	defer rows.Close()
	var out []EditRecord
	for rows.Next() {
		var record EditRecord
		var created int64
		if err := rows.Scan(&record.LoopID, &record.Iteration, &record.PayloadID,
			&record.Module, &record.File, &record.Old, &record.New, &record.Reason,
			&record.Kind, &created); err != nil {
			return nil, fmt.Errorf("scan edit: %w", err)
		}
		record.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, record)
	}
	return out, rows.Err()
}

// EditsForPayload returns the model edits that produced one payload.
func (t *TelemetryDB) EditsForPayload(ctx context.Context, payloadKey string) ([]EditRecord, error) {
	if strings.TrimSpace(payloadKey) == "" {
		return nil, nil
	}
	id, err := payloadIDByKey(ctx, t.db, payloadKey)
	if err != nil || id == 0 {
		return nil, err
	}
	rows, err := t.db.QueryContext(ctx, `SELECT `+editColumns+`
		FROM loop_edits WHERE next_payload_id = ? AND kind = ? ORDER BY id`, id, EditKindModel)
	if err != nil {
		return nil, fmt.Errorf("read edits: %w", err)
	}
	return scanEdits(rows)
}

// LoopEdits returns every edit recorded for one loop, oldest first.
func (t *TelemetryDB) LoopEdits(ctx context.Context, loopID string) ([]EditRecord, error) {
	rows, err := t.db.QueryContext(ctx, `SELECT `+editColumns+`
		FROM loop_edits WHERE loop_id = ? ORDER BY id`, loopID)
	if err != nil {
		return nil, fmt.Errorf("read loop edits: %w", err)
	}
	return scanEdits(rows)
}

// CyclesForPayload returns the detection cycles for one payload.
func (t *TelemetryDB) CyclesForPayload(ctx context.Context, payloadKey string) ([]Cycle, error) {
	id, err := payloadIDByKey(ctx, t.db, payloadKey)
	if err != nil || id == 0 {
		return nil, err
	}
	rows, err := t.db.QueryContext(ctx, `SELECT `+cycleColumns+` `+cycleFrom+
		` WHERE c.payload_id = ? ORDER BY c.id`, id)
	if err != nil {
		return nil, fmt.Errorf("read cycles: %w", err)
	}
	return scanCycleRows(rows)
}

// NetworkEventCount returns how many normalized network events one trace holds.
func (t *TelemetryDB) NetworkEventCount(ctx context.Context, traceID int64) (int, error) {
	if traceID == 0 {
		return 0, nil
	}
	var count int
	if err := t.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE trace_pk = ? AND category = 'network'`,
		traceID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count network events: %w", err)
	}
	return count, nil
}

// SaveWorker records one model worker session. Prompts and outputs are capped
// so a verbose model cannot grow the database without bound; the full cycle
// evidence stays in the feedback and build tables.
func (t *TelemetryDB) SaveWorker(ctx context.Context, run WorkerRun) error {
	const maxWorkerText = 64 << 10
	if run.CreatedAt == 0 {
		run.CreatedAt = time.Now().UTC().UnixMilli()
	}
	if _, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_workers(loop_id, iteration, role, model, prompt, output, status, error, reason, turns, tokens_in, tokens_out, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.LoopID, run.Iteration, run.Role, run.Model,
		clip(run.Prompt, maxWorkerText), clip(run.Output, maxWorkerText),
		run.Status, clip(run.Error, 4000), run.Reason, run.Turns,
		run.TokensIn, run.TokensOut, run.CreatedAt); err != nil {
		return fmt.Errorf("save worker run: %w", err)
	}
	return nil
}

// LoopWorkers returns the most recent worker sessions for one loop, newest
// last.
func (t *TelemetryDB) LoopWorkers(ctx context.Context, loopID string, limit int) ([]WorkerRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := t.db.QueryContext(ctx, `
		SELECT loop_id, iteration, role, model, prompt, output, status, error,
			reason, turns, tokens_in, tokens_out, created_at
		FROM loop_workers WHERE loop_id = ? ORDER BY id DESC LIMIT ?`, loopID, limit)
	if err != nil {
		return nil, fmt.Errorf("list worker runs: %w", err)
	}
	defer rows.Close()
	var out []WorkerRun
	for rows.Next() {
		var run WorkerRun
		if err := rows.Scan(&run.LoopID, &run.Iteration, &run.Role, &run.Model,
			&run.Prompt, &run.Output, &run.Status, &run.Error,
			&run.Reason, &run.Turns, &run.TokensIn, &run.TokensOut, &run.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan worker run: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// BuildForIteration returns the build record for one cycle.
func (t *TelemetryDB) BuildForIteration(ctx context.Context, loopID string, iteration int) (BuildRecord, bool, error) {
	var record BuildRecord
	err := t.db.QueryRowContext(ctx, `
		SELECT loop_id, iteration, payload_id, artifact, sha256, log
		FROM loop_builds WHERE loop_id = ? AND iteration = ?
		ORDER BY id DESC LIMIT 1`, loopID, iteration).
		Scan(&record.LoopID, &record.Iteration, &record.PayloadID, &record.Artifact, &record.SHA256, &record.Log)
	if errors.Is(err, sql.ErrNoRows) {
		return BuildRecord{}, false, nil
	}
	if err != nil {
		return BuildRecord{}, false, fmt.Errorf("read build: %w", err)
	}
	return record, true, nil
}

// UpdateCycleRecovery records a debugger-assisted execution recovery.
func (t *TelemetryDB) UpdateCycleRecovery(ctx context.Context, cycleID int64, execution string, online *bool, summary string) error {
	if cycleID == 0 {
		return fmt.Errorf("cycle id is required")
	}
	if _, err := t.db.ExecContext(ctx, `
		UPDATE loop_cycles SET execution = ?, agent_online = ?, summary = ?
		WHERE id = ?`, execution, nullableBool(online), summary, cycleID); err != nil {
		return fmt.Errorf("update cycle recovery: %w", err)
	}
	return nil
}
