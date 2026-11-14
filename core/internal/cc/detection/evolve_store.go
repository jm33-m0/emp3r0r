package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Cycle is one build-and-detonate step of a detection loop.
type Cycle struct {
	ID           int64     `json:"id,omitempty"`
	LoopID       string    `json:"loop_id"`
	Iteration    int       `json:"iteration"`
	PayloadID    int64     `json:"payload_id"`
	PayloadKey   string    `json:"payload_key,omitempty"`
	RunID        string    `json:"run_id"`
	Score        float64   `json:"score"`
	Level        string    `json:"level,omitempty"`
	Findings     int       `json:"findings"`
	Verdicts     int       `json:"verdicts"`
	TraceID      int64     `json:"trace_id,omitempty"`
	PayloadTable string    `json:"payload_table,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
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
	LoopID    string    `json:"loop_id"`
	Iteration int       `json:"iteration"`
	PayloadID int64     `json:"payload_id"`
	Module    string    `json:"module,omitempty"`
	File      string    `json:"file"`
	Old       string    `json:"old"`
	New       string    `json:"new"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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
			findings, verdicts, trace_id, summary, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cycle.LoopID, cycle.Iteration, cycle.PayloadID, cycle.RunID, cycle.Score,
		cycle.Level, cycle.Findings, cycle.Verdicts, nullableInt(cycle.TraceID),
		clip(cycle.Summary, 4000), cycle.CreatedAt.UnixMilli())
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

// SaveEdit stores one source edit, including the replaced text.
func (t *TelemetryDB) SaveEdit(ctx context.Context, record EditRecord) error {
	if record.PayloadID == 0 {
		return fmt.Errorf("edit has no payload")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if _, err := t.db.ExecContext(ctx, `
		INSERT INTO loop_edits(loop_id, iteration, payload_id, module, file, old, new, reason, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.LoopID, record.Iteration, record.PayloadID, record.Module, record.File,
		record.Old, record.New, clip(record.Reason, 1000),
		record.CreatedAt.UnixMilli()); err != nil {
		return fmt.Errorf("save edit: %w", err)
	}
	return nil
}

const editColumns = `loop_id, iteration, COALESCE(payload_id, 0), module, file, old, new, reason, created_at`

func scanEdits(rows *sql.Rows) ([]EditRecord, error) {
	defer rows.Close()
	var out []EditRecord
	for rows.Next() {
		var record EditRecord
		var created int64
		if err := rows.Scan(&record.LoopID, &record.Iteration, &record.PayloadID,
			&record.Module, &record.File, &record.Old, &record.New, &record.Reason, &created); err != nil {
			return nil, fmt.Errorf("scan edit: %w", err)
		}
		record.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, record)
	}
	return out, rows.Err()
}

// EditsForPayload returns the edits that produced one payload.
func (t *TelemetryDB) EditsForPayload(ctx context.Context, payloadKey string) ([]EditRecord, error) {
	id, err := payloadIDByKey(ctx, t.db, payloadKey)
	if err != nil || id == 0 {
		return nil, err
	}
	rows, err := t.db.QueryContext(ctx, `SELECT `+editColumns+`
		FROM loop_edits WHERE next_payload_id = ? ORDER BY id`, id)
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
	rows, err := t.db.QueryContext(ctx, `
		SELECT id, loop_id, iteration, payload_id, run_id, score, level, findings,
		       verdicts, COALESCE(trace_id, 0), summary, created_at
		FROM loop_cycles WHERE payload_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("read cycles: %w", err)
	}
	defer rows.Close()
	var out []Cycle
	for rows.Next() {
		var cycle Cycle
		var created int64
		if err := rows.Scan(&cycle.ID, &cycle.LoopID, &cycle.Iteration, &cycle.PayloadID,
			&cycle.RunID, &cycle.Score, &cycle.Level, &cycle.Findings, &cycle.Verdicts,
			&cycle.TraceID, &cycle.Summary, &created); err != nil {
			return nil, fmt.Errorf("scan cycle: %w", err)
		}
		cycle.PayloadKey = payloadKey
		cycle.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, cycle)
	}
	return out, rows.Err()
}
