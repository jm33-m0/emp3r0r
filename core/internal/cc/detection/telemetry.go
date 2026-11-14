package detection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
	_ "modernc.org/sqlite"
)

const (
	// TelemetrySchemaVersion is the SQLite schema version this package writes.
	TelemetrySchemaVersion = 2
	// maxTelemetryBytes bounds one imported telemetry file.
	maxTelemetryBytes = 64 << 20
	// maxTelemetryEvents bounds one trace.
	maxTelemetryEvents = 200000
	// maxTelemetryFindings bounds the deterministic findings from one trace.
	maxTelemetryFindings = 32
	// maxQueryRows and maxQueryCellBytes bound a model-issued SQL query.
	maxQueryRows      = 500
	maxQueryCellBytes = 8 << 10
)

const telemetrySchema = `
CREATE TABLE IF NOT EXISTS payloads (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payload_key TEXT NOT NULL UNIQUE,
	sha256 TEXT NOT NULL DEFAULT '',
	module TEXT NOT NULL DEFAULT '',
	label TEXT NOT NULL DEFAULT '',
	artifact_path TEXT NOT NULL DEFAULT '',
	table_name TEXT NOT NULL DEFAULT '',
	parent_id INTEGER REFERENCES payloads(id),
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS payloads_sha ON payloads(sha256);

CREATE TABLE IF NOT EXISTS traces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payload_id INTEGER REFERENCES payloads(id),
	run_id TEXT NOT NULL DEFAULT '',
	external_id TEXT NOT NULL DEFAULT '',
	module TEXT NOT NULL DEFAULT '',
	artifact_sha256 TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL,
	captured_at INTEGER NOT NULL DEFAULT 0,
	path TEXT NOT NULL DEFAULT '',
	meta TEXT NOT NULL DEFAULT '{}',
	payload_pid INTEGER,
	payload_image TEXT NOT NULL DEFAULT '',
	attribution TEXT NOT NULL DEFAULT '',
	coverage TEXT NOT NULL DEFAULT '{}',
	event_count INTEGER NOT NULL DEFAULT 0,
	findings_count INTEGER NOT NULL DEFAULT 0,
	findings_computed INTEGER NOT NULL DEFAULT 0,
	UNIQUE(run_id, source, external_id)
);
CREATE INDEX IF NOT EXISTS traces_module ON traces(module, captured_at DESC);
CREATE INDEX IF NOT EXISTS traces_run ON traces(run_id);

CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payload_id INTEGER REFERENCES payloads(id),
	trace_pk INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
	event_key TEXT NOT NULL DEFAULT '',
	ts_ns INTEGER,
	type TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	event TEXT NOT NULL DEFAULT '',
	provider TEXT NOT NULL DEFAULT '',
	event_id INTEGER,
	pid INTEGER,
	tid INTEGER,
	actor_pid INTEGER,
	target_pid INTEGER,
	target_tid INTEGER,
	parent_pid INTEGER,
	operation TEXT NOT NULL DEFAULT '',
	process TEXT NOT NULL DEFAULT '',
	target_image TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	image TEXT NOT NULL DEFAULT '',
	address INTEGER,
	size INTEGER,
	protection TEXT NOT NULL DEFAULT '',
	access INTEGER,
	status TEXT NOT NULL DEFAULT '',
	command TEXT NOT NULL DEFAULT '',
	proto TEXT NOT NULL DEFAULT '',
	src_addr TEXT NOT NULL DEFAULT '',
	src_port INTEGER,
	dst_addr TEXT NOT NULL DEFAULT '',
	dst_port INTEGER,
	bytes INTEGER,
	stack TEXT NOT NULL DEFAULT '',
	category TEXT NOT NULL DEFAULT 'other',
	severity TEXT NOT NULL DEFAULT '',
	signal TEXT NOT NULL DEFAULT '',
	payload_role TEXT NOT NULL DEFAULT '',
	attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_trace ON events(trace_pk, id);
CREATE INDEX IF NOT EXISTS events_payload ON events(payload_id, id);
CREATE INDEX IF NOT EXISTS events_category ON events(trace_pk, category);
CREATE INDEX IF NOT EXISTS events_event ON events(trace_pk, event);
CREATE INDEX IF NOT EXISTS events_pid ON events(trace_pk, pid);
CREATE INDEX IF NOT EXISTS events_image ON events(trace_pk, image);
CREATE INDEX IF NOT EXISTS events_path ON events(trace_pk, path);

CREATE TABLE IF NOT EXISTS findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_pk INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
	payload_id INTEGER REFERENCES payloads(id),
	stage TEXT NOT NULL DEFAULT 'telemetry',
	tool TEXT NOT NULL DEFAULT 'telemetry',
	severity TEXT NOT NULL DEFAULT '',
	rule TEXT NOT NULL DEFAULT '',
	indicator TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	signal TEXT NOT NULL DEFAULT 'signal',
	created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS loop_cycles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	loop_id TEXT NOT NULL,
	iteration INTEGER NOT NULL,
	payload_id INTEGER NOT NULL REFERENCES payloads(id),
	run_id TEXT NOT NULL DEFAULT '',
	score REAL NOT NULL DEFAULT 0,
	level TEXT NOT NULL DEFAULT '',
	findings INTEGER NOT NULL DEFAULT 0,
	verdicts INTEGER NOT NULL DEFAULT 0,
	trace_id INTEGER,
	summary TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS loop_cycles_loop ON loop_cycles(loop_id, iteration);

CREATE TABLE IF NOT EXISTS loop_feedback (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	loop_id TEXT NOT NULL,
	iteration INTEGER NOT NULL,
	payload_id INTEGER NOT NULL REFERENCES payloads(id),
	run_id TEXT NOT NULL,
	body TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS loop_builds (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	loop_id TEXT NOT NULL,
	iteration INTEGER NOT NULL,
	payload_id INTEGER NOT NULL REFERENCES payloads(id),
	artifact TEXT NOT NULL DEFAULT '',
	sha256 TEXT NOT NULL DEFAULT '',
	log TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS loop_results (
	loop_id TEXT PRIMARY KEY,
	answer TEXT NOT NULL,
	report TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS loop_edits (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	loop_id TEXT NOT NULL,
	iteration INTEGER NOT NULL,
	payload_id INTEGER REFERENCES payloads(id),
	next_payload_id INTEGER REFERENCES payloads(id),
	module TEXT NOT NULL DEFAULT '',
	file TEXT NOT NULL,
	old TEXT NOT NULL DEFAULT '',
	new TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS loop_shellcodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	loop_id TEXT NOT NULL,
	iteration INTEGER NOT NULL DEFAULT 0,
	producer TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	sha256 TEXT NOT NULL DEFAULT '',
	size INTEGER NOT NULL DEFAULT 0,
	options TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS loop_shellcodes_loop ON loop_shellcodes(loop_id, id);
`

// telemetryIndexesV2 is applied after ensureColumn because older databases do
// not have the columns yet when the base schema runs.
const telemetryIndexesV2 = `
CREATE INDEX IF NOT EXISTS traces_payload_pid ON traces(payload_pid);
CREATE INDEX IF NOT EXISTS events_actor ON events(trace_pk, actor_pid);
CREATE INDEX IF NOT EXISTS events_target ON events(trace_pk, target_pid);
CREATE INDEX IF NOT EXISTS events_operation ON events(trace_pk, category, operation);
CREATE INDEX IF NOT EXISTS events_role ON events(trace_pk, payload_role);
CREATE INDEX IF NOT EXISTS events_signal ON events(trace_pk, signal);
CREATE INDEX IF NOT EXISTS events_key ON events(trace_pk, event_key);
CREATE INDEX IF NOT EXISTS findings_trace ON findings(trace_pk);
CREATE INDEX IF NOT EXISTS findings_payload ON findings(payload_id, severity);
`

// TelemetryDB stores normalized ETW and DefenderObserver telemetry in SQLite.
// The write handle is limited to one connection, so imports and findings
// updates serialize without a process lock held during disk I/O. Queries the
// model issues use a separate read-only connection and a single SELECT guard.
type TelemetryDB struct {
	path string
	db   *sql.DB
	ro   *sql.DB
}

// OpenTelemetryDB opens or creates the telemetry database at path.
func OpenTelemetryDB(path string) (*TelemetryDB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("telemetry database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create telemetry directory: %w", err)
	}
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open telemetry database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure telemetry database: %w", err)
		}
	}
	if _, err := db.Exec(telemetrySchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create telemetry schema: %w", err)
	}
	// Databases created before payload tracking get the columns in place; the
	// per-payload views are created when the next trace is imported.
	for _, column := range []struct{ table, name, typ string }{
		{"traces", "payload_id", "INTEGER REFERENCES payloads(id)"},
		{"traces", "payload_pid", "INTEGER"},
		{"traces", "payload_image", "TEXT NOT NULL DEFAULT ''"},
		{"traces", "attribution", "TEXT NOT NULL DEFAULT ''"},
		{"traces", "coverage", "TEXT NOT NULL DEFAULT '{}'"},
		{"traces", "event_count", "INTEGER NOT NULL DEFAULT 0"},
		{"traces", "findings_count", "INTEGER NOT NULL DEFAULT 0"},
		{"traces", "findings_computed", "INTEGER NOT NULL DEFAULT 0"},
		{"events", "payload_id", "INTEGER REFERENCES payloads(id)"},
		{"events", "event_key", "TEXT NOT NULL DEFAULT ''"},
		{"events", "event_id", "INTEGER"},
		{"events", "actor_pid", "INTEGER"},
		{"events", "target_pid", "INTEGER"},
		{"events", "target_tid", "INTEGER"},
		{"events", "parent_pid", "INTEGER"},
		{"events", "operation", "TEXT NOT NULL DEFAULT ''"},
		{"events", "target_image", "TEXT NOT NULL DEFAULT ''"},
		{"events", "protection", "TEXT NOT NULL DEFAULT ''"},
		{"events", "access", "INTEGER"},
		{"events", "status", "TEXT NOT NULL DEFAULT ''"},
		{"events", "command", "TEXT NOT NULL DEFAULT ''"},
		{"events", "proto", "TEXT NOT NULL DEFAULT ''"},
		{"events", "src_addr", "TEXT NOT NULL DEFAULT ''"},
		{"events", "src_port", "INTEGER"},
		{"events", "dst_addr", "TEXT NOT NULL DEFAULT ''"},
		{"events", "dst_port", "INTEGER"},
		{"events", "bytes", "INTEGER"},
		{"events", "stack", "TEXT NOT NULL DEFAULT ''"},
		{"events", "signal", "TEXT NOT NULL DEFAULT ''"},
		{"events", "payload_role", "TEXT NOT NULL DEFAULT ''"},
		{"loop_edits", "next_payload_id", "INTEGER REFERENCES payloads(id)"},
		{"loop_edits", "module", "TEXT NOT NULL DEFAULT ''"},
		{"loop_results", "report", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := ensureColumn(db, column.table, column.name, column.typ); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(telemetryIndexesV2); err != nil {
		db.Close()
		return nil, fmt.Errorf("create telemetry indexes: %w", err)
	}
	if err := migrateTelemetrySchema(db); err != nil {
		db.Close()
		return nil, err
	}
	ro, err := sql.Open("sqlite", dsn+"?mode=ro")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open telemetry query connection: %w", err)
	}
	ro.SetMaxOpenConns(1)
	ro.SetMaxIdleConns(1)
	if _, err := ro.Exec("PRAGMA query_only=ON"); err != nil {
		db.Close()
		ro.Close()
		return nil, fmt.Errorf("set telemetry query connection read-only: %w", err)
	}
	return &TelemetryDB{path: path, db: db, ro: ro}, nil
}

// Path returns the database path.
func (t *TelemetryDB) Path() string { return t.path }

// Close releases both database handles.
func (t *TelemetryDB) Close() error {
	var errs []error
	if t.ro != nil {
		errs = append(errs, t.ro.Close())
	}
	if t.db != nil {
		errs = append(errs, t.db.Close())
	}
	return errors.Join(errs...)
}

// ImportOptions associates one trace with a detection run and artifact.
type ImportOptions struct {
	RunID          string
	Module         string
	ArtifactSHA256 string
	Source         string
	Path           string
	// ParentKey links a rebuilt payload to the payload it replaced.
	ParentKey string
}

// TelemetryCoverage records which telemetry sources produced events and which
// were expected from the run metadata. It makes a silently degraded capture
// visible to the loop instead of looking like a clean run.
type TelemetryCoverage struct {
	Delivered  []string          `json:"delivered,omitempty"`
	Expected   []string          `json:"expected,omitempty"`
	Missing    []string          `json:"missing,omitempty"`
	Analyzers  map[string]string `json:"analyzers,omitempty"`
	Providers  map[string]int    `json:"providers,omitempty"`
	Categories map[string]int    `json:"categories,omitempty"`
	Roles      map[string]int    `json:"roles,omitempty"`
	Signals    map[string]int    `json:"signals,omitempty"`
}

// TelemetryStats is the bounded per-trace summary attached to a run and shown
// to the loop. Full events stay in SQLite.
type TelemetryStats struct {
	TraceID       int64             `json:"trace_id"`
	Events        int               `json:"events"`
	PayloadEvents int               `json:"payload_events"`
	SignalEvents  int               `json:"signal_events"`
	Findings      int               `json:"findings"`
	ByCategory    map[string]int    `json:"by_category,omitempty"`
	ByRule        map[string]int    `json:"by_rule,omitempty"`
	BySeverity    map[string]int    `json:"by_severity,omitempty"`
	Coverage      TelemetryCoverage `json:"coverage"`
}

// TelemetryTrace is one persisted telemetry trace.
type TelemetryTrace struct {
	ID           int64             `json:"id"`
	PayloadID    int64             `json:"payload_id"`
	PayloadKey   string            `json:"payload_key,omitempty"`
	PayloadTable string            `json:"payload_table,omitempty"`
	Source       string            `json:"source"`
	ExternalID   string            `json:"external_id,omitempty"`
	Events       int               `json:"events"`
	First        time.Time         `json:"first,omitempty"`
	Last         time.Time         `json:"last,omitempty"`
	PayloadPID   int64             `json:"payload_pid,omitempty"`
	PayloadImage string            `json:"payload_image,omitempty"`
	Attribution  string            `json:"attribution,omitempty"`
	Coverage     TelemetryCoverage `json:"coverage,omitempty"`
	Meta         map[string]any    `json:"meta,omitempty"`
}

// TelemetryRun is the telemetry summary attached to a detection run.
type TelemetryRun struct {
	TraceID      int64             `json:"trace_id"`
	PayloadID    int64             `json:"payload_id,omitempty"`
	PayloadKey   string            `json:"payload_key,omitempty"`
	PayloadTable string            `json:"payload_table,omitempty"`
	Source       string            `json:"source"`
	Events       int               `json:"events"`
	First        time.Time         `json:"first,omitempty"`
	Last         time.Time         `json:"last,omitempty"`
	PayloadPID   int64             `json:"payload_pid,omitempty"`
	PayloadImage string            `json:"payload_image,omitempty"`
	Attribution  string            `json:"attribution,omitempty"`
	Coverage     TelemetryCoverage `json:"coverage,omitempty"`
	Stats        *TelemetryStats   `json:"stats,omitempty"`
	Findings     []Finding         `json:"findings,omitempty"`
}

// QueryResult is the bounded result of one model-issued SELECT.
type QueryResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated,omitempty"`
	ElapsedMS int64    `json:"elapsed_ms"`
}

type telemetryEvent struct {
	TS          time.Time
	EventKey    string
	Type        string
	Source      string
	Event       string
	Provider    string
	EventID     int64
	PID         int64
	TID         int64
	ActorPID    int64
	TargetPID   int64
	TargetTID   int64
	ParentPID   int64
	Operation   string
	Process     string
	TargetImage string
	Path        string
	Image       string
	Address     int64
	Size        int64
	Protection  string
	Access      int64
	Status      string
	Command     string
	Proto       string
	SrcAddr     string
	SrcPort     int64
	DstAddr     string
	DstPort     int64
	Bytes       int64
	Stack       string
	Category    string
	Severity    string
	Signal      string
	Role        string
	Attrs       string
}

type parsedTelemetry struct {
	Source       string
	ExternalID   string
	Meta         map[string]any
	Events       []telemetryEvent
	First        time.Time
	Last         time.Time
	PayloadPID   int64
	PayloadImage string
	Attribution  string
	Coverage     TelemetryCoverage
}

// Import parses and stores one telemetry blob. The format is detected from the
// content: a RedEdr JSON array/JSONL, a LitterBox dynamic result that contains
// RedEdr findings, or DefenderObserver JSONL.
func (t *TelemetryDB) Import(ctx context.Context, data []byte, opts ImportOptions) (TelemetryTrace, error) {
	if len(data) == 0 {
		return TelemetryTrace{}, fmt.Errorf("telemetry is empty")
	}
	if len(data) > maxTelemetryBytes {
		return TelemetryTrace{}, fmt.Errorf("telemetry exceeds %d bytes", maxTelemetryBytes)
	}
	parsed, err := parseTelemetry(data, opts.Source)
	if err != nil {
		return TelemetryTrace{}, err
	}
	return t.importParsed(ctx, parsed, opts, data)
}

func (t *TelemetryDB) importParsed(ctx context.Context, parsed parsedTelemetry, opts ImportOptions, seed []byte) (TelemetryTrace, error) {
	if len(parsed.Events) > maxTelemetryEvents {
		return TelemetryTrace{}, fmt.Errorf("telemetry has %d events, limit is %d", len(parsed.Events), maxTelemetryEvents)
	}
	prepareTelemetry(&parsed)
	captured := parsed.First
	if captured.IsZero() {
		captured = time.Now().UTC()
	}
	meta := parsed.Meta
	if meta == nil {
		meta = map[string]any{}
	}
	coverageJSON, err := json.Marshal(parsed.Coverage)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("encode telemetry coverage: %w", err)
	}
	meta["source"] = parsed.Source
	meta["events"] = len(parsed.Events)
	meta["first"] = parsed.First
	meta["last"] = parsed.Last
	meta["payload_pid"] = parsed.PayloadPID
	meta["payload_image"] = parsed.PayloadImage
	meta["attribution"] = parsed.Attribution
	meta["coverage"] = parsed.Coverage
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("encode telemetry meta: %w", err)
	}
	externalID := parsed.ExternalID
	if externalID == "" {
		sum := sha256.Sum256(seed)
		externalID = "sha256:" + hex.EncodeToString(sum[:12])
	}

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("begin telemetry import: %w", err)
	}
	defer tx.Rollback()
	payload, err := ensurePayload(ctx, tx, opts, parsed, externalID)
	if err != nil {
		return TelemetryTrace{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM traces WHERE run_id = ? AND source = ? AND external_id = ?`,
		opts.RunID, parsed.Source, externalID); err != nil {
		return TelemetryTrace{}, fmt.Errorf("replace telemetry trace: %w", err)
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO traces(payload_id, run_id, external_id, module, artifact_sha256, source, captured_at, path,
		 meta, payload_pid, payload_image, attribution, coverage, event_count, findings_count, findings_computed)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`,
		payload.ID, opts.RunID, externalID, opts.Module, opts.ArtifactSHA256, parsed.Source,
		captured.UnixMilli(), opts.Path, string(metaJSON), nullableInt(parsed.PayloadPID),
		parsed.PayloadImage, parsed.Attribution, string(coverageJSON), len(parsed.Events))
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("insert telemetry trace: %w", err)
	}
	traceID, err := result.LastInsertId()
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("telemetry trace id: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events(payload_id, trace_pk, event_key, ts_ns, type, source, event, provider,
		 event_id, pid, tid, actor_pid, target_pid, target_tid, parent_pid, operation,
		 process, target_image, path, image, address, size, protection, access, status,
		 command, proto, src_addr, src_port, dst_addr, dst_port, bytes, stack,
		 category, severity, signal, payload_role, attrs)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("prepare telemetry event insert: %w", err)
	}
	defer stmt.Close()
	for _, event := range parsed.Events {
		var ts any
		if !event.TS.IsZero() {
			ts = event.TS.UnixNano()
		}
		if _, err := stmt.ExecContext(ctx, payload.ID, traceID, event.EventKey, ts,
			event.Type, event.Source, event.Event, event.Provider,
			nullableInt(event.EventID), nullableInt(event.PID), nullableInt(event.TID),
			nullableInt(event.ActorPID), nullableInt(event.TargetPID), nullableInt(event.TargetTID),
			nullableInt(event.ParentPID), event.Operation, event.Process, event.TargetImage,
			event.Path, event.Image, nullableInt(event.Address), nullableInt(event.Size),
			event.Protection, nullableInt(event.Access), event.Status, event.Command,
			event.Proto, event.SrcAddr, nullableInt(event.SrcPort), event.DstAddr,
			nullableInt(event.DstPort), nullableInt(event.Bytes), event.Stack,
			event.Category, event.Severity, event.Signal, event.Role, event.Attrs); err != nil {
			return TelemetryTrace{}, fmt.Errorf("insert telemetry event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return TelemetryTrace{}, fmt.Errorf("commit telemetry import: %w", err)
	}
	return TelemetryTrace{
		ID:           traceID,
		PayloadID:    payload.ID,
		PayloadKey:   payload.Key,
		PayloadTable: payload.Table,
		Source:       parsed.Source,
		ExternalID:   externalID,
		Events:       len(parsed.Events),
		First:        parsed.First,
		Last:         parsed.Last,
		PayloadPID:   parsed.PayloadPID,
		PayloadImage: parsed.PayloadImage,
		Attribution:  parsed.Attribution,
		Coverage:     parsed.Coverage,
		Meta:         meta,
	}, nil
}

func nullableInt(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

// ImportFile reads and imports one local telemetry file.
func (t *TelemetryDB) ImportFile(ctx context.Context, path string, opts ImportOptions) (TelemetryTrace, error) {
	info, err := os.Stat(path)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("stat telemetry file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return TelemetryTrace{}, fmt.Errorf("telemetry path is not a regular file")
	}
	if info.Size() > maxTelemetryBytes {
		return TelemetryTrace{}, fmt.Errorf("telemetry file exceeds %d bytes", maxTelemetryBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("read telemetry file: %w", err)
	}
	if opts.Path == "" {
		opts.Path = path
	}
	return t.Import(ctx, data, opts)
}

// ImportSandbox stores one saved LitterBox result bundle as a single telemetry
// trace. RedEdr output keeps its normalized events; the file info, every other
// analyzer block, HolyGrail, and each EDR profile become one type='analysis'
// event that carries the block JSON in attrs. A block with nothing flagged
// stays at low severity, so a clean scan never becomes a finding.
func (t *TelemetryDB) ImportSandbox(ctx context.Context, results SandboxResults, opts ImportOptions) (TelemetryTrace, error) {
	if results.Empty() {
		return TelemetryTrace{}, fmt.Errorf("sandbox results are empty")
	}
	if strings.TrimSpace(opts.Source) == "" {
		opts.Source = "sandbox"
	}
	var (
		parsed   parsedTelemetry
		warnings []string
	)
	if len(results.Dynamic) > 0 {
		fromDynamic, err := parseTelemetry(results.Dynamic, opts.Source)
		switch {
		case err == nil:
			parsed = fromDynamic
		case !json.Valid(results.Dynamic):
			// Valid JSON without RedEdr events is a normal analyzer-only
			// result. Malformed JSON is not, and would otherwise drop the
			// dynamic block without a trace.
			warnings = append(warnings, "dynamic results: "+err.Error())
		}
	}
	parsed.Source = opts.Source
	parsed.Events = append(parsed.Events, sandboxAnalysisEvents(results, opts.Source)...)
	if len(parsed.Events) == 0 {
		return TelemetryTrace{}, fmt.Errorf("sandbox results carry no telemetry events")
	}
	if parsed.Meta == nil {
		parsed.Meta = map[string]any{}
	}
	if len(results.Info) > 0 {
		if info, err := decodeJSON(results.Info); err == nil {
			parsed.Meta["info"] = info
		}
	}
	if len(warnings) > 0 {
		parsed.Meta["warnings"] = warnings
	}
	seed, err := json.Marshal(results)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("encode sandbox results: %w", err)
	}
	return t.importParsed(ctx, parsed, opts, seed)
}

// sandboxAnalysisEvents turns every analyzer block into one analysis event.
// Static and dynamic analyzers are group-qualified ("static/yara") so the
// finding rule names the stage that produced them; HolyGrail and EDR profiles
// are unambiguous on their own.
func sandboxAnalysisEvents(results SandboxResults, source string) []telemetryEvent {
	var events []telemetryEvent
	add := func(name string, raw json.RawMessage) {
		if len(raw) == 0 {
			return
		}
		severity, reported := analyzerReport(raw)
		if !reported {
			severity = "low"
		}
		events = append(events, telemetryEvent{
			Type:     "analysis",
			Source:   source,
			Event:    name,
			Category: "analysis",
			Severity: severity,
			Attrs:    string(raw),
			EventKey: "analysis:" + name,
		})
	}
	add("info", results.Info)
	forEachAnalyzer(results.Static, func(name string, raw json.RawMessage) {
		add("static/"+name, raw)
	})
	forEachAnalyzer(results.Dynamic, func(name string, raw json.RawMessage) {
		// RedEdr output is imported as its own event stream, not as an
		// analyzer blob.
		if strings.EqualFold(name, "rededr") {
			return
		}
		add("dynamic/"+name, raw)
	})
	add("holygrail", results.HolyGrail)
	profiles := make([]string, 0, len(results.EDR))
	for profile := range results.EDR {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		add("edr/"+profile, results.EDR[profile])
	}
	return events
}

// analyzerMetadataKeys are result-block keys that carry run status rather than
// analyzer output.
var analyzerMetadataKeys = map[string]bool{
	"status":   true,
	"error":    true,
	"errors":   true,
	"message":  true,
	"warning":  true,
	"warnings": true,
}

// forEachAnalyzer calls fn for every analyzer block in one static or dynamic
// result. Scalar entries (status, counts) are skipped, and a "results"
// envelope is unwrapped without hiding any sibling analyzer.
func forEachAnalyzer(raw json.RawMessage, fn func(name string, block json.RawMessage)) {
	if len(raw) == 0 {
		return
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return
	}
	names := make([]string, 0, len(top))
	for name := range top {
		if name == "results" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if analyzerMetadataKeys[strings.ToLower(name)] {
			continue
		}
		block := bytes.TrimSpace(top[name])
		if len(block) == 0 || (block[0] != '{' && block[0] != '[') {
			continue
		}
		fn(name, top[name])
	}
	if wrapped, ok := top["results"]; ok {
		forEachAnalyzer(wrapped, fn)
	}
}

// analyzerFindingKeys are the containers an analyzer uses to report what it
// found.
var analyzerFindingKeys = map[string]bool{
	"findings":   true,
	"alerts":     true,
	"detections": true,
	"anomalies":  true,
	"suspicious": true,
	"matches":    true,
	"hits":       true,
	"threats":    true,
	"indicators": true,
	"iocs":       true,
	"signatures": true,
	"rules":      true,
}

// analyzerReport returns the strongest explicit severity in one analyzer block
// and whether the block reports anything at all. Empty collections, zero
// counters, scan statistics, and false booleans do not count, so a clean scan
// never becomes a finding.
func analyzerReport(raw json.RawMessage) (string, bool) {
	value, err := decodeJSON(raw)
	if err != nil {
		return "", false
	}
	var (
		findingSeverity string
		hintSeverity    string
		reported        bool
	)
	var walk func(node any, inFinding bool, depth int)
	walk = func(node any, inFinding bool, depth int) {
		if depth > 12 {
			return
		}
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				lower := strings.ToLower(strings.TrimSpace(key))
				// Only an explicit severity ranks a detection. A logging
				// level such as "level": "info" must not silence an
				// analyzer that reported findings, and a severity outside a
				// finding container may raise the result but not lower it:
				// analyzer output can echo the sample's own text.
				if lower == "severity" {
					if level := analyzerSeverity(child); level != "" {
						if inFinding {
							findingSeverity = strongerSeverity(findingSeverity, level)
						} else {
							hintSeverity = strongerSeverity(hintSeverity, level)
						}
					}
					continue
				}
				childInFinding := inFinding || analyzerFindingKeys[lower]
				if (childInFinding || analyzerDetectionKey(lower)) && analyzerSignal(child, lower) {
					reported = true
				}
				walk(child, childInFinding, depth+1)
			}
		case []any:
			for _, child := range typed {
				walk(child, inFinding, depth+1)
			}
		}
	}
	walk(value, false, 0)
	switch {
	case !reported:
		return "", false
	case findingSeverity != "":
		return findingSeverity, true
	case severityRank(hintSeverity) < severityRank("medium"):
		return hintSeverity, true
	default:
		return "medium", true
	}
}

// analyzerDetectionKey matches keys that name a detection or its count rather
// than a scan statistic such as scanned files, bytes, or elapsed time. A
// signature-database size is a configuration value, not a hit.
func analyzerDetectionKey(key string) bool {
	for _, token := range []string{"time", "duration", "elapsed", "bytes", "scanned", "size"} {
		if strings.Contains(key, token) {
			return false
		}
	}
	for _, token := range []string{
		"find", "threat", "susp", "malic", "detect", "anomal", "vulnerab",
		"inject", "hollow", "rwx", "hook", "ioc", "indicator", "match", "alert", "hit",
	} {
		if strings.Contains(key, token) {
			return true
		}
	}
	return false
}

// analyzerSignal reports whether one value under a finding container or a
// detection-named key is an actual detection. Negative text such as "none" or
// "clean" is not a detection, and an array of matches counts while an empty
// one does not.
func analyzerSignal(node any, key string) bool {
	switch typed := node.(type) {
	case bool:
		return typed
	case string:
		return analyzerMeaningfulString(typed)
	case json.Number:
		if !analyzerDetectionKey(key) {
			return false
		}
		value, err := typed.Float64()
		return err == nil && value > 0
	case []any:
		return len(typed) > 0
	case map[string]any:
		for childKey, child := range typed {
			if analyzerSignal(child, strings.ToLower(strings.TrimSpace(childKey))) {
				return true
			}
		}
	}
	return false
}

// analyzerMeaningfulString reports whether a text value asserts a detection
// rather than naming its absence.
func analyzerMeaningfulString(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	switch text {
	case "", "-", "0", "no", "none", "false", "nil", "null", "n/a", "na",
		"clean", "ok", "nothing", "benign", "not found", "not detected",
		"no findings", "no threats", "no detections", "no anomalies":
		return false
	}
	if value, err := strconv.ParseFloat(text, 64); err == nil && value <= 0 {
		return false
	}
	return true
}

// analyzerSeverity reads an explicit severity from an analyzer block, ignoring
// labels that are not severities.
func analyzerSeverity(value any) string {
	text := ""
	switch typed := value.(type) {
	case string:
		text = typed
	case json.Number:
		text = typed.String()
	}
	text = strings.ToLower(strings.TrimSpace(text))
	switch text {
	case "critical", "high", "medium", "low", "info":
		return text
	case "100", "80", "50", "20", "5":
		return normalizeSeverity(text)
	}
	return ""
}

func strongerSeverity(current, candidate string) string {
	if current == "" || severityRank(candidate) < severityRank(current) {
		return candidate
	}
	return current
}

// FetchTelemetry downloads one telemetry URL from the configured sandbox
// origin. Redirects may not leave that origin: telemetry import is reachable
// from an injected model turn, so it must not become an SSRF pivot.
func FetchTelemetry(ctx context.Context, rawURL, allowedOrigin string) ([]byte, error) {
	origin, err := url.Parse(strings.TrimSpace(allowedOrigin))
	if err != nil {
		return nil, fmt.Errorf("parse telemetry origin: %w", err)
	}
	if (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" {
		return nil, fmt.Errorf("telemetry origin is invalid")
	}
	if origin.User != nil {
		return nil, fmt.Errorf("telemetry origin must not carry credentials")
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("telemetry URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("telemetry URL must be http or https")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("telemetry URL has no host")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("telemetry URL must not carry credentials")
	}
	if !sameOrigin(origin, parsed) {
		return nil, fmt.Errorf("telemetry URL must use the configured sandbox origin %s", origin.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("telemetry request: %w", err)
	}
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many telemetry redirects")
			}
			if req.URL.User != nil || !sameOrigin(origin, req.URL) {
				return fmt.Errorf("telemetry redirect left the sandbox origin")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch telemetry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch telemetry: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTelemetryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read telemetry: %w", err)
	}
	if len(data) > maxTelemetryBytes {
		return nil, fmt.Errorf("telemetry exceeds %d bytes", maxTelemetryBytes)
	}
	return data, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// Query runs one SELECT against the telemetry database. It is the only path
// the analyst and the MCP tool use; writes, PRAGMAs, ATTACH, and multiple
// statements are rejected before SQLite sees them.
func (t *TelemetryDB) Query(ctx context.Context, statement string, limit int) (QueryResult, error) {
	statement, err := validateQuery(statement)
	if err != nil {
		return QueryResult{}, err
	}
	if limit <= 0 || limit > maxQueryRows {
		limit = maxQueryRows
	}
	started := time.Now()
	rows, err := t.ro.QueryContext(ctx,
		fmt.Sprintf("SELECT * FROM (%s) LIMIT %d", statement, limit+1))
	if err != nil {
		return QueryResult{}, fmt.Errorf("telemetry query: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return QueryResult{}, fmt.Errorf("telemetry columns: %w", err)
	}
	for i := range columns {
		columns[i] = sanitize.SanitizeOneLine(columns[i])
	}
	result := QueryResult{Columns: columns, Rows: [][]any{}}
	for rows.Next() {
		if len(result.Rows) >= limit {
			result.Truncated = true
			break
		}
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return QueryResult{}, fmt.Errorf("telemetry row: %w", err)
		}
		for i, value := range values {
			values[i] = queryCell(value)
		}
		result.Rows = append(result.Rows, values)
	}
	if err := rows.Err(); err != nil {
		return QueryResult{}, fmt.Errorf("telemetry rows: %w", err)
	}
	result.ElapsedMS = time.Since(started).Milliseconds()
	return result, nil
}

func queryCell(value any) any {
	switch typed := value.(type) {
	case []byte:
		return clipUTF8(sanitize.SanitizeOneLine(string(typed)), maxQueryCellBytes)
	case string:
		return clipUTF8(sanitize.SanitizeOneLine(typed), maxQueryCellBytes)
	case int64, float64, bool, nil:
		return typed
	default:
		return clipUTF8(sanitize.SanitizeOneLine(fmt.Sprintf("%v", typed)), maxQueryCellBytes)
	}
}

var (
	queryForbidden = regexp.MustCompile(`\b(attach|detach|pragma|vacuum|insert|update|delete|drop|alter|create|replace|reindex|analyze|begin|commit|rollback|savepoint|release|load_extension|writefile|readfile|backup)\b`)
	queryPrefix    = regexp.MustCompile(`^(select|with)\b`)
)

func validateQuery(statement string) (string, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return "", fmt.Errorf("sql is required")
	}
	if len(statement) > 20<<10 {
		return "", fmt.Errorf("sql is too long")
	}
	if strings.Contains(statement, "--") || strings.Contains(statement, "/*") ||
		strings.Contains(statement, "*/") {
		return "", fmt.Errorf("sql comments are not allowed")
	}
	trimmed := strings.TrimSpace(strings.TrimSuffix(statement, ";"))
	if strings.Contains(trimmed, ";") {
		return "", fmt.Errorf("only one SQL statement is allowed")
	}
	lower := strings.ToLower(trimmed)
	if !queryPrefix.MatchString(lower) {
		return "", fmt.Errorf("only SELECT or WITH queries are allowed")
	}
	if location := queryForbidden.FindStringIndex(lower); location != nil {
		return "", fmt.Errorf("SQL keyword %q is not allowed", lower[location[0]:location[1]])
	}
	return trimmed, nil
}

// Findings runs the deterministic telemetry detection queries for one trace
// and returns source-mappable indicators. The SQL is intentionally exposed in
// the finding detail so an operator can re-run it with detection_query.
func (t *TelemetryDB) Findings(ctx context.Context, traceID int64) ([]Finding, error) {
	if existing, computed, err := t.persistedFindings(ctx, traceID); err != nil {
		return nil, err
	} else if computed {
		return existing, nil
	}
	meta, err := t.traceMeta(ctx, traceID)
	if err != nil {
		return nil, err
	}
	payloadPID := metaInt(meta, "payload_pid")
	payloadImage := metaString(meta, "payload_image")
	var findings []Finding
	add := func(severity, rule, indicator, detail string) {
		if len(findings) >= maxTelemetryFindings {
			return
		}
		findings = append(findings, Finding{
			Stage:     StageTelemetry,
			Tool:      "telemetry",
			Severity:  normalizeSeverity(severity),
			Rule:      clipUTF8(sanitizeMultiline(rule), 200),
			Indicator: clipUTF8(sanitizeMultiline(indicator), 300),
			Detail:    clipUTF8(sanitizeMultiline(detail), 500),
			Executes:  true,
		})
	}

	// Defender verdicts and scan engagement. Internal Bm* plumbing is noise;
	// behavior-monitor engagement is signal about how hard the engine looked.
	defender, err := t.rows(ctx, `SELECT event, pid, path, image, severity, signal, attrs FROM events
		WHERE trace_pk = ? AND category = 'defender' ORDER BY id LIMIT 2000`, traceID)
	if err != nil {
		return nil, err
	}
	scans := 0
	for _, row := range defender {
		if row.string("signal") == "verdict" || row.string("severity") == "critical" {
			name := row.string("event")
			if name == "" {
				name = defenderThreatName(row.string("event"), row.json("attrs"))
			}
			target := firstNonEmpty(row.string("path"), row.string("image"),
				jsonString(row.json("attrs")["imagepath"]), "the uploaded artifact")
			add("critical", "defender/verdict", name, "Defender detection "+name+" on "+target)
			continue
		}
		if row.string("signal") == "scan" {
			scans++
		}
	}
	if scans > 0 {
		add("low", "defender/scan", "Defender scan activity",
			fmt.Sprintf("Defender behavior monitoring engaged the payload %d times", scans))
	}

	// LitterBox analyzer events: Moneta, pe-sieve, HollowsHunter, HSB, Patriot,
	// Blender, YARA, CheckPlz, HolyGrail, and EDR profiles.
	analyzers, err := t.rows(ctx, `SELECT event, severity FROM events
		WHERE trace_pk = ? AND category = 'analysis'
		AND severity IN ('critical', 'high', 'medium') ORDER BY id LIMIT 200`, traceID)
	if err != nil {
		return nil, err
	}
	seenAnalyzer := map[string]bool{}
	for _, row := range analyzers {
		name := row.string("event")
		severity := row.string("severity")
		key := name + "|" + severity
		if name == "" || seenAnalyzer[key] {
			continue
		}
		seenAnalyzer[key] = true
		add(severity, "analyzer/"+name, name,
			"LitterBox analyzer "+name+" reported "+severity+" findings")
	}

	// Child process creation and its image path.
	processes, err := t.rows(ctx, `SELECT event, pid, image, command, payload_role FROM events
		WHERE trace_pk = ? AND category = 'process' AND operation = 'create'
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 20`, traceID)
	if err != nil {
		return nil, err
	}
	seenProcess := map[string]struct{}{}
	for _, row := range processes {
		child := row.int("pid")
		image := row.string("image")
		key := fmt.Sprintf("%d|%s", child, image)
		if _, ok := seenProcess[key]; ok {
			continue
		}
		seenProcess[key] = struct{}{}
		severity := "medium"
		if image == "" || !isWindowsImagePath(image) {
			severity = "high"
		}
		detail := fmt.Sprintf("payload created process %d from %s", child, firstNonEmpty(image, "an unknown image"))
		if command := row.string("command"); command != "" {
			detail += ": " + command
		}
		add(severity, "telemetry/child-process", "CreateProcessW", detail)
	}

	// File activity outside Windows directories.
	files, err := t.rows(ctx, `SELECT event, operation, path FROM events
		WHERE trace_pk = ? AND category = 'file' AND path <> '' AND signal = 'signal'
		AND payload_role IN ('payload', 'payload-child')
		ORDER BY id LIMIT 500`, traceID)
	if err != nil {
		return nil, err
	}
	seenFiles := map[string]struct{}{}
	for _, row := range files {
		path := row.string("path")
		if isSystemImage(path) {
			continue
		}
		key := strings.ToLower(path)
		if _, ok := seenFiles[key]; ok {
			continue
		}
		seenFiles[key] = struct{}{}
		operation := row.string("operation")
		indicator := "CreateFileW"
		switch operation {
		case "write":
			indicator = "WriteFile"
		case "delete":
			indicator = "DeleteFileW"
		case "rename":
			indicator = "MoveFileExW"
		}
		add("medium", "telemetry/file-write", indicator,
			fmt.Sprintf("payload performed %s on %s", row.string("event"), path))
		if len(seenFiles) >= 5 {
			break
		}
	}

	// Images and modules loaded outside the system directories.
	images, err := t.rows(ctx, `SELECT event, category, image FROM events
		WHERE trace_pk = ? AND category IN ('image', 'module') AND image <> ''
		AND signal = 'signal' AND payload_role IN ('payload', 'payload-child')
		ORDER BY id LIMIT 200`, traceID)
	if err != nil {
		return nil, err
	}
	seenImages := map[string]struct{}{}
	for _, row := range images {
		image := row.string("image")
		if sameWindowsPath(image, payloadImage) || isSystemImage(image) {
			continue
		}
		if _, ok := seenImages[strings.ToLower(image)]; ok {
			continue
		}
		seenImages[strings.ToLower(image)] = struct{}{}
		base := filepath.Base(strings.ReplaceAll(image, `\`, "/"))
		rule := "telemetry/user-image"
		if row.string("category") == "module" {
			rule = "telemetry/user-module"
		}
		add("medium", rule, base, "payload loaded an image from a user-writable path: "+image)
		if len(seenImages) >= 5 {
			break
		}
	}

	// Audit API calls initiated by the payload. A target PID different from the
	// caller is remote process access; high desired-access masks are also notable.
	audits, err := t.rows(ctx, `SELECT event, event_id, pid, target_pid, target_tid, access, attrs
		FROM events WHERE trace_pk = ? AND category = 'audit' AND payload_role = 'payload'
		ORDER BY id LIMIT 100`, traceID)
	if err != nil {
		return nil, err
	}
	seenAudit := map[string]struct{}{}
	for _, row := range audits {
		target := row.int("target_pid")
		targetThread := row.int("target_tid")
		access := row.int("access")
		caller := row.int("pid")
		eventID := row.int("event_id")
		switch eventID {
		case 3:
			if _, ok := seenAudit["symlink"]; !ok {
				seenAudit["symlink"] = struct{}{}
				add("medium", "telemetry/symlink", "CreateSymbolicLink",
					fmt.Sprintf("audit-visible symbolic link creation by payload (event=%s)", row.string("event")))
			}
		case 4:
			if _, ok := seenAudit["setcontext"]; !ok {
				seenAudit["setcontext"] = struct{}{}
				add("high", "telemetry/thread-context", "SetContextThread",
					fmt.Sprintf("audit-visible thread context change: caller=%d target_pid=%d target_tid=%d",
						caller, target, targetThread))
			}
		case 6:
			if _, ok := seenAudit["openthread"]; !ok {
				seenAudit["openthread"] = struct{}{}
				add("medium", "telemetry/thread-access", "OpenThread",
					fmt.Sprintf("audit-visible thread handle: caller=%d target_pid=%d access=0x%x",
						caller, target, access))
			}
		case 5:
			remote := target != 0 && caller != 0 && target != caller
			risky := access != 0 && (access&0x1F0FFF) == 0x1F0FFF
			if !remote && !risky {
				continue
			}
			if _, ok := seenAudit["openprocess"]; ok {
				continue
			}
			seenAudit["openprocess"] = struct{}{}
			add("high", "telemetry/process-access", "OpenProcess",
				fmt.Sprintf("audit-visible process handle: caller=%d target=%d access=0x%x event=%s",
					caller, target, access, row.string("event")))
		default:
			key := fmt.Sprintf("audit-%d", eventID)
			if _, ok := seenAudit[key]; ok {
				continue
			}
			seenAudit[key] = struct{}{}
			add("low", "telemetry/audit", "AuditAPI",
				fmt.Sprintf("payload invoked an audited API: event_id=%d target_pid=%d event=%s",
					eventID, target, row.string("event")))
		}
	}

	// Outbound network activity, one finding per unique payload flow. Ambient
	// Defender traffic is excluded by payload_role.
	network, err := t.rows(ctx, `SELECT event, proto, src_addr, src_port, dst_addr, dst_port, bytes
		FROM events WHERE trace_pk = ? AND category = 'network' AND signal = 'signal'
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 200`, traceID)
	if err != nil {
		return nil, err
	}
	seenNetwork := map[string]struct{}{}
	for _, row := range network {
		local := displayEndpoint(firstNonEmpty(row.string("src_addr"), "?"), row.int("src_port"))
		remote := displayEndpoint(firstNonEmpty(row.string("dst_addr"), "?"), row.int("dst_port"))
		proto := row.string("proto")
		key := proto + "|" + local + "->" + remote
		if _, ok := seenNetwork[key]; ok {
			continue
		}
		seenNetwork[key] = struct{}{}
		detail := fmt.Sprintf("payload network %s %s using %s", firstNonEmpty(proto, "flow"), key, row.string("event"))
		if bytes := row.int("bytes"); bytes > 0 {
			detail += fmt.Sprintf(" bytes=%d", bytes)
		}
		add("medium", "telemetry/network", "connect", detail)
		if len(seenNetwork) >= 5 {
			break
		}
	}

	// ETW-TI memory operations. Grouping by caller/target/operation keeps a
	// READVM flood from producing hundreds of identical findings.
	memory, err := t.rows(ctx, `SELECT event, operation, pid, target_pid, target_image, size,
		protection, bytes, status, stack FROM events
		WHERE trace_pk = ? AND category = 'memory'
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 2000`, traceID)
	if err != nil {
		return nil, err
	}
	type memoryGroup struct {
		event, operation string
		actor, target    int64
		image            string
		count            int
		size, bytes      int64
		protection       string
		status, stack    string
	}
	groups := map[string]*memoryGroup{}
	var order []string
	for _, row := range memory {
		key := fmt.Sprintf("%s|%d", row.string("operation"), row.int("target_pid"))
		group := groups[key]
		if group == nil {
			group = &memoryGroup{
				event: row.string("event"), operation: row.string("operation"),
				actor: row.int("pid"), target: row.int("target_pid"),
				image: row.string("target_image"), protection: row.string("protection"),
				status: row.string("status"), stack: row.string("stack"),
			}
			groups[key] = group
			order = append(order, key)
		}
		group.count++
		if size := row.int("size"); size > group.size {
			group.size = size
		}
		if bytes := row.int("bytes"); bytes > group.bytes {
			group.bytes = bytes
			group.stack = firstNonEmpty(row.string("stack"), group.stack)
		}
		if protection := row.string("protection"); protection != "" {
			group.protection = protection
		}
	}
	seenMemory := map[string]struct{}{}
	for _, key := range order {
		group := groups[key]
		cross := group.target != 0 && group.target != group.actor
		severity, rule, indicator := "low", "telemetry/memory", "VirtualAlloc"
		switch group.operation {
		case "write":
			if cross {
				severity, rule, indicator = "high", "telemetry/cross-process-write", "WriteProcessMemory"
			} else {
				severity, rule, indicator = "low", "telemetry/self-write", "NtWriteVirtualMemory"
			}
		case "protect":
			if cross {
				severity, rule, indicator = "high", "telemetry/cross-process-protect", "VirtualProtectEx"
			} else {
				severity, rule, indicator = "medium", "telemetry/self-protect", "VirtualProtect"
			}
		case "suspend":
			severity, rule, indicator = "high", "telemetry/thread-suspend", "SuspendThread"
		case "allocate":
			if cross {
				severity, rule, indicator = "medium", "telemetry/cross-process-alloc", "VirtualAllocEx"
			} else {
				severity, rule, indicator = "low", "telemetry/self-alloc", "VirtualAlloc"
			}
		case "read":
			severity, rule, indicator = "low", "telemetry/readvm", "ReadProcessMemory"
		case "map":
			severity, rule, indicator = "medium", "telemetry/map-view", "MapViewOfFile"
		}
		dedupe := rule + "|" + indicator + "|" + strconv.FormatInt(group.target, 10)
		if _, ok := seenMemory[dedupe]; ok {
			continue
		}
		seenMemory[dedupe] = struct{}{}
		detail := fmt.Sprintf("ETW-TI %s caller=%d target=%d", group.operation, group.actor, group.target)
		if group.image != "" {
			detail += " (" + group.image + ")"
		}
		if group.count > 1 {
			detail += fmt.Sprintf(" count=%d", group.count)
		}
		if group.size > 0 {
			detail += fmt.Sprintf(" size=%d", group.size)
		}
		if group.protection != "" {
			detail += " protection=" + group.protection
		}
		if group.bytes > 0 {
			detail += fmt.Sprintf(" bytes=%d", group.bytes)
		}
		if group.status != "" {
			detail += " status=" + group.status
		}
		if group.stack != "" {
			detail += " stack=" + group.stack
		}
		add(severity, rule, indicator, detail)
		if len(seenMemory) >= 8 {
			break
		}
	}

	// ntdll hooks observed by RedEdrDll. The hooked API name is directly
	// mappable to the loader source that calls it.
	hooks, err := t.rows(ctx, `SELECT event, pid, tid, address, size, protection, status
		FROM events WHERE trace_pk = ? AND category = 'hook' AND signal = 'signal'
		AND payload_role IN ('payload', 'payload-child') ORDER BY id LIMIT 200`, traceID)
	if err != nil {
		return nil, err
	}
	seenHooks := map[string]struct{}{}
	for _, row := range hooks {
		api := row.string("event")
		if api == "" {
			continue
		}
		if _, ok := seenHooks[api]; ok {
			continue
		}
		seenHooks[api] = struct{}{}
		severity := "medium"
		lower := strings.ToLower(api)
		for _, sensitive := range []string{"write", "protect", "allocate", "map", "createthread", "queueuserapc", "setcontext"} {
			if strings.Contains(lower, sensitive) {
				severity = "high"
				break
			}
		}
		detail := fmt.Sprintf("ntdll hook observed %s pid=%d tid=%d addr=0x%x size=%d",
			api, row.int("pid"), row.int("tid"), row.int("address"), row.int("size"))
		if protection := row.string("protection"); protection != "" {
			detail += " protect=" + protection
		}
		if status := row.string("status"); status != "" {
			detail += " status=" + status
		}
		add(severity, "telemetry/hook", api, detail)
		if len(seenHooks) >= 6 {
			break
		}
	}

	// Kernel-callback thread creation in a process other than the caller is a
	// remote-thread indicator independent of the ETW-TI view.
	if payloadPID != 0 {
		threads, err := t.rows(ctx, `SELECT pid, actor_pid, target_tid, stack FROM events
			WHERE trace_pk = ? AND type = 'kernel' AND category = 'thread' AND operation = 'start'
			AND actor_pid = ? AND pid <> ? ORDER BY id LIMIT 20`, traceID, payloadPID, payloadPID)
		if err != nil {
			return nil, err
		}
		for _, row := range threads {
			add("medium", "telemetry/remote-thread", "CreateRemoteThread",
				fmt.Sprintf("kernel callback observed thread creation in remote process %d (tid=%d) stack=%s",
					row.int("pid"), row.int("target_tid"), row.string("stack")))
			break
		}
	}

	if payloadPID != 0 {
		// A debugged or protected target is not a detection by itself, but it
		// changes what the sandbox can observe.
		queries, err := t.rows(ctx, `SELECT attrs FROM events
			WHERE trace_pk = ? AND type = 'process_query' AND event = 'peb' LIMIT 1`, traceID)
		if err == nil && len(queries) == 1 {
			attrs := queries[0].json("attrs")
			for _, key := range []string{"is_debugged", "is_protected_process", "is_protected_process_light"} {
				if v, ok := attrs[key].(json.Number); ok && v.String() != "0" {
					add("info", "telemetry/debugged", key,
						"the payload observed its own anti-analysis state: "+key+" is set")
					break
				}
			}
		}
	}

	attribution := metaString(meta, "attribution")
	if attribution == "unknown" {
		add("low", "telemetry/attribution", "payload identity",
			"the capture has no payload PEB; events are stored but cannot be attributed to the sample")
	}
	if coverage, ok := meta["coverage"].(map[string]any); ok {
		if missing, ok := coverage["missing"].([]any); ok && len(missing) > 0 {
			names := make([]string, 0, len(missing))
			for _, item := range missing {
				if text, ok := item.(string); ok {
					names = append(names, text)
				}
			}
			if len(names) > 0 {
				add("medium", "telemetry/coverage", "missing telemetry",
					"expected telemetry sources produced no events: "+strings.Join(names, ", "))
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		return findings[i].Indicator < findings[j].Indicator
	})
	if err := t.saveFindings(ctx, traceID, findings); err != nil {
		return nil, err
	}
	return findings, nil
}

type telemetryRow map[string]any

func (r telemetryRow) string(key string) string {
	value, _ := r[key].(string)
	return value
}

func (r telemetryRow) int(key string) int64 {
	return intFrom(r, key)
}

func (r telemetryRow) json(key string) map[string]any {
	text, _ := r[key].(string)
	if text == "" {
		return map[string]any{}
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value map[string]any
	if err := dec.Decode(&value); err != nil {
		return map[string]any{}
	}
	return value
}

func (t *TelemetryDB) rows(ctx context.Context, query string, args ...any) ([]telemetryRow, error) {
	rows, err := t.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("telemetry findings: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("telemetry findings columns: %w", err)
	}
	var out []telemetryRow
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, fmt.Errorf("telemetry findings row: %w", err)
		}
		row := telemetryRow{}
		for i, column := range columns {
			switch typed := values[i].(type) {
			case []byte:
				row[column] = string(typed)
			default:
				row[column] = typed
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (t *TelemetryDB) traceMeta(ctx context.Context, traceID int64) (map[string]any, error) {
	var raw string
	if err := t.db.QueryRowContext(ctx, `SELECT meta FROM traces WHERE id = ?`, traceID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("load telemetry trace %d: %w", traceID, err)
	}
	meta := map[string]any{}
	if raw != "" {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.UseNumber()
		_ = dec.Decode(&meta)
	}
	return meta, nil
}

func metaInt(meta map[string]any, key string) int64 { return intFrom(meta, key) }
func metaString(meta map[string]any, key string) string {
	value, _ := meta[key].(string)
	return value
}

// --- parsing ---------------------------------------------------------------

func parseTelemetry(data []byte, sourceHint string) (parsedTelemetry, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return parsedTelemetry{}, fmt.Errorf("telemetry is empty")
	}
	// A complete document wins over JSONL. Formatted JSON can put one event
	// across several lines, so the line decoder would otherwise accept a
	// partial first event and drop the rest.
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if json.Valid(trimmed) {
			if value, err := decodeJSON(trimmed); err == nil {
				if parsed, parseErr := parseTelemetryValue(value, sourceHint); parseErr == nil {
					return parsed, nil
				}
			}
		}
	}
	if parsed, ok := parseTelemetryJSONL(trimmed, sourceHint); ok {
		return parsed, nil
	}
	value, err := decodeJSON(trimmed)
	if err != nil {
		return parsedTelemetry{}, fmt.Errorf("decode telemetry: %w", err)
	}
	if parsed, parseErr := parseTelemetryValue(value, sourceHint); parseErr == nil {
		return parsed, nil
	}
	return parsedTelemetry{}, fmt.Errorf("unsupported telemetry format")
}

func parseTelemetryValue(value any, sourceHint string) (parsedTelemetry, error) {
	maps := collectTelemetryObjects(value)
	if len(maps) == 0 {
		return parsedTelemetry{}, fmt.Errorf("unsupported telemetry object")
	}
	return parseTelemetryMaps(maps, sourceHint)
}

// collectTelemetryObjects walks a LitterBox or RedEdr envelope and returns
// every event object, merging RedEdr findings.events with raw_output and the
// kernel/hook/query records that only raw_output carries.
func collectTelemetryObjects(value any) []map[string]any {
	seen := map[string]bool{}
	var out []map[string]any
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case string:
			for _, object := range decodeTelemetryLines(typed) {
				walk(object)
			}
		case map[string]any:
			if isDefenderObserver(typed) || isRedEdrEvent(typed) {
				encoded, _ := json.Marshal(typed)
				key := string(encoded)
				if !seen[key] {
					seen[key] = true
					out = append(out, typed)
				}
				return
			}
			for _, key := range []string{"events", "findings", "rededr", "raw_output", "data"} {
				if child, ok := typed[key]; ok {
					walk(child)
				}
			}
		}
	}
	walk(value)
	return out
}

func decodeTelemetryLines(raw string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		decoded, err := decodeJSON([]byte(line))
		if err != nil {
			continue
		}
		object, ok := decoded.(map[string]any)
		if !ok || (!isRedEdrEvent(object) && !isDefenderObserver(object)) {
			continue
		}
		out = append(out, object)
	}
	return out
}

func parseTelemetryMaps(maps []map[string]any, sourceHint string) (parsedTelemetry, error) {
	if len(maps) == 0 {
		return parsedTelemetry{}, fmt.Errorf("telemetry has no events")
	}
	source := strings.ToLower(strings.TrimSpace(sourceHint))
	if source == "" || source == "auto" {
		if isDefenderObserver(maps[0]) {
			source = "defender_observer"
		} else {
			source = "rededr"
		}
	}
	parsed := parsedTelemetry{Source: source, Meta: map[string]any{}}
	for _, object := range maps {
		if eventType, _ := object["type"].(string); strings.EqualFold(strings.TrimSpace(eventType), "meta") {
			for key, value := range object {
				parsed.Meta[key] = value
			}
			continue
		}
		normalizerSource := source
		switch {
		case isDefenderObserver(object):
			normalizerSource = "defender_observer"
		case isRedEdrEvent(object):
			normalizerSource = "rededr"
		}
		for _, event := range normalizeTelemetryObject(normalizerSource, object) {
			event.Source = source
			if event.EventKey == "" {
				event.EventKey = telemetryObjectKey(event.Attrs, "")
			}
			parsed.Events = append(parsed.Events, event)
			if parsed.First.IsZero() || (!event.TS.IsZero() && event.TS.Before(parsed.First)) {
				parsed.First = event.TS
			}
			if event.TS.After(parsed.Last) {
				parsed.Last = event.TS
			}
		}
	}
	parsed.ExternalID = telemetryExternalID(parsed.Source, parsed.Meta, parsed.Events)
	if len(parsed.Events) == 0 {
		return parsedTelemetry{}, fmt.Errorf("telemetry has no data events")
	}
	return parsed, nil
}

func isRedEdrEvent(object map[string]any) bool {
	if _, ok := object["etw_provider_name"]; ok {
		return true
	}
	if _, ok := object["event_time"]; ok {
		return true
	}
	eventType, _ := object["type"].(string)
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "etw", "process_query", "proces_query", "kernel", "dll", "meta":
		return true
	}
	return false
}

func isDefenderObserver(object map[string]any) bool {
	_, hasProvider := object["providerName"]
	_, hasTimestamp := object["timestamp"]
	_, hasPayload := object["payload"]
	return hasProvider && hasTimestamp && hasPayload
}

func telemetryTime(object map[string]any) time.Time {
	for _, key := range []string{"event_time", "etw_time", "time", "createtime"} {
		if value := telemetryTimeKey(object, key); !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func telemetryTimeKey(object map[string]any, key string) time.Time {
	raw, ok := object[key]
	if !ok {
		return time.Time{}
	}
	value := intFrom(map[string]any{"v": raw}, "v")
	if value <= 0 {
		return time.Time{}
	}
	switch {
	case value > 116444736000000000: // Windows FILETIME, 100ns since 1601
		return time.Unix(0, (value-116444736000000000)*100).UTC()
	case value > 1_000_000_000_000_000_000: // unix nanoseconds
		return time.Unix(0, value).UTC()
	case value > 1_000_000_000_000: // unix milliseconds
		return time.UnixMilli(value).UTC()
	case value > 1_000_000_000: // unix seconds
		return time.Unix(value, 0).UTC()
	}
	return time.Time{}
}

func telemetryExternalID(source string, meta map[string]any, events []telemetryEvent) string {
	if value := intFrom(meta, "trace_id"); value != 0 {
		return fmt.Sprintf("trace:%d", value)
	}
	for _, event := range events {
		if event.Attrs == "" {
			continue
		}
		var object map[string]any
		dec := json.NewDecoder(strings.NewReader(event.Attrs))
		dec.UseNumber()
		if dec.Decode(&object) == nil {
			if value := intFrom(object, "trace_id"); value != 0 {
				return fmt.Sprintf("trace:%d", value)
			}
		}
	}
	return ""
}

// --- value helpers ---------------------------------------------------------

func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func encodeObject(object map[string]any) string {
	data, err := json.Marshal(object)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func jsonString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%v", typed)
	default:
		return ""
	}
}

func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := jsonString(object[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstInt(object map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if value := intFrom(object, key); value != 0 {
			return value
		}
	}
	return 0
}

func intFrom(object map[string]any, key string) int64 {
	value, ok := object[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	case string:
		var parsed int64
		if _, err := fmt.Sscanf(typed, "%d", &parsed); err == nil {
			return parsed
		}
	}
	return 0
}

// defenderThreatName returns a verdict only for real threat events. Behavior
// monitoring emits per-operation Bm* events whose attributes contain
// "ismultiprocdetection" and "matchedthreatsnumber"; those are scan activity,
// not a verdict.
func defenderThreatName(event string, object map[string]any) string {
	lowerEvent := strings.ToLower(strings.TrimSpace(event))
	threatEvent := strings.Contains(lowerEvent, "threatfound") ||
		strings.Contains(lowerEvent, "threatdetect") ||
		strings.Contains(lowerEvent, "malwarefound") ||
		strings.Contains(lowerEvent, "detectionadded") ||
		strings.Contains(lowerEvent, "protectionalert") ||
		strings.Contains(lowerEvent, "bmdetection")
	for key, value := range object {
		lowerKey := strings.ToLower(key)
		threatKey := lowerKey == "threatname" || lowerKey == "threatid" ||
			lowerKey == "malwarename" || lowerKey == "verdict"
		if threatEvent && lowerKey == "name" {
			threatKey = true
		}
		if !threatKey {
			continue
		}
		text := strings.TrimSpace(jsonString(value))
		switch strings.ToLower(text) {
		case "", "0", "false", "n/a", "unsupported", "none":
			continue
		}
		return text
	}
	return ""
}

var windowsDevicePrefix = regexp.MustCompile(`^\\device\\harddiskvolume\d+`)

// normalizeWindowsPath makes a Win32 path and an ETW device path comparable.
func normalizeWindowsPath(path string) string {
	lower := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "/", `\`))
	lower = windowsDevicePrefix.ReplaceAllString(lower, "")
	if len(lower) >= 2 && lower[1] == ':' {
		lower = lower[2:]
	}
	return strings.TrimRight(lower, `\`)
}

func sameWindowsPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalizeWindowsPath(a) == normalizeWindowsPath(b)
}

func isWindowsImagePath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return strings.Contains(lower, `\windows\`) || strings.Contains(lower, `\program files\`)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// parseTelemetryJSONL accepts one JSON event object per line, tolerating the
// loguru INFO lines RedEdr interleaves with its JSON output.
func parseTelemetryJSONL(data []byte, sourceHint string) (parsedTelemetry, bool) {
	maps := decodeTelemetryLines(string(data))
	if len(maps) == 0 {
		return parsedTelemetry{}, false
	}
	parsed, err := parseTelemetryMaps(maps, sourceHint)
	if err != nil {
		return parsedTelemetry{}, false
	}
	return parsed, true
}
