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
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// TelemetrySchemaVersion is the SQLite schema version this package writes.
	TelemetrySchemaVersion = 1
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
	UNIQUE(run_id, source, external_id)
);
CREATE INDEX IF NOT EXISTS traces_module ON traces(module, captured_at DESC);
CREATE INDEX IF NOT EXISTS traces_run ON traces(run_id);

CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	payload_id INTEGER REFERENCES payloads(id),
	trace_pk INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
	ts_ns INTEGER,
	type TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	event TEXT NOT NULL DEFAULT '',
	provider TEXT NOT NULL DEFAULT '',
	pid INTEGER,
	tid INTEGER,
	process TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	image TEXT NOT NULL DEFAULT '',
	address INTEGER,
	size INTEGER,
	category TEXT NOT NULL DEFAULT 'other',
	severity TEXT NOT NULL DEFAULT '',
	attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_trace ON events(trace_pk, id);
CREATE INDEX IF NOT EXISTS events_payload ON events(payload_id, id);
CREATE INDEX IF NOT EXISTS events_category ON events(trace_pk, category);
CREATE INDEX IF NOT EXISTS events_event ON events(trace_pk, event);
CREATE INDEX IF NOT EXISTS events_pid ON events(trace_pk, pid);
CREATE INDEX IF NOT EXISTS events_image ON events(trace_pk, image);
CREATE INDEX IF NOT EXISTS events_path ON events(trace_pk, path);

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
	file TEXT NOT NULL,
	old TEXT NOT NULL DEFAULT '',
	new TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);
`

// TelemetryDB stores normalized ETW and DefenderObserver telemetry in SQLite.
// Writes are serialized because SQLite has one writer; queries that the model
// issues use a separate read-only connection and a single SELECT guard.
type TelemetryDB struct {
	path string
	db   *sql.DB
	ro   *sql.DB
	mu   sync.Mutex
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
		{"events", "payload_id", "INTEGER REFERENCES payloads(id)"},
		{"loop_edits", "next_payload_id", "INTEGER REFERENCES payloads(id)"},
		{"loop_results", "report", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := ensureColumn(db, column.table, column.name, column.typ); err != nil {
			db.Close()
			return nil, err
		}
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

// TelemetryTrace is one persisted telemetry trace.
type TelemetryTrace struct {
	ID           int64          `json:"id"`
	PayloadID    int64          `json:"payload_id"`
	PayloadKey   string         `json:"payload_key,omitempty"`
	PayloadTable string         `json:"payload_table,omitempty"`
	Source       string         `json:"source"`
	ExternalID   string         `json:"external_id,omitempty"`
	Events       int            `json:"events"`
	First        time.Time      `json:"first,omitempty"`
	Last         time.Time      `json:"last,omitempty"`
	Meta         map[string]any `json:"meta,omitempty"`
}

// TelemetryRun is the telemetry summary attached to a detection run.
type TelemetryRun struct {
	TraceID      int64     `json:"trace_id"`
	PayloadID    int64     `json:"payload_id,omitempty"`
	PayloadKey   string    `json:"payload_key,omitempty"`
	PayloadTable string    `json:"payload_table,omitempty"`
	Source       string    `json:"source"`
	Events       int       `json:"events"`
	First        time.Time `json:"first,omitempty"`
	Last         time.Time `json:"last,omitempty"`
	Findings     []Finding `json:"findings,omitempty"`
}

// QueryResult is the bounded result of one model-issued SELECT.
type QueryResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated,omitempty"`
	ElapsedMS int64    `json:"elapsed_ms"`
}

type telemetryEvent struct {
	TS       time.Time
	Type     string
	Source   string
	Event    string
	Provider string
	PID      int64
	TID      int64
	Process  string
	Path     string
	Image    string
	Address  int64
	Size     int64
	Category string
	Severity string
	Attrs    string
}

type parsedTelemetry struct {
	Source     string
	ExternalID string
	Meta       map[string]any
	Events     []telemetryEvent
	First      time.Time
	Last       time.Time
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
	if len(parsed.Events) > maxTelemetryEvents {
		return TelemetryTrace{}, fmt.Errorf("telemetry has %d events, limit is %d", len(parsed.Events), maxTelemetryEvents)
	}
	captured := parsed.First
	if captured.IsZero() {
		captured = time.Now().UTC()
	}
	meta := parsed.Meta
	if meta == nil {
		meta = map[string]any{}
	}
	meta["source"] = parsed.Source
	meta["events"] = len(parsed.Events)
	meta["first"] = parsed.First
	meta["last"] = parsed.Last
	if pid, image := payloadIdentity(parsed.Events); pid != 0 || image != "" {
		meta["payload_pid"] = pid
		meta["payload_image"] = image
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("encode telemetry meta: %w", err)
	}
	externalID := parsed.ExternalID
	if externalID == "" {
		sum := sha256.Sum256(data)
		externalID = "sha256:" + hex.EncodeToString(sum[:12])
	}

	t.mu.Lock()
	defer t.mu.Unlock()

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
		`INSERT INTO traces(payload_id, run_id, external_id, module, artifact_sha256, source, captured_at, path, meta)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payload.ID, opts.RunID, externalID, opts.Module, opts.ArtifactSHA256, parsed.Source,
		captured.UnixMilli(), opts.Path, string(metaJSON))
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("insert telemetry trace: %w", err)
	}
	traceID, err := result.LastInsertId()
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("telemetry trace id: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events(payload_id, trace_pk, ts_ns, type, source, event, provider, pid, tid,
		 process, path, image, address, size, category, severity, attrs)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return TelemetryTrace{}, fmt.Errorf("prepare telemetry event insert: %w", err)
	}
	defer stmt.Close()
	for _, event := range parsed.Events {
		var ts any
		if !event.TS.IsZero() {
			ts = event.TS.UnixNano()
		}
		pid := nullableInt(event.PID)
		tid := nullableInt(event.TID)
		address := nullableInt(event.Address)
		size := nullableInt(event.Size)
		if _, err := stmt.ExecContext(ctx, payload.ID, traceID, ts, event.Type, event.Source,
			event.Event, event.Provider, pid, tid, event.Process, event.Path,
			event.Image, address, size, event.Category, event.Severity, event.Attrs); err != nil {
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

// FetchTelemetry downloads one telemetry URL, bounded and with credentials and
// non-HTTP schemes rejected.
func FetchTelemetry(ctx context.Context, rawURL string) ([]byte, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("telemetry request: %w", err)
	}
	client := &http.Client{Timeout: 60 * time.Second}
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
		return clipUTF8(string(typed), maxQueryCellBytes)
	case string:
		return clipUTF8(typed, maxQueryCellBytes)
	case int64, float64, bool, nil:
		return typed
	default:
		return clipUTF8(fmt.Sprintf("%v", typed), maxQueryCellBytes)
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
			Rule:      rule,
			Indicator: indicator,
			Detail:    clip(detail, 500),
			Executes:  true,
		})
	}

	// Defender verdicts and scan engagement. Without ETW-TI the engine can
	// still report scan activity, so keep the two classes separate.
	defender, err := t.rows(ctx, `SELECT event, pid, path, image, severity, attrs FROM events
		WHERE trace_pk = ? AND category = 'defender' ORDER BY id LIMIT 2000`, traceID)
	if err != nil {
		return nil, err
	}
	scans := 0
	for _, row := range defender {
		event := row.string("event")
		attrs := row.json("attrs")
		if name := defenderThreatName(event, attrs); name != "" {
			target := firstNonEmpty(row.string("path"), row.string("image"),
				jsonString(attrs["imagepath"]), "the uploaded artifact")
			add("critical", "defender/verdict", name, "Defender detection "+name+" on "+target)
			continue
		}
		scans++
	}
	if scans > 0 {
		add("low", "defender/scan", "Defender scan activity",
			fmt.Sprintf("Defender behavior monitoring produced %d scan/internal events", scans))
	}

	// Child process creation and its image path.
	processes, err := t.rows(ctx, `SELECT event, pid, image, attrs FROM events
		WHERE trace_pk = ? AND category = 'process' AND event LIKE 'ProcessStart%'
		ORDER BY id LIMIT 20`, traceID)
	if err != nil {
		return nil, err
	}
	for _, row := range processes {
		attrs := row.json("attrs")
		child := intFrom(attrs, "processid")
		image := row.string("image")
		severity := "medium"
		if image != "" && !isWindowsImagePath(image) {
			severity = "high"
		}
		add(severity, "telemetry/child-process", "CreateProcessW",
			fmt.Sprintf("payload created process %d from %s", child, firstNonEmpty(image, "an unknown image")))
	}

	// File activity outside Windows directories, including opens, creates,
	// writes, and name creation from every Kernel-File event.
	files, err := t.rows(ctx, `SELECT event, pid, path FROM events
		WHERE trace_pk = ? AND category = 'file' AND path <> ''
		ORDER BY id LIMIT 500`, traceID)
	if err != nil {
		return nil, err
	}
	seenFiles := map[string]struct{}{}
	for _, row := range files {
		if payloadPID == 0 || row.int("pid") != payloadPID {
			continue
		}
		path := row.string("path")
		if isWindowsImagePath(path) {
			continue
		}
		key := strings.ToLower(path)
		if _, ok := seenFiles[key]; ok {
			continue
		}
		seenFiles[key] = struct{}{}
		event := row.string("event")
		indicator := "CreateFileW"
		if strings.Contains(strings.ToLower(event), "write") {
			indicator = "WriteFile"
		}
		add("medium", "telemetry/file-write", indicator,
			fmt.Sprintf("payload performed %s on %s", event, path))
		if len(seenFiles) >= 5 {
			break
		}
	}

	// Images loaded outside the Windows directories, excluding the payload
	// image itself and the main executable.
	images, err := t.rows(ctx, `SELECT event, pid, image FROM events
		WHERE trace_pk = ? AND category = 'image' AND image <> ''
		AND image NOT LIKE '%\Windows\%' ORDER BY id LIMIT 100`, traceID)
	if err != nil {
		return nil, err
	}
	seenImages := map[string]struct{}{}
	for _, row := range images {
		image := row.string("image")
		if sameWindowsPath(image, payloadImage) {
			continue
		}
		if _, ok := seenImages[strings.ToLower(image)]; ok {
			continue
		}
		seenImages[strings.ToLower(image)] = struct{}{}
		add("medium", "telemetry/user-image", filepath.Base(strings.ReplaceAll(image, `\`, "/")),
			"payload loaded an image from a user-writable path: "+image)
		if len(seenImages) >= 5 {
			break
		}
	}

	// Audit API calls. A target PID different from the caller is remote
	// process access; high desired-access masks are also notable.
	audits, err := t.rows(ctx, `SELECT event, pid, attrs FROM events
		WHERE trace_pk = ? AND category = 'audit' ORDER BY id LIMIT 50`, traceID)
	if err != nil {
		return nil, err
	}
	seenAudit := map[string]struct{}{}
	for _, row := range audits {
		if payloadPID == 0 {
			continue
		}
		attrs := row.json("attrs")
		target := intFrom(attrs, "targetprocessid")
		targetThread := intFrom(attrs, "targetthreadid")
		access := intFrom(attrs, "desiredaccess")
		caller := row.int("pid")
		if caller != payloadPID {
			continue
		}
		eventID := intFrom(attrs, "etw_event_id")
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
		}
	}

	// Outbound network activity, one finding per unique endpoint.
	network, err := t.rows(ctx, `SELECT event, pid, attrs FROM events
		WHERE trace_pk = ? AND category = 'network' ORDER BY id LIMIT 200`, traceID)
	if err != nil {
		return nil, err
	}
	seenNetwork := map[string]struct{}{}
	for _, row := range network {
		attrs := row.json("attrs")
		local := fmt.Sprintf("%s:%d", firstNonEmpty(jsonString(attrs["saddr"]), "?"), intFrom(attrs, "sport"))
		remote := fmt.Sprintf("%s:%d", firstNonEmpty(jsonString(attrs["daddr"]), "?"), intFrom(attrs, "dport"))
		key := local + "->" + remote
		if _, ok := seenNetwork[key]; ok {
			continue
		}
		seenNetwork[key] = struct{}{}
		add("medium", "telemetry/network", "connect",
			fmt.Sprintf("payload network %s using %s", key, row.string("event")))
		if len(seenNetwork) >= 5 {
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
			if v, ok := attrs["is_debugged"].(json.Number); ok && v.String() != "0" {
				add("info", "telemetry/debugged", "IsDebuggerPresent",
					"the payload process was debugged in the sandbox")
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return findings[i].Rule < findings[j].Rule
	})
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
	var (
		value any
		err   error
	)
	if trimmed[0] == '{' && bytes.Contains(trimmed, []byte("\n")) {
		if parsed, ok := parseTelemetryJSONL(trimmed, sourceHint); ok {
			return parsed, nil
		}
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		value, err = decodeJSON(trimmed)
		if err == nil {
			if parsed, parseErr := parseTelemetryValue(value, sourceHint); parseErr == nil {
				return parsed, nil
			}
		}
	}
	if parsed, ok := parseTelemetryJSONL(trimmed, sourceHint); ok {
		return parsed, nil
	}
	if err != nil {
		return parsedTelemetry{}, fmt.Errorf("decode telemetry: %w", err)
	}
	return parsedTelemetry{}, fmt.Errorf("unsupported telemetry format")
}

func parseTelemetryValue(value any, sourceHint string) (parsedTelemetry, error) {
	switch typed := value.(type) {
	case []any:
		maps := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				return parsedTelemetry{}, fmt.Errorf("telemetry array contains a non-object")
			}
			maps = append(maps, object)
		}
		if len(maps) == 0 {
			return parsedTelemetry{}, fmt.Errorf("telemetry array is empty")
		}
		return parseTelemetryMaps(maps, sourceHint)
	case map[string]any:
		if rededr, ok := findRedEdr(typed); ok {
			return parseTelemetryValue(rededr, "litterbox-rededr")
		}
		if rawOutput, ok := typed["raw_output"].(string); ok {
			if parsed, ok := parseRedEdrRawOutput(rawOutput, "litterbox-rededr"); ok {
				return parsed, nil
			}
		}
		if events, ok := typed["events"].([]any); ok {
			return parseTelemetryValue(events, sourceHint)
		}
		if findings, ok := typed["findings"].(map[string]any); ok {
			if events, ok := findings["events"].([]any); ok {
				return parseTelemetryValue(events, sourceHint)
			}
		}
		if isDefenderObserver(typed) || isRedEdrEvent(typed) {
			return parseTelemetryMaps([]map[string]any{typed}, sourceHint)
		}
	}
	return parsedTelemetry{}, fmt.Errorf("unsupported telemetry object")
}

func parseTelemetryMaps(maps []map[string]any, sourceHint string) (parsedTelemetry, error) {
	if len(maps) == 0 {
		return parsedTelemetry{}, fmt.Errorf("telemetry has no events")
	}
	source := strings.ToLower(strings.TrimSpace(sourceHint))
	if source == "" || source == "auto" {
		switch {
		case isDefenderObserver(maps[0]):
			source = "defender_observer"
		case isRedEdrEvent(maps[0]):
			source = "rededr"
		default:
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
		event := telemetryEvent{Source: source}
		switch source {
		case "defender_observer":
			event = normalizeDefenderObserver(object)
		default:
			event = normalizeRedEdr(object)
		}
		if event.Event == "" && event.Image == "" && event.Path == "" {
			continue
		}
		parsed.Events = append(parsed.Events, event)
		if parsed.First.IsZero() || (!event.TS.IsZero() && event.TS.Before(parsed.First)) {
			parsed.First = event.TS
		}
		if event.TS.After(parsed.Last) {
			parsed.Last = event.TS
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
	return strings.EqualFold(strings.TrimSpace(eventType), "etw") ||
		strings.EqualFold(strings.TrimSpace(eventType), "process_query")
}

func isDefenderObserver(object map[string]any) bool {
	_, hasProvider := object["providerName"]
	_, hasTimestamp := object["timestamp"]
	_, hasPayload := object["payload"]
	return hasProvider && hasTimestamp && hasPayload
}

func findRedEdr(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if strings.EqualFold(key, "rededr") {
				if object, ok := child.(map[string]any); ok {
					if _, ok := object["findings"]; ok {
						return object, true
					}
				}
			}
			if found, ok := findRedEdr(child); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := findRedEdr(child); ok {
				return found, true
			}
		}
	}
	return nil, false
}

func normalizeRedEdr(object map[string]any) telemetryEvent {
	eventName := strings.TrimSpace(jsonString(object["event"]))
	provider := jsonString(object["etw_provider_name"])
	eventType := strings.TrimSpace(jsonString(object["type"]))
	category := redEdrCategory(provider, eventName, eventType)
	event := telemetryEvent{
		Type:     eventType,
		Event:    eventName,
		Provider: provider,
		PID:      firstInt(object, "etw_pid", "processid", "pid"),
		TID:      firstInt(object, "etw_tid", "threadid"),
		Process:  firstString(object, "etw_process", "process_name"),
		Image:    firstString(object, "imagename", "imagepath"),
		Path:     firstString(object, "filename", "filepath"),
		Address:  firstInt(object, "imagebase", "image_base", "addr"),
		Size:     firstInt(object, "imagesize"),
		Category: category,
	}
	// A Defender BmDetection uses "name" for the threat verdict, not a path.
	if event.Path == "" && category != "defender" {
		event.Path = firstString(object, "name")
	}
	if strings.EqualFold(eventType, "process_query") {
		if eventName == "" {
			event.Event = strings.TrimSpace(jsonString(object["func"]))
		}
		event.Path = jsonString(object["working_dir"])
		event.Image = firstString(object, "image_path")
	}
	if event.Image == "" && strings.EqualFold(eventType, "process_query") {
		event.Image = jsonString(object["process_name"])
	}
	if event.TS = telemetryTime(object); event.TS.IsZero() {
		event.TS = telemetryTimeKey(object, "createtime")
	}
	if event.Category == "defender" && defenderThreatName(eventName, object) != "" {
		event.Severity = "high"
	}
	event.Attrs = encodeObject(object)
	return event
}

func normalizeDefenderObserver(object map[string]any) telemetryEvent {
	payload, _ := object["payload"].(map[string]any)
	event := telemetryEvent{
		Type:     "defender_observer",
		Event:    firstString(object, "symbol", "summary", "task", "opcode"),
		Provider: firstString(object, "providerName"),
		PID:      firstInt(object, "processId"),
		TID:      firstInt(object, "threadId"),
		Process:  firstString(object, "processName"),
		Category: "other",
	}
	if strings.Contains(strings.ToLower(event.Provider), "antimalware") ||
		strings.Contains(strings.ToLower(event.Provider), "defender") {
		event.Category = "defender"
	}
	if timestamp := jsonString(object["timestamp"]); timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			event.TS = parsed.UTC()
		}
	}
	for key, value := range payload {
		text, ok := value.(string)
		if !ok || text == "" {
			continue
		}
		lower := strings.ToLower(key)
		switch {
		case strings.Contains(lower, "image"):
			if event.Image == "" {
				event.Image = text
			}
		case strings.Contains(lower, "path") || strings.Contains(lower, "file"):
			if event.Path == "" {
				event.Path = text
			}
		}
	}
	if event.Category == "defender" && defenderThreatName(event.Event, payload) != "" {
		event.Severity = "high"
	}
	event.Attrs = encodeObject(object)
	return event
}

func redEdrCategory(provider, event, eventType string) string {
	switch {
	case strings.EqualFold(eventType, "process_query"), strings.EqualFold(eventType, "proces_query"):
		return "query"
	case strings.Contains(provider, "Audit-API"):
		return "audit"
	case strings.Contains(provider, "Antimalware"):
		return "defender"
	case strings.Contains(provider, "Kernel-File"):
		return "file"
	case strings.Contains(provider, "Kernel-Network"):
		return "network"
	case strings.Contains(provider, "Kernel-Process"):
		switch {
		case strings.HasPrefix(event, "ImageLoad"), strings.HasPrefix(event, "ImageUnload"):
			return "image"
		case strings.HasPrefix(event, "ProcessStart"):
			return "process"
		case strings.HasPrefix(event, "ThreadStart"):
			return "thread"
		}
	}
	return "other"
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

func payloadIdentity(events []telemetryEvent) (int64, string) {
	var fallbackPID int64
	var fallbackImage string
	for _, event := range events {
		if event.Type != "process_query" {
			continue
		}
		var object map[string]any
		dec := json.NewDecoder(strings.NewReader(event.Attrs))
		dec.UseNumber()
		if dec.Decode(&object) != nil {
			continue
		}
		funcName := strings.ToLower(strings.TrimSpace(jsonString(object["func"])))
		if funcName != "peb" && !strings.EqualFold(event.Event, "peb") {
			continue
		}
		pid := intFrom(object, "pid")
		image := firstString(object, "image_path")
		lower := strings.ToLower(image)
		// The sandbox also traces MsMpEng; its PEB has no image or a Windows
		// image and must not become the payload identity.
		if image == "" || strings.Contains(lower, `\windows\`) || strings.Contains(lower, "msmpeng") {
			if fallbackPID == 0 && pid != 0 {
				fallbackPID, fallbackImage = pid, image
			}
			continue
		}
		return pid, image
	}
	if fallbackPID != 0 {
		return fallbackPID, fallbackImage
	}
	for _, event := range events {
		if event.PID != 0 {
			return event.PID, event.Image
		}
	}
	return 0, ""
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

// parseTelemetryJSONL accepts one JSON object per line and requires at least
// two objects, so a pretty-printed single object is left to the JSON decoder.
func parseTelemetryJSONL(data []byte, sourceHint string) (parsedTelemetry, bool) {
	var maps []map[string]any
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		decoded, err := decodeJSON(line)
		if err != nil {
			continue
		}
		if object, ok := decoded.(map[string]any); ok {
			maps = append(maps, object)
		}
	}
	if len(maps) < 2 {
		return parsedTelemetry{}, false
	}
	parsed, err := parseTelemetryMaps(maps, sourceHint)
	if err != nil {
		return parsedTelemetry{}, false
	}
	return parsed, true
}

// parseRedEdrRawOutput extracts the JSON event lines from RedEdr's stdout,
// which interleaves loguru INFO lines with one JSON object per event.
func parseRedEdrRawOutput(raw, source string) (parsedTelemetry, bool) {
	var maps []map[string]any
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		decoded, err := decodeJSON([]byte(line))
		if err != nil {
			continue
		}
		if object, ok := decoded.(map[string]any); ok {
			maps = append(maps, object)
		}
	}
	if len(maps) == 0 {
		return parsedTelemetry{}, false
	}
	parsed, err := parseTelemetryMaps(maps, source)
	if err != nil {
		return parsedTelemetry{}, false
	}
	return parsed, true
}
