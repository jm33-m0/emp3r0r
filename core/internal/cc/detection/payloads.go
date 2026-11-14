package detection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Payload is one build artifact with its per-payload telemetry view and the
// latest detection cycle. Models compare Payload rows to see what a source
// edit changed between two builds.
type Payload struct {
	ID           int64     `json:"id"`
	Key          string    `json:"key"`
	SHA256       string    `json:"sha256,omitempty"`
	Module       string    `json:"module,omitempty"`
	Label        string    `json:"label,omitempty"`
	ArtifactPath string    `json:"artifact_path,omitempty"`
	Table        string    `json:"table"`
	ParentID     int64     `json:"parent_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Score        float64   `json:"score,omitempty"`
	Level        string    `json:"level,omitempty"`
	Findings     int       `json:"findings,omitempty"`
	Verdicts     int       `json:"verdicts,omitempty"`
	TraceID      int64     `json:"trace_id,omitempty"`
	Iteration    int       `json:"iteration,omitempty"`
	RunID        string    `json:"run_id,omitempty"`
}

// PayloadChange is one normalized event signature whose count differs between
// two payloads.
type PayloadChange struct {
	Category    string `json:"category"`
	Event       string `json:"event"`
	Operation   string `json:"operation,omitempty"`
	Path        string `json:"path,omitempty"`
	Image       string `json:"image,omitempty"`
	TargetImage string `json:"target_image,omitempty"`
	PID         int64  `json:"pid,omitempty"`
	ActorPID    int64  `json:"actor_pid,omitempty"`
	TargetPID   int64  `json:"target_pid,omitempty"`
	Proto       string `json:"proto,omitempty"`
	SrcAddr     string `json:"src_addr,omitempty"`
	DstAddr     string `json:"dst_addr,omitempty"`
	Count       int64  `json:"count"`
}

// PayloadDiff lists event signatures added and removed between two payloads.
type PayloadDiff struct {
	From         Payload         `json:"from"`
	To           Payload         `json:"to"`
	Added        []PayloadChange `json:"added,omitempty"`
	Removed      []PayloadChange `json:"removed,omitempty"`
	AddedTotal   int64           `json:"added_total"`
	RemovedTotal int64           `json:"removed_total"`
}

// ListPayloads returns the newest payloads with their latest cycle summary.
func (t *TelemetryDB) ListPayloads(ctx context.Context, limit int) ([]Payload, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := t.db.QueryContext(ctx, `
		SELECT p.id, p.payload_key, p.sha256, p.module, p.label, p.artifact_path,
		       p.table_name, COALESCE(p.parent_id, 0), p.created_at,
		       COALESCE((SELECT score FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT level FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), ''),
		       COALESCE((SELECT findings FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT verdicts FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT trace_id FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT iteration FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT run_id FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), '')
		FROM payloads p ORDER BY p.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list payloads: %w", err)
	}
	defer rows.Close()
	var out []Payload
	for rows.Next() {
		var p Payload
		var created int64
		if err := rows.Scan(&p.ID, &p.Key, &p.SHA256, &p.Module, &p.Label, &p.ArtifactPath,
			&p.Table, &p.ParentID, &created, &p.Score, &p.Level, &p.Findings, &p.Verdicts,
			&p.TraceID, &p.Iteration, &p.RunID); err != nil {
			return nil, fmt.Errorf("scan payload: %w", err)
		}
		p.CreatedAt = time.UnixMilli(created).UTC()
		p.Label = sanitizeLine(p.Label)
		p.ArtifactPath = sanitizeLine(p.ArtifactPath)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PayloadByKey resolves one payload by its stable key.
func (t *TelemetryDB) PayloadByKey(ctx context.Context, key string) (Payload, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return Payload{}, fmt.Errorf("payload key is required")
	}
	row := t.db.QueryRowContext(ctx, `
		SELECT p.id, p.payload_key, p.sha256, p.module, p.label, p.artifact_path,
		       p.table_name, COALESCE(p.parent_id, 0), p.created_at,
		       COALESCE((SELECT score FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT level FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), ''),
		       COALESCE((SELECT findings FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT verdicts FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT trace_id FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT iteration FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), 0),
		       COALESCE((SELECT run_id FROM loop_cycles c WHERE c.payload_id = p.id ORDER BY c.id DESC LIMIT 1), '')
		FROM payloads p WHERE p.payload_key = ?`, key)
	var p Payload
	var created int64
	if err := row.Scan(&p.ID, &p.Key, &p.SHA256, &p.Module, &p.Label, &p.ArtifactPath,
		&p.Table, &p.ParentID, &created, &p.Score, &p.Level, &p.Findings, &p.Verdicts,
		&p.TraceID, &p.Iteration, &p.RunID); err != nil {
		return Payload{}, fmt.Errorf("payload %q not found: %w", key, err)
	}
	p.CreatedAt = time.UnixMilli(created).UTC()
	p.Label = sanitizeLine(p.Label)
	p.ArtifactPath = sanitizeLine(p.ArtifactPath)
	return p, nil
}

// ComparePayloads computes the event-signature delta between two payloads.
// The full per-payload tables stay in SQLite; only the largest changes are
// returned so a model can see the effect of its edit.
func (t *TelemetryDB) ComparePayloads(ctx context.Context, fromKey, toKey string) (PayloadDiff, error) {
	from, err := t.PayloadByKey(ctx, fromKey)
	if err != nil {
		return PayloadDiff{}, err
	}
	to, err := t.PayloadByKey(ctx, toKey)
	if err != nil {
		return PayloadDiff{}, err
	}
	fromEvents, err := t.payloadEvents(ctx, from.Table)
	if err != nil {
		return PayloadDiff{}, err
	}
	toEvents, err := t.payloadEvents(ctx, to.Table)
	if err != nil {
		return PayloadDiff{}, err
	}
	diff := PayloadDiff{From: from, To: to}
	for key, change := range toEvents {
		previous, ok := fromEvents[key]
		if !ok {
			diff.Added = append(diff.Added, change)
			diff.AddedTotal += change.Count
			continue
		}
		if change.Count > previous.Count {
			change.Count -= previous.Count
			diff.Added = append(diff.Added, change)
			diff.AddedTotal += change.Count
		}
	}
	for key, change := range fromEvents {
		current, ok := toEvents[key]
		if !ok {
			diff.Removed = append(diff.Removed, change)
			diff.RemovedTotal += change.Count
			continue
		}
		if change.Count > current.Count {
			change.Count -= current.Count
			diff.Removed = append(diff.Removed, change)
			diff.RemovedTotal += change.Count
		}
	}
	diff.Added = topChanges(diff.Added, 50)
	diff.Removed = topChanges(diff.Removed, 50)
	return diff, nil
}

func (t *TelemetryDB) payloadEvents(ctx context.Context, table string) (map[string]PayloadChange, error) {
	if !safePayloadTable.MatchString(table) {
		return nil, fmt.Errorf("invalid payload table %q", table)
	}
	rows, err := t.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT category, event, operation, path, image, target_image,
		       COALESCE(pid, 0), COALESCE(actor_pid, 0), COALESCE(target_pid, 0),
		       proto, src_addr, dst_addr, COUNT(*)
		FROM %s
		GROUP BY category, event, operation, path, image, target_image,
		         COALESCE(pid, 0), COALESCE(actor_pid, 0), COALESCE(target_pid, 0),
		         proto, src_addr, dst_addr`, table))
	if err != nil {
		return nil, fmt.Errorf("payload events: %w", err)
	}
	defer rows.Close()
	out := map[string]PayloadChange{}
	for rows.Next() {
		var change PayloadChange
		if err := rows.Scan(&change.Category, &change.Event, &change.Operation,
			&change.Path, &change.Image, &change.TargetImage, &change.PID,
			&change.ActorPID, &change.TargetPID, &change.Proto, &change.SrcAddr,
			&change.DstAddr, &change.Count); err != nil {
			return nil, fmt.Errorf("scan payload event: %w", err)
		}
		sanitizePayloadChange(&change)
		out[payloadChangeKey(change)] = change
	}
	return out, rows.Err()
}

func payloadChangeKey(change PayloadChange) string {
	return strings.Join([]string{
		change.Category, change.Event, change.Operation, change.Path,
		change.Image, change.TargetImage, fmt.Sprint(change.PID),
		fmt.Sprint(change.ActorPID), fmt.Sprint(change.TargetPID),
		change.Proto, change.SrcAddr, change.DstAddr,
	}, "\x00")
}

func topChanges(changes []PayloadChange, limit int) []PayloadChange {
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Count == changes[j].Count {
			return payloadChangeKey(changes[i]) < payloadChangeKey(changes[j])
		}
		return changes[i].Count > changes[j].Count
	})
	if len(changes) > limit {
		return changes[:limit]
	}
	return changes
}

var safePayloadTable = regexp.MustCompile(`^payload_[a-f0-9]{16}$`)

type payloadRef struct {
	ID       int64
	Key      string
	Table    string
	Label    string
	ParentID int64
}

func ensurePayload(ctx context.Context, tx *sql.Tx, opts ImportOptions, parsed parsedTelemetry, externalID string) (payloadRef, error) {
	key, sha, label := payloadKeyIdentity(opts, parsed, externalID)
	table := payloadTableName(key)
	now := time.Now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO payloads(payload_key, sha256, module, label, artifact_path, table_name, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(payload_key) DO UPDATE SET
			module = excluded.module,
			label = excluded.label,
			artifact_path = excluded.artifact_path`,
		key, sha, opts.Module, label, opts.Path, table, now); err != nil {
		return payloadRef{}, fmt.Errorf("record payload: %w", err)
	}
	var payload payloadRef
	if err := tx.QueryRowContext(ctx,
		`SELECT id, payload_key, table_name, label, COALESCE(parent_id, 0) FROM payloads WHERE payload_key = ?`,
		key).Scan(&payload.ID, &payload.Key, &payload.Table, &payload.Label, &payload.ParentID); err != nil {
		return payloadRef{}, fmt.Errorf("load payload: %w", err)
	}
	if opts.ParentKey != "" && payload.ParentID == 0 {
		var parentID int64
		if err := tx.QueryRowContext(ctx,
			`SELECT id FROM payloads WHERE payload_key = ?`, opts.ParentKey).Scan(&parentID); err == nil {
			if _, err := tx.ExecContext(ctx,
				`UPDATE payloads SET parent_id = ? WHERE id = ?`, parentID, payload.ID); err != nil {
				return payloadRef{}, fmt.Errorf("link payload parent: %w", err)
			}
			payload.ParentID = parentID
		}
	}
	if !safePayloadTable.MatchString(payload.Table) {
		return payloadRef{}, fmt.Errorf("invalid payload table %q", payload.Table)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		`CREATE VIEW IF NOT EXISTS %s AS SELECT * FROM events WHERE payload_id = %d`,
		payload.Table, payload.ID)); err != nil {
		return payloadRef{}, fmt.Errorf("create payload view: %w", err)
	}
	return payload, nil
}

func payloadKeyIdentity(opts ImportOptions, parsed parsedTelemetry, externalID string) (key, sha, label string) {
	sha = strings.ToLower(strings.TrimSpace(opts.ArtifactSHA256))
	if sha != "" {
		label = strings.TrimSpace(parsed.MetaString("payload_image"))
		if label == "" {
			label = filepath.Base(opts.Path)
		}
		return "sha256:" + sha, sha, label
	}
	source := externalID
	if source == "" {
		source = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	label = parsed.MetaString("payload_image")
	if label == "" {
		label = opts.Path
	}
	return "trace:" + parsed.Source + ":" + source, "", label
}

func payloadTableName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "payload_" + hex.EncodeToString(sum[:8])
}

// MetaString reads a string from the parsed trace metadata.
func (p parsedTelemetry) MetaString(key string) string {
	value, _ := p.Meta[key].(string)
	return value
}

func ensureColumn(db *sql.DB, table, column, typ string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan %s columns: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, typ)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
