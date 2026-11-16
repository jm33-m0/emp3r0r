package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestPersistPartialReport(t *testing.T) {
	store := t.TempDir()
	db, err := OpenTelemetryDB(filepath.Join(store, "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := &evolver{
		cfg:        EvolveConfig{LoopID: "loop", StoreRoot: store},
		db:         db,
		baseLoopID: "loop",
		attempt:    1,
		lastAnswer: map[string]any{"summary": "partial summary"},
		cycles: []Cycle{{
			LoopID: "loop", Iteration: 1, PayloadID: 1,
			Summary: `{"mechanism":"self-load"}`,
		}},
		logf: func(logging.Class, string, ...any) {},
	}
	e.persistPartial()
	report, err := os.ReadFile(filepath.Join(store, "reports", "loop.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "partial summary") {
		t.Fatalf("partial report = %s", report)
	}
	var answer string
	if err := db.db.QueryRow(`SELECT answer FROM loop_results WHERE loop_id = 'loop'`).Scan(&answer); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer, "partial summary") {
		t.Fatalf("stored answer = %s", answer)
	}
}

func TestStableTelemetryViews(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.db.Exec(`INSERT INTO payloads(payload_key, sha256, module, table_name)
		VALUES('sha256:view', 'view', 'loader_windows', 'payload_view_rows')`)
	if err != nil {
		t.Fatal(err)
	}
	payloadID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO loop_cycles(loop_id, iteration, payload_id, run_id)
		VALUES('loop', 1, ?, 'run')`, payloadID); err != nil {
		t.Fatal(err)
	}
	var key string
	var traceID int64
	if err := db.db.QueryRow(`SELECT payload_key, COALESCE(trace_id, 0) FROM cycle_history WHERE loop_id = 'loop'`).
		Scan(&key, &traceID); err != nil {
		t.Fatal(err)
	}
	if key != "sha256:view" || traceID != 0 {
		t.Fatalf("cycle_history = %q %d", key, traceID)
	}
	if err := db.db.QueryRow(`SELECT payload_key FROM payload_view WHERE payload_id = ?`, payloadID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key != "sha256:view" {
		t.Fatalf("payload_view = %q", key)
	}
}
