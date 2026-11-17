package detection

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestInspectFeedbackDoesNotStopTheSession(t *testing.T) {
	db, err := OpenTelemetryDB(t.TempDir() + "/telemetry.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.db.Exec(`INSERT INTO payloads(payload_key, sha256, module, table_name)
		VALUES('sha256:feedback', 'feedback', 'loader_windows', 'payload_feedback')`)
	if err != nil {
		t.Fatal(err)
	}
	payloadID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveFeedback(context.Background(), FeedbackRecord{
		LoopID: "loop", Iteration: 1, PayloadID: payloadID, RunID: "run-1", Body: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		db:   db,
		logf: func(logging.Class, string, ...any) {},
	}
	result, err := e.inspectFeedbackTool().Call(context.Background(), json.RawMessage(`{"run_id":"run-1"}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("InspectFeedback failed: err=%v result=%+v", err, result)
	}
	if e.sessionStopped() {
		t.Fatal("InspectFeedback stopped the worker session")
	}
}
