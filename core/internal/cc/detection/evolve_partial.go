package detection

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// persistPartial records the cycles and whatever answer exists when the loop
// exits without a final answer, so a canceled operator session does not lose
// its report.
func (e *evolver) persistPartial() {
	if e == nil || e.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	answer := map[string]any{}
	for key, value := range e.lastAnswer {
		answer[key] = value
	}
	if summary := answerString(answer, "summary"); summary == "" {
		answer["summary"] = "the detection loop stopped before returning a final answer"
	}
	if _, ok := answer["residual"]; !ok {
		answer["residual"] = []string{"the loop stopped before the final JSON object; inspect the last cycle"}
	}
	answer["parse_error"] = "partial result: the loop stopped before the final answer"
	answer["loop_id"] = e.cfg.LoopID
	answer["base_loop_id"] = e.baseLoopID
	answer["attempt"] = e.attempt
	answer["global_cycles"] = e.usedCycles()
	answer["cycles"] = e.cycles
	if e.sourceTreeHash != "" {
		answer["source_tree_hash"] = e.sourceTreeHash
	}
	if e.lastExecuting != nil {
		answer["last_executing_payload"] = e.lastExecuting.PayloadKey
	} else if e.priorLastGood != nil {
		answer["last_executing_payload"] = e.priorLastGood.PayloadKey
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return
	}
	edits, _ := e.db.LoopEdits(ctx, e.cfg.LoopID)
	report := RenderLoopReport(answer, e.cycles, edits)
	reportPath, reportErr := writeLoopReport(e.cfg.StoreRoot, e.cfg.LoopID, report)
	if reportErr == nil {
		e.logClass(logging.ClassWarning, "partial report saved: %s", reportPath)
	}
	if summaryPath, summaryErr := writeLoopSummary(e.cfg.StoreRoot, e.cfg.LoopID, RenderLoopSummary(answer, e.cycles, edits)); summaryErr == nil {
		e.logClass(logging.ClassWarning, "partial executive summary saved: %s", summaryPath)
	}
	if _, err := e.db.db.ExecContext(ctx, `
		INSERT INTO loop_results(loop_id, answer, report, created_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(loop_id) DO UPDATE SET answer = excluded.answer, report = excluded.report, created_at = excluded.created_at`,
		e.cfg.LoopID, string(encoded), report, time.Now().UTC().UnixMilli()); err != nil {
		e.logClass(logging.ClassError, "save partial result: %v", err)
	}
}
