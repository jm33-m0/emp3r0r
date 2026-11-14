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

// RenderLoopReport turns the agent's JSON answer and the persisted cycles into
// a human-readable Markdown report. The raw JSON remains in loop_results.
func RenderLoopReport(answer map[string]any, cycles []Cycle, edits []EditRecord) string {
	var b strings.Builder
	loopID := answerString(answer, "loop_id")
	if loopID == "" && len(cycles) > 0 {
		loopID = cycles[0].LoopID
	}
	fmt.Fprintf(&b, "# Detection loop `%s`\n\n", loopID)

	summary := answerString(answer, "summary")
	if summary == "" {
		summary = "The agent did not return a final summary."
	}
	fmt.Fprintf(&b, "## Outcome\n\n%s\n\n", summary)

	before := answerStrings(answer, "verdicts_before")
	after := answerStrings(answer, "verdicts_after")
	if len(before) > 0 || len(after) > 0 {
		fmt.Fprintf(&b, "| Real Defender verdicts | Value |\n| --- | --- |\n")
		fmt.Fprintf(&b, "| Before | %s |\n", verdictCell(before))
		fmt.Fprintf(&b, "| After | %s |\n\n", verdictCell(after))
	}
	if parseErr := answerString(answer, "parse_error"); parseErr != "" {
		fmt.Fprintf(&b, "> The agent's final text was not the requested JSON object: %s\n\n", parseErr)
	}

	fmt.Fprintf(&b, "## Achieved objectives\n\n")
	achieved := false
	if len(before) > 0 && len(after) == 0 {
		fmt.Fprintf(&b, "- Removed all recorded Defender verdicts (%s).\n", strings.Join(before, ", "))
		achieved = true
	}
	if len(edits) > 0 {
		for _, edit := range edits {
			fmt.Fprintf(&b, "- `%s`: %s\n", sanitizeLine(editPath(edit)), sanitizeLine(edit.Reason))
		}
		achieved = true
	}
	if len(cycles) > 0 {
		last := cycles[len(cycles)-1]
		fmt.Fprintf(&b, "- Rebuilt and detonated the final payload (`%s`, score %.2f, %d findings, %d verdicts).\n",
			shortSHA(strings.TrimPrefix(last.PayloadKey, "sha256:")), last.Score, last.Findings, last.Verdicts)
		if last.Verdicts == 0 {
			fmt.Fprintf(&b, "- Final cycle recorded no real Defender verdicts; remaining items are generic/static findings.\n")
		}
		achieved = true
	}
	if !achieved {
		fmt.Fprintf(&b, "- No source change was completed in this run.\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Cycles\n\n")
	if len(cycles) == 0 {
		fmt.Fprintf(&b, "No cycle completed.\n\n")
	} else {
		fmt.Fprintf(&b, "| # | Payload | SHA-256 | Score | Level | Findings | Verdicts | Trace |\n")
		fmt.Fprintf(&b, "| ---: | --- | --- | ---: | --- | ---: | ---: | ---: |\n")
		for _, cycle := range cycles {
			fmt.Fprintf(&b, "| %d | `%s` | `%s` | %.2f | %s | %d | %d | %d |\n",
				cycle.Iteration, cycle.PayloadKey, shortSHA(strings.TrimPrefix(cycle.PayloadKey, "sha256:")),
				cycle.Score, sanitizeLine(cycle.Level), cycle.Findings, cycle.Verdicts, cycle.TraceID)
		}
		b.WriteString("\n")
	}

	if len(cycles) > 0 {
		if stats := telemetryStatsFromSummary(cycles[len(cycles)-1].Summary); stats != nil {
			fmt.Fprintf(&b, "## Telemetry coverage\n\n")
			fmt.Fprintf(&b, "| Events | Payload events | Signal events | Findings |\n")
			fmt.Fprintf(&b, "| ---: | ---: | ---: | ---: |\n")
			fmt.Fprintf(&b, "| %d | %d | %d | %d |\n\n",
				stats.Events, stats.PayloadEvents, stats.SignalEvents, stats.Findings)
			fmt.Fprintf(&b, "| Source | Status |\n| --- | --- |\n")
			delivered := map[string]bool{}
			for _, name := range stats.Coverage.Delivered {
				name = sanitizeLine(name)
				delivered[name] = true
				fmt.Fprintf(&b, "| `%s` | delivered |\n", name)
			}
			for _, name := range stats.Coverage.Missing {
				fmt.Fprintf(&b, "| `%s` | **missing** |\n", sanitizeLine(name))
			}
			if len(delivered) == 0 && len(stats.Coverage.Missing) == 0 {
				fmt.Fprintf(&b, "| none | no RedEdr source produced events |\n")
			}
			b.WriteString("\n")
		}
	}

	if len(edits) > 0 {
		fmt.Fprintf(&b, "## Source edits\n\n")
		for _, edit := range edits {
			fmt.Fprintf(&b, "### `%s`\n\n%s\n\n", sanitizeLine(editPath(edit)), sanitizeMultiline(edit.Reason))
		}
	}

	residual := answerStrings(answer, "residual")
	if len(residual) > 0 {
		fmt.Fprintf(&b, "## Residual findings\n\n")
		for _, item := range residual {
			fmt.Fprintf(&b, "- %s\n", item)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Final payload views\n\n")
	seen := map[string]bool{}
	for _, cycle := range cycles {
		table := cycle.PayloadTable
		if table == "" {
			table = payloadTableFromSummary(cycle.Summary)
		}
		if table == "" || seen[table] {
			continue
		}
		seen[table] = true
		fmt.Fprintf(&b, "- `%s` (iteration %d)\n", table, cycle.Iteration)
	}
	if len(seen) == 0 {
		fmt.Fprintf(&b, "No payload view was recorded.\n")
	}
	return b.String()
}

func telemetryStatsFromSummary(summary string) *TelemetryStats {
	if strings.TrimSpace(summary) == "" {
		return nil
	}
	var value struct {
		Telemetry *TelemetryStats `json:"telemetry"`
	}
	if json.Unmarshal([]byte(summary), &value) != nil {
		return nil
	}
	return value.Telemetry
}

func answerString(answer map[string]any, key string) string {
	value, _ := answer[key].(string)
	return sanitizeMultiline(value)
}

func answerStrings(answer map[string]any, key string) []string {
	raw, ok := answer[key].([]any)
	if !ok {
		values, _ := answer[key].([]string)
		return sanitizeStrings(values)
	}
	var out []string
	for _, item := range raw {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, sanitizeLine(text))
		}
	}
	return out
}

func verdictCell(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "<br>")
}

func payloadTableFromSummary(summary string) string {
	var value map[string]any
	if json.Unmarshal([]byte(summary), &value) != nil {
		return ""
	}
	table, _ := value["payload_table"].(string)
	return table
}

// LoopReport returns the persisted Markdown report for one loop. If an older
// row has no report yet, it renders and stores one from the answer and cycles.
func (t *TelemetryDB) LoopReport(ctx context.Context, loopID string) (string, error) {
	var answerRaw, report string
	err := t.db.QueryRowContext(ctx,
		`SELECT answer, report FROM loop_results WHERE loop_id = ?`, loopID).
		Scan(&answerRaw, &report)
	if errors.Is(err, sql.ErrNoRows) {
		answerRaw, report = "{}", ""
	} else if err != nil {
		return "", fmt.Errorf("loop %q: %w", loopID, err)
	}
	if strings.TrimSpace(report) != "" {
		return report, nil
	}
	var answer map[string]any
	_ = json.Unmarshal([]byte(answerRaw), &answer)
	if answer == nil {
		answer = map[string]any{}
	}
	cycles, err := t.CyclesForLoop(ctx, loopID)
	if err != nil {
		return "", err
	}
	edits, err := t.LoopEdits(ctx, loopID)
	if err != nil {
		return "", err
	}
	report = RenderLoopReport(answer, cycles, edits)
	if _, err := t.db.ExecContext(ctx,
		`UPDATE loop_results SET report = ? WHERE loop_id = ?`, report, loopID); err != nil {
		return report, err
	}
	return report, nil
}

// CyclesForLoop returns every cycle belonging to one loop, in iteration order.
func (t *TelemetryDB) CyclesForLoop(ctx context.Context, loopID string) ([]Cycle, error) {
	rows, err := t.db.QueryContext(ctx, `
		SELECT c.id, c.loop_id, c.iteration, c.payload_id, c.run_id, c.score, c.level,
		       c.findings, c.verdicts, COALESCE(c.trace_id, 0), c.summary, c.created_at,
		       COALESCE(p.payload_key, ''), COALESCE(p.table_name, '')
		FROM loop_cycles c LEFT JOIN payloads p ON p.id = c.payload_id
		WHERE c.loop_id = ? ORDER BY c.iteration`, loopID)
	if err != nil {
		return nil, fmt.Errorf("read loop cycles: %w", err)
	}
	defer rows.Close()
	var out []Cycle
	for rows.Next() {
		var cycle Cycle
		var created int64
		if err := rows.Scan(&cycle.ID, &cycle.LoopID, &cycle.Iteration, &cycle.PayloadID,
			&cycle.RunID, &cycle.Score, &cycle.Level, &cycle.Findings, &cycle.Verdicts,
			&cycle.TraceID, &cycle.Summary, &created, &cycle.PayloadKey, &cycle.PayloadTable); err != nil {
			return nil, err
		}
		cycle.CreatedAt = time.UnixMilli(created).UTC()
		out = append(out, cycle)
	}
	return out, rows.Err()
}

// editPath names the edited file with its source root when it is a producer or
// dependency module rather than the payload module.
func editPath(edit EditRecord) string {
	if strings.TrimSpace(edit.Module) == "" {
		return edit.File
	}
	return edit.Module + "/" + edit.File
}
