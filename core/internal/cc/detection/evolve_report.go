package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RenderLoopSummary returns a compact Markdown summary for the operator
// console. The full report remains next to it for the log pane and the report
// file.
func RenderLoopSummary(answer map[string]any, cycles []Cycle, edits []EditRecord) string {
	edits = modelEdits(edits)
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
	fmt.Fprintf(&b, "**Outcome:** %s\n\n", clipUTF8(summary, 700))

	mechanism := answerString(answer, "mechanism")
	if mechanism == "" && len(cycles) > 0 {
		var last cycleSummary
		if json.Unmarshal([]byte(cycles[len(cycles)-1].Summary), &last) == nil {
			mechanism = last.Mechanism
		}
	}
	if mechanism != "" {
		fmt.Fprintf(&b, "**Mechanism:** `%s`\n", sanitizeLine(mechanism))
	}
	if len(cycles) > 0 {
		first, last := cycles[0], cycles[len(cycles)-1]
		firstCounts, lastCounts := cycleFindingCounts(&first), cycleFindingCounts(&last)
		fmt.Fprintf(&b, "**High findings:** %d → %d | **Static signatures:** %d → %d | **Total findings:** %d → %d | **Verdicts:** %d → %d | **Cycles:** %d\n",
			firstCounts.High, lastCounts.High, firstCounts.Static, lastCounts.Static,
			firstCounts.Total, lastCounts.Total, first.Verdicts, last.Verdicts, len(cycles))
		if last.Execution == executionOffline {
			fmt.Fprintf(&b, "\n> The final cycle did not execute; its finding counts are not comparable with an executing cycle.\n")
		}
	}
	if usage, ok := tokenUsageFromAnswer(answer); ok {
		fmt.Fprintf(&b, "**Tokens:** %s in / %s out | **Estimated cost:** %s\n",
			formatTokenCount(usage.Input), formatTokenCount(usage.Output), costLabel(usage))
	}

	fmt.Fprintf(&b, "\n## Changes\n\n")
	if len(edits) == 0 {
		fmt.Fprintf(&b, "- No source edits were recorded.\n")
	} else {
		for i, edit := range edits {
			if i >= 6 {
				fmt.Fprintf(&b, "- and %d more\n", len(edits)-i)
				break
			}
			fmt.Fprintf(&b, "- `%s`: %s\n", sanitizeLine(editPath(edit)), clipUTF8(sanitizeLine(edit.Reason), 180))
		}
	}

	renderGitHistory(&b, answer)

	residual := answerStrings(answer, "residual")
	if len(residual) > 0 {
		fmt.Fprintf(&b, "\n## Residuals\n\n")
		for i, item := range residual {
			if i >= 5 {
				fmt.Fprintf(&b, "- and %d more\n", len(residual)-i)
				break
			}
			fmt.Fprintf(&b, "- %s\n", clipUTF8(item, 180))
		}
	}
	return b.String()
}

// RenderLoopReport turns the agent's JSON answer and the persisted cycles into
// a human-readable Markdown report. The raw JSON remains in loop_results.
func RenderLoopReport(answer map[string]any, cycles []Cycle, edits []EditRecord) string {
	edits = modelEdits(edits)
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

	renderFindingObjective(&b, cycles)

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
		counts := cycleFindingCounts(&last)
		fmt.Fprintf(&b, "- Rebuilt and detonated the final payload (`%s`, high=%d, medium=%d, static=%d, total=%d, verdicts=%d, execution=%s).\n",
			shortPayloadKey(last.PayloadKey), counts.High, counts.Medium, counts.Static, counts.Total, last.Verdicts, headerOrNone(last.Execution))
		if last.Execution == executionOffline {
			fmt.Fprintf(&b, "- Final payload did not execute; its finding counts are not comparable with an executing cycle.\n")
		} else if last.Verdicts == 0 {
			fmt.Fprintf(&b, "- Final cycle recorded no real Defender verdicts; remaining items are static/dynamic findings.\n")
		}
		if counts.Static == 0 {
			fmt.Fprintf(&b, "- No static YARA/CheckPlz/Stringnalyzer signature finding was recorded in the final cycle.\n")
		}
		achieved = true
	}
	if !achieved {
		fmt.Fprintf(&b, "- No source change was completed in this run.\n")
	}
	b.WriteString("\n")

	renderGitHistory(&b, answer)

	renderModelUsage(&b, answer)

	fmt.Fprintf(&b, "## Cycles\n\n")
	if len(cycles) == 0 {
		fmt.Fprintf(&b, "No cycle completed.\n\n")
	} else {
		fmt.Fprintf(&b, "| # | Payload | SHA-256 | High | Medium | Static | Total | Verdicts | Execution | Trace |\n")
		fmt.Fprintf(&b, "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |\n")
		for _, cycle := range cycles {
			counts := cycleFindingCounts(&cycle)
			fmt.Fprintf(&b, "| %d | `%s` | `%s` | %d | %d | %d | %d | %d | %s | %d |\n",
				cycle.Iteration, cycle.PayloadKey, shortPayloadKey(cycle.PayloadKey),
				counts.High, counts.Medium, counts.Static, counts.Total, cycle.Verdicts,
				headerOrNone(cycle.Execution), cycle.TraceID)
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

	renderGitHistory(&b, answer)

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

func modelEdits(edits []EditRecord) []EditRecord {
	out := make([]EditRecord, 0, len(edits))
	for _, edit := range edits {
		if editKind(edit.Kind) == EditKindModel {
			out = append(out, edit)
		}
	}
	return out
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
	rows, err := t.db.QueryContext(ctx, `SELECT `+cycleColumns+` `+cycleFrom+
		` WHERE c.loop_id = ? ORDER BY c.iteration`, loopID)
	if err != nil {
		return nil, fmt.Errorf("read loop cycles: %w", err)
	}
	return scanCycleRows(rows)
}

// editPath names the edited file with its source root when it is a producer or
// dependency module rather than the payload module.
func editPath(edit EditRecord) string {
	if strings.TrimSpace(edit.Module) == "" {
		return edit.File
	}
	return edit.Module + "/" + edit.File
}

// renderGitHistory adds the shadow-repository record when versioning ran.
func renderGitHistory(b *strings.Builder, answer map[string]any) {
	dir := answerString(answer, "git_dir")
	if dir == "" {
		return
	}
	fmt.Fprintf(b, "## Source history\n\n")
	fmt.Fprintf(b, "Shadow repository: `%s`\n\n", sanitizeLine(dir))
	heads := make(map[string]string)
	switch value := answer["git_heads"].(type) {
	case map[string]string:
		for name, commit := range value {
			heads[name] = commit
		}
	case map[string]any:
		for name, commit := range value {
			if text, ok := commit.(string); ok {
				heads[name] = text
			}
		}
	}
	if len(heads) == 0 {
		fmt.Fprintf(b, "No commit was recorded.\n\n")
		return
	}
	names := make([]string, 0, len(heads))
	for name := range heads {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(b, "- `%s`: `%s`\n", sanitizeLine(name), sanitizeLine(heads[name]))
	}
	b.WriteString("\n")
}

// renderFindingObjective puts the loop's actual objective before the change
// log: high findings, static signatures, total findings, and real verdicts.
func renderFindingObjective(b *strings.Builder, cycles []Cycle) {
	if len(cycles) == 0 {
		return
	}
	first, last := cycles[0], cycles[len(cycles)-1]
	before, after := cycleFindingCounts(&first), cycleFindingCounts(&last)
	executing := 0
	for i := range cycles {
		if cycles[i].Execution == executionVerified {
			executing++
		}
	}
	fmt.Fprintf(b, "## Findings objective\n\n")
	fmt.Fprintf(b, "| Metric | Baseline | Final | Change |\n")
	fmt.Fprintf(b, "| --- | ---: | ---: | ---: |\n")
	fmt.Fprintf(b, "| High findings | %d | %d | %s |\n", before.High, after.High, signedChange(after.High-before.High))
	fmt.Fprintf(b, "| Static signatures | %d | %d | %s |\n", before.Static, after.Static, signedChange(after.Static-before.Static))
	fmt.Fprintf(b, "| Total findings | %d | %d | %s |\n", before.Total, after.Total, signedChange(after.Total-before.Total))
	fmt.Fprintf(b, "| Defender verdicts | %d | %d | %s |\n", first.Verdicts, last.Verdicts, signedChange(last.Verdicts-first.Verdicts))
	fmt.Fprintf(b, "\nExecuting cycles: %d/%d.", executing, len(cycles))
	if last.Execution != executionVerified {
		fmt.Fprintf(b, " The final cycle did not execute, so its counts are not a detection result.")
	}
	b.WriteString("\n\n")
}

func signedChange(delta int) string {
	if delta > 0 {
		return fmt.Sprintf("+%d", delta)
	}
	return fmt.Sprintf("%d", delta)
}

// renderModelUsage shows where the model budget went. Rates are optional; a
// report without rates still gives the exact token counts.
func renderModelUsage(b *strings.Builder, answer map[string]any) {
	usage, ok := tokenUsageFromAnswer(answer)
	if !ok {
		return
	}
	fmt.Fprintf(b, "## Model usage\n\n")
	if !usage.PricingConfigured {
		fmt.Fprintf(b, "Cost rates were not configured; token counts are exact and the cost column is omitted. Pass `--input-price`, `--output-price`, `--cache-read-price`, and `--cache-write-price` in USD per million tokens to estimate cost.\n\n")
	}
	fmt.Fprintf(b, "| Role | Input | Output | Cache read | Cache write | Cost |\n")
	fmt.Fprintf(b, "| --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, role := range usage.Roles {
		cost := "—"
		if usage.PricingConfigured {
			cost = formatUSD(role.CostUSD)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
			sanitizeLine(role.Role), formatTokenCount(role.Input), formatTokenCount(role.Output),
			formatTokenCount(role.CacheRead), formatTokenCount(role.CacheWrite), cost)
	}
	totalCost := "—"
	if usage.PricingConfigured {
		totalCost = formatUSD(usage.CostUSD)
	}
	fmt.Fprintf(b, "| **total** | **%s** | **%s** | **%s** | **%s** | **%s** |\n\n",
		formatTokenCount(usage.Input), formatTokenCount(usage.Output),
		formatTokenCount(usage.CacheRead), formatTokenCount(usage.CacheWrite), totalCost)
}

// tokenUsageFromAnswer accepts the live struct and the JSON-decoded map that a
// persisted loop report carries.
func tokenUsageFromAnswer(answer map[string]any) (TokenUsage, bool) {
	raw, ok := answer["token_usage"]
	if !ok {
		return TokenUsage{}, false
	}
	if usage, ok := raw.(TokenUsage); ok {
		return usage, true
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return TokenUsage{}, false
	}
	var usage TokenUsage
	if json.Unmarshal(body, &usage) != nil {
		return TokenUsage{}, false
	}
	return usage, true
}
