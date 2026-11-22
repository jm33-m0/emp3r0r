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

// reportPlatform reads the sandbox runtime from the first cycle summary.
func reportPlatform(cycles []Cycle) string {
	for _, cycle := range cycles {
		var summary cycleSummary
		if json.Unmarshal([]byte(cycle.Summary), &summary) == nil && summary.Platform != "" {
			return summary.Platform
		}
	}
	return platformWindows
}

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
		if json.Unmarshal([]byte(cycles[reportFinalIndex(cycles, answer)].Summary), &last) == nil {
			mechanism = last.Mechanism
		}
	}
	if mechanism != "" {
		fmt.Fprintf(&b, "**Mechanism:** `%s`\n", sanitizeLine(mechanism))
	}
	if len(cycles) > 0 {
		finalIndex := reportFinalIndex(cycles, answer)
		first, last := cycles[0], cycles[finalIndex]
		firstCounts, lastCounts := cycleFindingCounts(&first), cycleFindingCounts(&last)
		fmt.Fprintf(&b, "**High findings:** %d → %d | **Static findings:** %d → %d | **Total findings:** %d → %d | **Verdicts:** %d → %d | **Cycles:** %d\n",
			firstCounts.High, lastCounts.High, firstCounts.Static, lastCounts.Static,
			firstCounts.Total, lastCounts.Total, first.Verdicts, last.Verdicts, len(cycles))
		fmt.Fprintf(&b, "**Detection high:** %d → %d | **Hygiene high:** %d → %d | **Detection medium:** %d → %d | **Hygiene medium:** %d → %d\n",
			firstCounts.DetectionHigh, lastCounts.DetectionHigh, firstCounts.HygieneHigh, lastCounts.HygieneHigh,
			firstCounts.DetectionMedium, lastCounts.DetectionMedium, firstCounts.HygieneMedium, lastCounts.HygieneMedium)
		var finalSummary cycleSummary
		if json.Unmarshal([]byte(last.Summary), &finalSummary) == nil {
			if len(finalSummary.Hygiene) > 0 {
				fmt.Fprintf(&b, "**Static hygiene:** %d open\n", len(finalSummary.Hygiene))
			}
			if len(finalSummary.CoverageMissing) > 0 {
				fmt.Fprintf(&b, "**Coverage:** incomplete (%d missing analyzer(s))\n", len(finalSummary.CoverageMissing))
			}
		}
		if last.Execution == executionOffline {
			fmt.Fprintf(&b, "\n> The final cycle did not execute; its finding counts are not comparable with an executing cycle.\n")
		}
		if removed, added := deliveredDiff(cycleDelivered(first), cycleDelivered(last)); len(removed) > 0 || len(added) > 0 {
			fmt.Fprintf(&b, "\n> **Counts are not comparable:** cycle 1 delivered `%s`; cycle %d delivered `%s`",
				strings.Join(cycleDelivered(first), ", "), last.Iteration, strings.Join(cycleDelivered(last), ", "))
			if len(removed) > 0 {
				fmt.Fprintf(&b, " (removed `%s`)", strings.Join(removed, ", "))
			}
			if len(added) > 0 {
				fmt.Fprintf(&b, " (added `%s`)", strings.Join(added, ", "))
			}
			fmt.Fprintf(&b, ". Telemetry findings that vanished with a removed source were not observed, not evaded.\n")
		}
		if note := reportLastCycleNote(cycles, finalIndex); note != "" {
			fmt.Fprintf(&b, "\n> %s\n", note)
		}
		if baselineIndex := reportBaselineIndex(cycles, answer); baselineIndex >= 0 && baselineIndex != finalIndex {
			baseline := cycles[baselineIndex]
			baselineCounts := cycleFindingCounts(&baseline)
			fmt.Fprintf(&b, "\n> The host's finding baseline is cycle %d (`%s`, verdicts=%d, high=%d, medium=%d, total=%d); the final counts above are the last verified payload, which did not replace it.\n",
				baseline.Iteration, shortPayloadKey(baseline.PayloadKey), baseline.Verdicts,
				baselineCounts.High, baselineCounts.Medium, baselineCounts.Total)
		}
	}
	if usage, ok := tokenUsageFromAnswer(answer); ok {
		fmt.Fprintf(&b, "**Tokens:** %s in / %s out | **Estimated cost:** %s\n",
			formatTokenCount(usage.Input), formatTokenCount(usage.Output), costLabel(usage))
	}

	fmt.Fprintf(&b, "\n## Finding-to-change map\n\n")
	changes, newFinal := reportFindingChanges(cycles, reportFinalIndex(cycles, answer), edits)
	if len(changes) == 0 {
		if len(newFinal) > 0 {
			fmt.Fprintf(&b, "- The baseline did not report a top finding; the final cycle introduced: %s\n",
				clipUTF8(strings.Join(limitStrings(newFinal, 4), "; "), 300))
		} else {
			fmt.Fprintf(&b, "- The baseline did not report a top finding, so no finding mapping was possible.\n")
		}
		for i, edit := range edits {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "- Applied edit: `%s`: %s\n", sanitizeLine(editPath(edit)), clipUTF8(sanitizeLine(edit.Reason), 160))
		}
	} else {
		for i, change := range changes {
			if i >= 4 {
				fmt.Fprintf(&b, "- and %d more\n", len(changes)-i)
				break
			}
			fmt.Fprintf(&b, "- %s: %s; %s\n", clipUTF8(change.Finding, 180), change.Final, clipUTF8(change.Change, 240))
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

	finalIndex := reportFinalIndex(cycles, answer)
	var before, after []string
	if len(cycles) > 0 && finalIndex >= 0 {
		before = cycleVerdictNames(cycles[0])
		after = cycleVerdictNames(cycles[finalIndex])
	}
	verdictLabel := "Real Defender verdicts"
	if reportPlatform(cycles) == platformLinux {
		verdictLabel = "High-confidence Falco alerts"
	}
	if len(cycles) > 0 {
		fmt.Fprintf(&b, "| %s | Value |\n| --- | --- |\n", verdictLabel)
		fmt.Fprintf(&b, "| Before | %s |\n", verdictCell(before))
		fmt.Fprintf(&b, "| After | %s |\n\n", verdictCell(after))
	}
	if parseErr := answerString(answer, "parse_error"); parseErr != "" {
		fmt.Fprintf(&b, "> The agent's final text was not the requested JSON object: %s\n\n", parseErr)
	}

	renderFindingObjective(&b, cycles, finalIndex)
	renderFindingChangeMap(&b, cycles, finalIndex, edits)

	fmt.Fprintf(&b, "## Findings status\n\n")
	achieved := false
	if len(before) > 0 && len(after) == 0 {
		fmt.Fprintf(&b, "- Removed all recorded %s (%s).\n", strings.ToLower(verdictLabel), strings.Join(before, ", "))
		achieved = true
	}
	changes, _ := reportFindingChanges(cycles, finalIndex, edits)
	for _, change := range changes {
		switch change.Final {
		case "not in final top findings":
			fmt.Fprintf(&b, "- %s: not in the final top findings. %s\n", clipUTF8(change.Finding, 220), clipUTF8(change.Change, 320))
			achieved = true
		case "still present":
			fmt.Fprintf(&b, "- %s remained in the final top findings; it was not counted as removed.\n", clipUTF8(change.Finding, 220))
			achieved = true
		}
	}
	if finalIndex >= 0 {
		last := cycles[finalIndex]
		counts := cycleFindingCounts(&last)
		fmt.Fprintf(&b, "- Final payload: `%s` (high=%d, medium=%d, static=%d, total=%d, verdicts=%d, execution=%s).\n",
			shortPayloadKey(last.PayloadKey), counts.High, counts.Medium, counts.Static, counts.Total, last.Verdicts, headerOrNone(last.Execution))
		if last.Execution == executionOffline {
			fmt.Fprintf(&b, "- Final payload did not execute; its finding counts are not comparable with an executing cycle.\n")
		}
		if counts.Static == 0 && last.Execution == executionVerified {
			fmt.Fprintf(&b, "- No static YARA/CheckPlz/Stringnalyzer signature finding was recorded in the final cycle.\n")
		}
		var finalSummary cycleSummary
		if json.Unmarshal([]byte(last.Summary), &finalSummary) == nil {
			if len(finalSummary.Hygiene) > 0 {
				fmt.Fprintf(&b, "- Static hygiene backlog: %d item(s) remain; see the Static hygiene table.\n", len(finalSummary.Hygiene))
			}
			if len(finalSummary.CoverageMissing) > 0 {
				fmt.Fprintf(&b, "- Final payload coverage is incomplete: %s. Its finding counts are not a clean result.\n",
					clipUTF8(sanitizeLine(strings.Join(finalSummary.CoverageMissing, "; ")), 500))
			}
		}
		if baselineIndex := reportBaselineIndex(cycles, answer); baselineIndex >= 0 && baselineIndex != finalIndex {
			baseline := cycles[baselineIndex]
			baselineCounts := cycleFindingCounts(&baseline)
			fmt.Fprintf(&b, "- Finding baseline: cycle %d `%s` (verdicts=%d, high=%d, medium=%d, total=%d); the final payload above did not replace it.\n",
				baseline.Iteration, shortPayloadKey(baseline.PayloadKey), baseline.Verdicts,
				baselineCounts.High, baselineCounts.Medium, baselineCounts.Total)
		}
		if note := reportLastCycleNote(cycles, finalIndex); note != "" {
			fmt.Fprintf(&b, "- %s\n", note)
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
		var optionRows []string
		for _, cycle := range cycles {
			var summary cycleSummary
			if json.Unmarshal([]byte(cycle.Summary), &summary) != nil {
				continue
			}
			if len(summary.BuildOptions) == 0 && len(summary.ProducerOptions) == 0 {
				continue
			}
			row := fmt.Sprintf("- Cycle %d: build options `%s`", cycle.Iteration, sanitizeLine(formatBuildOptions(summary.BuildOptions)))
			if summary.Producer != "" {
				row += fmt.Sprintf("; producer `%s` options `%s`", sanitizeLine(summary.Producer), sanitizeLine(formatBuildOptions(summary.ProducerOptions)))
			}
			optionRows = append(optionRows, row)
		}
		if len(optionRows) > 0 {
			fmt.Fprintf(&b, "## Build options\n\n")
			for _, row := range optionRows {
				fmt.Fprintf(&b, "%s\n", row)
			}
			b.WriteString("\n")
		}
	}

	renderHygieneBacklog(&b, cycles, finalIndex)

	if len(cycles) > 0 {
		if stats := telemetryStatsFromSummary(cycles[finalIndex].Summary); stats != nil {
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
		if editKind(edit.Kind) == EditKindModel && !edit.Reverted {
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

// renderHygieneBacklog shows stable static findings across the executing
// payloads. It stops at the final executing cycle; rejected attempts are not a
// hygiene baseline.
func renderHygieneBacklog(b *strings.Builder, cycles []Cycle, finalIndex int) {
	if len(cycles) == 0 || finalIndex < 0 || finalIndex >= len(cycles) {
		return
	}
	type row struct {
		item        hygieneFinding
		first, last int
		final       bool
	}
	rows := map[string]*row{}
	order := make([]string, 0, 8)
	for i := 0; i <= finalIndex && i < len(cycles); i++ {
		var summary cycleSummary
		if json.Unmarshal([]byte(cycles[i].Summary), &summary) != nil {
			continue
		}
		for _, item := range summary.Hygiene {
			key := hygieneKey(item)
			if key == "|" {
				continue
			}
			entry, ok := rows[key]
			if !ok {
				if len(order) >= 32 {
					continue
				}
				entry = &row{item: item, first: i, last: i}
				rows[key] = entry
				order = append(order, key)
			} else {
				entry.item = item
				entry.last = i
			}
			if i == finalIndex {
				entry.final = true
			}
		}
	}
	if len(order) == 0 {
		return
	}
	b.WriteString("## Static hygiene\n\n")
	if reportPlatform(cycles) == platformLinux {
		b.WriteString("Stable elf/*, YARA, and string findings; stringnalyzer indicators are omitted because they change per build.\n\n")
	} else {
		b.WriteString("Stable pe/*, YARA, and CheckPlz findings; stringnalyzer indicators are omitted because they change per build.\n\n")
	}
	b.WriteString("| Finding | Severity | First seen | Last seen | Final status | Source |\n")
	b.WriteString("| --- | --- | ---: | ---: | --- | --- |\n")
	for _, key := range order {
		entry := rows[key]
		finding := strings.TrimSpace(strings.Join([]string{entry.item.Rule, entry.item.Indicator}, " "))
		if finding == "" {
			continue
		}
		status := "not in final payload"
		if entry.final {
			status = "present"
		}
		source := entry.item.Source
		if source == "" {
			source = "—"
		}
		fmt.Fprintf(b, "| `%s` | %s | %d | %d | %s | %s |\n",
			markdownCell(finding), markdownCell(entry.item.Severity), cycles[entry.first].Iteration,
			cycles[entry.last].Iteration, markdownCell(status), markdownCell(source))
	}
	b.WriteString("\n")
}

// renderFindingObjective puts the loop's actual objective before the change
// log: high findings, static findings, total findings, and real verdicts.
// reportFinalIndex picks the payload whose findings the report should show.
// A cycle can have run in the sandbox without checking in, so execution is
// required. last_verified_payload is the newest artifact whose agent checked
// in; last_executing_payload is the host's finding baseline, which a held or
// regressed cycle does not replace.
func reportFinalIndex(cycles []Cycle, answer map[string]any) int {
	if len(cycles) == 0 {
		return -1
	}
	for _, name := range []string{"last_verified_payload", "last_executing_payload"} {
		key := strings.TrimSpace(answerString(answer, name))
		if key == "" {
			continue
		}
		for i := len(cycles) - 1; i >= 0; i-- {
			if cycles[i].PayloadKey == key && cycles[i].Execution == executionVerified {
				return i
			}
		}
	}
	for i := len(cycles) - 1; i >= 0; i-- {
		if cycles[i].Execution == executionVerified {
			return i
		}
	}
	return len(cycles) - 1
}

// reportBaselineIndex returns the cycle the host kept as the finding baseline.
// It can differ from reportFinalIndex when a verified payload did not replace
// the baseline, so the report names both instead of calling the baseline the
// final artifact.
func reportBaselineIndex(cycles []Cycle, answer map[string]any) int {
	key := strings.TrimSpace(answerString(answer, "last_executing_payload"))
	if key == "" {
		return -1
	}
	for i := len(cycles) - 1; i >= 0; i-- {
		if cycles[i].PayloadKey == key && cycles[i].Execution == executionVerified {
			return i
		}
	}
	return -1
}

// cycleVerdictNames returns the sandbox's named verdicts for one cycle. The
// report derives the before/after table from the cycles, not from the model's
// final text, so a mistaken summary cannot relabel a verdict-free payload as
// one that still carries a verdict.
func cycleVerdictNames(cycle Cycle) []string {
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) == nil {
		if names := sanitizeStrings(summary.Verdicts); len(names) > 0 {
			return names
		}
	}
	if cycle.Verdicts > 0 {
		return []string{fmt.Sprintf("%d verdict(s) recorded without a stored name", cycle.Verdicts)}
	}
	return nil
}

// reportLastCycleNote explains why the report's final payload is not the last
// attempted cycle. A cycle can fail to check in, or it can check in without
// replacing the finding baseline (a regression the host held). The two cases
// need different wording: only the first one failed to execute.
func reportLastCycleNote(cycles []Cycle, finalIndex int) string {
	if len(cycles) == 0 || finalIndex == len(cycles)-1 {
		return ""
	}
	last := cycles[len(cycles)-1]
	if last.Execution != executionVerified {
		return fmt.Sprintf("The last attempted cycle (%d) did not check in (execution=%s); the final column is the last verified payload.",
			last.Iteration, headerOrNone(last.Execution))
	}
	if finalIndex >= 0 && cycles[finalIndex].Execution == executionVerified {
		return fmt.Sprintf("The last attempted cycle (%d) checked in but did not replace the finding baseline; the final column is the finding baseline payload.",
			last.Iteration)
	}
	return fmt.Sprintf("The last attempted cycle (%d) did not count as a verified payload; the final column is the last verified payload.",
		last.Iteration)
}

func renderFindingObjective(b *strings.Builder, cycles []Cycle, finalIndex int) {
	if len(cycles) == 0 || finalIndex < 0 || finalIndex >= len(cycles) {
		return
	}
	first, last := cycles[0], cycles[finalIndex]
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
	fmt.Fprintf(b, "| Detection high | %d | %d | %s |\n", before.DetectionHigh, after.DetectionHigh, signedChange(after.DetectionHigh-before.DetectionHigh))
	fmt.Fprintf(b, "| Hygiene high | %d | %d | %s |\n", before.HygieneHigh, after.HygieneHigh, signedChange(after.HygieneHigh-before.HygieneHigh))
	fmt.Fprintf(b, "| Detection medium | %d | %d | %s |\n", before.DetectionMedium, after.DetectionMedium, signedChange(after.DetectionMedium-before.DetectionMedium))
	fmt.Fprintf(b, "| Hygiene medium | %d | %d | %s |\n", before.HygieneMedium, after.HygieneMedium, signedChange(after.HygieneMedium-before.HygieneMedium))
	fmt.Fprintf(b, "| Static findings | %d | %d | %s |\n", before.Static, after.Static, signedChange(after.Static-before.Static))
	fmt.Fprintf(b, "| Stable findings | %d | %d | %s |\n", before.StableTotal, after.StableTotal, signedChange(after.StableTotal-before.StableTotal))
	fmt.Fprintf(b, "| Total findings | %d | %d | %s |\n", before.Total, after.Total, signedChange(after.Total-before.Total))
	verdictLabel := "Defender verdicts"
	if reportPlatform(cycles) == platformLinux {
		verdictLabel = "Falco verdicts"
	}
	fmt.Fprintf(b, "| %s | %d | %d | %s |\n", verdictLabel, first.Verdicts, last.Verdicts, signedChange(last.Verdicts-first.Verdicts))
	fmt.Fprintf(b, "\nExecuting cycles: %d/%d.", executing, len(cycles))
	if removed, added := deliveredDiff(cycleDelivered(first), cycleDelivered(last)); len(removed) > 0 || len(added) > 0 {
		fmt.Fprintf(b, "\n\n> **Counts are not comparable:** cycle 1 delivered `%s`; cycle %d delivered `%s`",
			strings.Join(cycleDelivered(first), ", "), last.Iteration, strings.Join(cycleDelivered(last), ", "))
		if len(removed) > 0 {
			fmt.Fprintf(b, " (removed `%s`)", strings.Join(removed, ", "))
		}
		if len(added) > 0 {
			fmt.Fprintf(b, " (added `%s`)", strings.Join(added, ", "))
		}
		fmt.Fprintf(b, ". Telemetry findings that vanished with a removed source were not observed, not evaded.\n")
	}
	if last.Execution != executionVerified {
		fmt.Fprintf(b, " The final cycle did not execute, so its counts are not a detection result.")
	}
	var finalSummary cycleSummary
	if json.Unmarshal([]byte(last.Summary), &finalSummary) == nil && len(finalSummary.CoverageMissing) > 0 {
		fmt.Fprintf(b, " The final payload has incomplete coverage: %s; its counts are not a clean result.",
			clipUTF8(sanitizeLine(strings.Join(finalSummary.CoverageMissing, "; ")), 400))
	}
	if note := reportLastCycleNote(cycles, finalIndex); note != "" {
		fmt.Fprintf(b, " %s", note)
	}
	b.WriteString("\n\n")
}

type findingChange struct {
	Finding string
	Final   string
	Change  string
}

// reportFindingKey compares top-finding text across cycles without the
// severity prefix, which can change while the rule and indicator stay the
// same.
func reportFindingKey(text string) string {
	text = strings.ToLower(strings.TrimSpace(text))
	for _, prefix := range []string{"high ", "medium ", "low ", "info "} {
		text = strings.TrimSpace(strings.TrimPrefix(text, prefix))
	}
	return strings.Join(strings.Fields(text), " ")
}

func containsFindingKey(keys []string, key string) bool {
	for _, candidate := range keys {
		if candidate == key {
			return true
		}
	}
	return false
}

func cycleDelivered(cycle Cycle) []string {
	var summary cycleSummary
	if json.Unmarshal([]byte(cycle.Summary), &summary) != nil || summary.Telemetry == nil {
		return nil
	}
	return summary.Telemetry.Coverage.Delivered
}

func deliveredDiff(baseline, current []string) (removed, added []string) {
	before := stringSet(baseline)
	after := stringSet(current)
	for feature := range before {
		if !after[feature] {
			removed = append(removed, feature)
		}
	}
	for feature := range after {
		if !before[feature] {
			added = append(added, feature)
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	return removed, added
}

func telemetryFinding(text string) bool {
	return strings.Contains(text, "telemetry/")
}

func cycleReportEdits(cycles []Cycle, edits []EditRecord, index int) []EditRecord {
	if index < 0 || index >= len(cycles) {
		return nil
	}
	var summary cycleSummary
	if json.Unmarshal([]byte(cycles[index].Summary), &summary) == nil && len(summary.Edits) > 0 {
		return summary.Edits
	}
	var fallback []EditRecord
	for _, edit := range edits {
		if edit.Iteration == cycles[index].Iteration {
			fallback = append(fallback, edit)
		}
	}
	return fallback
}

// reportAttributableFinding reports whether a top-finding line can be tied to
// a source edit. Address-specific dynamic lines and lines without a stable
// rule are observations, not a rule the loop can patch.
func reportAttributableFinding(top string) bool {
	finding, ok := parseMemoryFinding(top)
	return ok && finding.Rule != "" && !memoryVolatileFinding(finding)
}

// reportFindingChanges maps each baseline top finding to its final status and
// the first cycle where it was no longer reported. It deliberately says
// "not in final top findings" rather than "removed": the stored top-finding
// list is capped and the sandbox can vary between runs.
func reportFindingChanges(cycles []Cycle, finalIndex int, edits []EditRecord) ([]findingChange, []string) {
	if len(cycles) == 0 || finalIndex < 0 || finalIndex >= len(cycles) {
		return nil, nil
	}
	type cycleFindings struct {
		keys    []string
		summary cycleSummary
	}
	findings := make([]cycleFindings, len(cycles))
	for i := range cycles {
		var summary cycleSummary
		_ = json.Unmarshal([]byte(cycles[i].Summary), &summary)
		findings[i].summary = summary
		for _, top := range summary.TopFindings {
			if key := reportFindingKey(top); key != "" {
				findings[i].keys = append(findings[i].keys, key)
			}
		}
	}
	finalKeys := findings[finalIndex].keys
	baselineKeys := map[string]bool{}
	var changes []findingChange
	for _, top := range findings[0].summary.TopFindings {
		key := reportFindingKey(top)
		if key == "" || baselineKeys[key] {
			continue
		}
		if !reportAttributableFinding(top) {
			continue
		}
		baselineKeys[key] = true
		change := findingChange{Finding: sanitizeLine(top), Final: "not in final top findings"}
		if containsFindingKey(finalKeys, key) {
			changes = append(changes, findingChange{
				Finding: sanitizeLine(top),
				Final:   "still present",
				Change:  "No removal recorded; the finding is still in the final top findings.",
			})
			continue
		}
		firstAbsent := -1
		for i := 1; i < len(cycles); i++ {
			if cycles[i].Execution != executionVerified {
				continue
			}
			if !containsFindingKey(findings[i].keys, key) {
				firstAbsent = i
				break
			}
		}
		if firstAbsent < 0 || firstAbsent >= len(cycles) {
			change.Change = "No later cycle recorded the finding as absent."
			changes = append(changes, change)
			continue
		}
		cycle := cycles[firstAbsent]
		summary := findings[firstAbsent].summary
		if telemetryFinding(top) {
			if removed, _ := deliveredDiff(cycleDelivered(cycles[0]), cycleDelivered(cycle)); len(removed) > 0 {
				change.Change = fmt.Sprintf("Not attributable: cycle %d was captured without `%s`; the telemetry finding was not observed.",
					cycle.Iteration, strings.Join(removed, ", "))
				changes = append(changes, change)
				continue
			}
		}
		if strings.Contains(key, "pe/entropy") && strings.Contains(strings.ToLower(summary.Note), "overlay") {
			change.Change = fmt.Sprintf("Section entropy is no longer reported because the blob moved to a PE overlay in cycle %d; pe-info does not scan overlays, so this is an analyzer blind spot rather than a reduction in the blob's entropy.",
				cycle.Iteration)
			changes = append(changes, change)
			continue
		}
		parts := []string{fmt.Sprintf("First absent in cycle %d", cycle.Iteration)}
		if mechanism := strings.TrimSpace(summary.Mechanism); mechanism != "" {
			parts = append(parts, "mechanism `"+sanitizeLine(mechanism)+"`")
		}
		if note := strings.TrimSpace(summary.Note); note != "" {
			parts = append(parts, "note: "+sanitizeLine(note))
		}
		cycleEdits := cycleReportEdits(cycles, edits, firstAbsent)
		if len(cycleEdits) == 0 {
			parts = append(parts, "no source edit recorded in that cycle")
		} else {
			for i, edit := range cycleEdits {
				if i >= 2 {
					parts = append(parts, fmt.Sprintf("and %d more edit(s)", len(cycleEdits)-i))
					break
				}
				parts = append(parts, fmt.Sprintf("`%s`: %s", sanitizeLine(editPath(edit)), sanitizeLine(edit.Reason)))
			}
		}
		change.Change = strings.Join(parts, "; ")
		changes = append(changes, change)
	}
	var newFinal []string
	for _, top := range findings[finalIndex].summary.TopFindings {
		key := reportFindingKey(top)
		if key != "" && !baselineKeys[key] {
			newFinal = append(newFinal, sanitizeLine(top))
		}
	}
	return changes, newFinal
}

func markdownCell(text string) string {
	text = sanitizeLine(text)
	text = strings.ReplaceAll(text, "|", "\\|")
	if text == "" {
		return "—"
	}
	return text
}

func renderFindingChangeMap(b *strings.Builder, cycles []Cycle, finalIndex int, edits []EditRecord) {
	fmt.Fprintf(b, "## Finding-to-change map\n\n")
	if len(cycles) == 0 || finalIndex < 0 || finalIndex >= len(cycles) {
		fmt.Fprintf(b, "No cycle completed, so no finding-to-change mapping exists.\n\n")
		return
	}
	changes, newFinal := reportFindingChanges(cycles, finalIndex, edits)
	if len(changes) == 0 {
		if len(newFinal) > 0 {
			fmt.Fprintf(b, "The baseline reported no top finding. The final cycle introduced: %s.\n\n",
				clipUTF8(strings.Join(limitStrings(newFinal, 4), "; "), 500))
		} else {
			fmt.Fprintf(b, "The baseline and final cycles reported no top finding, so no mapping exists.\n\n")
		}
		return
	}
	fmt.Fprintf(b, "| Baseline finding | Final status | First change / evidence |\n")
	fmt.Fprintf(b, "| --- | --- | --- |\n")
	for _, change := range changes {
		fmt.Fprintf(b, "| %s | %s | %s |\n",
			markdownCell(change.Finding), markdownCell(change.Final), markdownCell(change.Change))
	}
	b.WriteString("\n")
	if len(newFinal) > 0 {
		fmt.Fprintf(b, "New top findings in the final cycle (no baseline counterpart): %s.\n\n",
			clipUTF8(strings.Join(limitStrings(newFinal, 4), "; "), 500))
	}
	fmt.Fprintf(b, "> Top findings are capped at eight per cycle. A finding absent from the final top findings is not proof of removal; use the counts above and the saved feedback for the full picture.\n\n")
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
