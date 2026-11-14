package detection

import "github.com/jm33-m0/emp3r0r/core/lib/sanitize"

// Telemetry names, paths, and stack frames come from the target. Strip
// terminal escapes and binary data before they reach a prompt, report, or
// terminal, while keeping multiline evidence readable.

func sanitizeLine(text string) string {
	return sanitize.SanitizeOneLine(text)
}

func sanitizeMultiline(text string) string {
	return sanitize.SanitizeText(text)
}

func sanitizeStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = sanitizeLine(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func sanitizeCounts(counts map[string]int) map[string]int {
	if counts == nil {
		return nil
	}
	out := make(map[string]int, len(counts))
	for key, value := range counts {
		if key = sanitizeLine(key); key != "" {
			out[key] += value
		}
	}
	return out
}

func sanitizeTelemetryCoverage(coverage TelemetryCoverage) TelemetryCoverage {
	coverage.Delivered = sanitizeStrings(coverage.Delivered)
	coverage.Expected = sanitizeStrings(coverage.Expected)
	coverage.Missing = sanitizeStrings(coverage.Missing)
	if coverage.Analyzers != nil {
		analyzers := make(map[string]string, len(coverage.Analyzers))
		for name, status := range coverage.Analyzers {
			key := sanitizeLine(name)
			if key == "" {
				continue
			}
			analyzers[key] = sanitizeLine(status)
		}
		coverage.Analyzers = analyzers
	}
	coverage.Providers = sanitizeCounts(coverage.Providers)
	coverage.Categories = sanitizeCounts(coverage.Categories)
	coverage.Roles = sanitizeCounts(coverage.Roles)
	coverage.Signals = sanitizeCounts(coverage.Signals)
	return coverage
}

func sanitizeFindingText(finding *Finding) {
	finding.Rule = sanitizeMultiline(finding.Rule)
	finding.Indicator = sanitizeMultiline(finding.Indicator)
	finding.Detail = sanitizeMultiline(finding.Detail)
	for i := range finding.Sources {
		finding.Sources[i].File = sanitizeLine(finding.Sources[i].File)
		finding.Sources[i].Excerpt = sanitizeMultiline(finding.Sources[i].Excerpt)
	}
}

func sanitizePayloadChange(change *PayloadChange) {
	change.Category = sanitizeLine(change.Category)
	change.Event = sanitizeLine(change.Event)
	change.Operation = sanitizeLine(change.Operation)
	change.Path = sanitizeLine(change.Path)
	change.Image = sanitizeLine(change.Image)
	change.TargetImage = sanitizeLine(change.TargetImage)
	change.Proto = sanitizeLine(change.Proto)
	change.SrcAddr = sanitizeLine(change.SrcAddr)
	change.DstAddr = sanitizeLine(change.DstAddr)
}

// SanitizeTelemetryTrace strips terminal escapes from target-derived trace
// fields before the trace is returned outside the detection package. Meta can
// contain arbitrary fields copied from a target-supplied meta event, so it is
// dropped; query traces.meta explicitly if raw metadata is needed.
func SanitizeTelemetryTrace(trace *TelemetryTrace) {
	if trace == nil {
		return
	}
	trace.Source = sanitizeLine(trace.Source)
	trace.PayloadKey = sanitizeLine(trace.PayloadKey)
	trace.PayloadTable = sanitizeLine(trace.PayloadTable)
	trace.PayloadImage = sanitizeLine(trace.PayloadImage)
	trace.Attribution = sanitizeLine(trace.Attribution)
	trace.Coverage = sanitizeTelemetryCoverage(trace.Coverage)
	trace.Meta = nil
}

func sanitizeTelemetryRun(run *TelemetryRun) {
	if run == nil {
		return
	}
	run.Source = sanitizeLine(run.Source)
	run.PayloadKey = sanitizeLine(run.PayloadKey)
	run.PayloadTable = sanitizeLine(run.PayloadTable)
	run.PayloadImage = sanitizeLine(run.PayloadImage)
	run.Attribution = sanitizeLine(run.Attribution)
	run.Coverage = sanitizeTelemetryCoverage(run.Coverage)
	for i := range run.Findings {
		sanitizeFindingText(&run.Findings[i])
	}
	if run.Stats != nil {
		run.Stats.ByCategory = sanitizeCounts(run.Stats.ByCategory)
		run.Stats.ByRule = sanitizeCounts(run.Stats.ByRule)
		run.Stats.BySeverity = sanitizeCounts(run.Stats.BySeverity)
		run.Stats.Coverage = sanitizeTelemetryCoverage(run.Stats.Coverage)
	}
}

// SanitizeFeedback strips terminal escapes and binary data from the
// target-derived strings in one feedback record before it is returned to a
// model or rendered by a terminal.
func SanitizeFeedback(feedback *Feedback) {
	if feedback == nil {
		return
	}
	feedback.RunID = sanitizeLine(feedback.RunID)
	feedback.Module = sanitizeLine(feedback.Module)
	feedback.ModuleDir = sanitizeLine(feedback.ModuleDir)
	feedback.Artifact.Path = sanitizeLine(feedback.Artifact.Path)
	feedback.Artifact.Name = sanitizeLine(feedback.Artifact.Name)
	feedback.Artifact.Kind = sanitizeLine(feedback.Artifact.Kind)
	feedback.Artifact.SHA256 = sanitizeLine(feedback.Artifact.SHA256)
	feedback.Level = sanitizeLine(feedback.Level)
	feedback.RiskFactors = sanitizeStrings(feedback.RiskFactors)
	feedback.Notes = sanitizeStrings(feedback.Notes)
	for i := range feedback.Findings {
		sanitizeFindingText(&feedback.Findings[i])
	}
	for i := range feedback.SourceEdits {
		feedback.SourceEdits[i].File = sanitizeLine(feedback.SourceEdits[i].File)
		feedback.SourceEdits[i].Excerpt = sanitizeMultiline(feedback.SourceEdits[i].Excerpt)
		feedback.SourceEdits[i].Reason = sanitizeLine(feedback.SourceEdits[i].Reason)
		feedback.SourceEdits[i].Action = sanitizeLine(feedback.SourceEdits[i].Action)
	}
	for i := range feedback.Pending {
		feedback.Pending[i].Kind = StageKind(sanitizeLine(string(feedback.Pending[i].Kind)))
		feedback.Pending[i].Tool = sanitizeLine(feedback.Pending[i].Tool)
		feedback.Pending[i].Status = sanitizeLine(feedback.Pending[i].Status)
		feedback.Pending[i].Reason = sanitizeMultiline(feedback.Pending[i].Reason)
	}
	sanitizeTelemetryRun(feedback.Telemetry)
}

// SanitizeRisk strips terminal escapes from a sandbox risk assessment before
// its factors are returned to a model.
func SanitizeRisk(risk *Risk) {
	if risk == nil {
		return
	}
	risk.Level = sanitizeLine(risk.Level)
	risk.Factors = sanitizeStrings(risk.Factors)
}
