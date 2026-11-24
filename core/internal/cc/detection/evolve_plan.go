package detection

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	predictionMatched     = "matched"
	predictionNotObserved = "not-observed"
	predictionUnclear     = "unclear"
)

// cyclePreconditions rejects a no-op cycle and a third attempt at a mechanism
// whose last two predictions were not observed.
func (e *evolver) cyclePreconditions(mechanism string) error {
	if e.last == nil {
		return nil
	}
	var last cycleSummary
	if json.Unmarshal([]byte(e.last.Summary), &last) == nil && last.SourceTreeHash != "" {
		lastKey := last.DesignKey
		if lastKey == "" {
			lastKey = designKey(last.SourceTreeHash, last.BuildOptions, last.ProducerOptions, last.Producer, e.cfg.AgentType)
		}
		currentKey := e.designKey()
		if lastKey != "" && currentKey != "" && lastKey == currentKey {
			return fmt.Errorf("no source or design change since cycle %d; edit the module, change a build/producer option, or change the producer/agent before another cycle", e.last.Iteration)
		}
	}
	cycles := e.recentCycles(2)
	if len(cycles) < 2 {
		return nil
	}
	var previous, latest cycleSummary
	if json.Unmarshal([]byte(cycles[len(cycles)-2].Summary), &previous) != nil ||
		json.Unmarshal([]byte(cycles[len(cycles)-1].Summary), &latest) != nil {
		return nil
	}
	if previous.Mechanism != "" && previous.Mechanism == latest.Mechanism &&
		latest.Mechanism == mechanism &&
		previous.PredictionResult == predictionNotObserved &&
		latest.PredictionResult == predictionNotObserved {
		return fmt.Errorf("the last two predictions for mechanism %q were not observed; change the mechanism or the predicted behavior", mechanism)
	}
	return nil
}

func (e *evolver) bindCycleMechanism(requested string) (string, error) {
	requested = clip(strings.TrimSpace(requested), 80)
	planned := clip(strings.TrimSpace(e.plannedMechanism), 80)
	if planned == "" {
		if requested == "" {
			return "other", nil
		}
		return requested, nil
	}
	if requested != "" && !strings.EqualFold(requested, planned) {
		return "", fmt.Errorf("mechanism %q does not match the plan's %q; return to the planner if the hypothesis changed", requested, planned)
	}
	return planned, nil
}

func stageNames(stages []string) []string {
	seen, _ := stageSet(stages)
	var out []string
	for _, name := range []string{"static", "dynamic", "edr"} {
		if seen[name] {
			out = append(out, name)
		}
	}
	return out
}

// observedFindings records the bounded result the prediction is compared
// against. The full feedback remains in SQLite.
func observedFindings(feedback Feedback) string {
	parts := make([]string, 0, len(feedback.Findings)*2)
	for _, finding := range feedback.Findings {
		parts = append(parts, finding.Rule, finding.Indicator)
	}
	return clip(strings.Join(parts, " "), 600)
}

// predictionObservation is the bounded text a prediction is graded against.
// It includes the finding rules and indicators plus the execution outcome, so
// a claim about the agent checking in is testable rather than silently failing
// because findings do not carry execution state.
func predictionObservation(feedback Feedback, execution string, agentOnline *bool) string {
	parts := make([]string, 0, len(feedback.Findings)*2+2)
	for _, finding := range feedback.Findings {
		parts = append(parts, finding.Rule, finding.Indicator)
	}
	if execution != "" {
		parts = append(parts, "execution="+execution)
	}
	if agentOnline != nil {
		parts = append(parts, fmt.Sprintf("agent_online=%t", *agentOnline))
	}
	return clip(strings.ToLower(strings.Join(parts, " ")), 16<<10)
}

type predictionEvidence struct {
	text       string
	ruleCounts map[string]int
}

// evaluatePrediction grades a prediction against the findings alone. Callers
// that also have the execution result should use evaluatePredictionWithExecution.
func evaluatePrediction(prediction string, feedback Feedback) string {
	return evaluatePredictionAgainst(prediction, predictionEvidence{text: predictionObservation(feedback, "", nil)})
}

// evaluatePredictionWithExecution grades a prediction against findings, the
// execution outcome, and the per-rule alert counts for the same cycle.
func evaluatePredictionWithExecution(prediction string, feedback Feedback, execution string, agentOnline *bool) string {
	return evaluatePredictionAgainst(prediction, predictionEvidence{
		text:       predictionObservation(feedback, execution, agentOnline),
		ruleCounts: predictionRuleCounts(feedback),
	})
}

func predictionRuleCounts(feedback Feedback) map[string]int {
	if feedback.Telemetry == nil || feedback.Telemetry.Stats == nil {
		return nil
	}
	counts := feedback.Telemetry.Stats.ByRule
	if len(counts) == 0 {
		return nil
	}
	out := make(map[string]int, len(counts))
	for rule, count := range counts {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}
		out[rule] = count
	}
	return out
}

// evaluatePredictionAgainst grades each independent claim in a prediction.
// A prediction may mix an expected disappearance with an expected persistence;
// treating the whole text as one negative claim made a correct mixed
// prediction fail because a persisted finding matched a keyword shared with
// the removed one.
func evaluatePredictionAgainst(prediction string, evidence predictionEvidence) string {
	prediction = strings.TrimSpace(prediction)
	if prediction == "" {
		return ""
	}
	lower := strings.ToLower(prediction)
	if index := strings.Index(lower, "predict="); index >= 0 {
		prediction = strings.TrimSpace(prediction[index+len("predict="):])
	}
	observed := strings.ToLower(strings.Join(strings.Fields(evidence.text), " "))
	clauses := predictionClauses(prediction)
	if len(clauses) == 0 {
		return predictionUnclear
	}
	matched, failed := 0, 0
	for _, clause := range clauses {
		switch evaluatePredictionClause(clause, observed, evidence.ruleCounts) {
		case predictionMatched:
			matched++
		case predictionNotObserved:
			failed++
		}
	}
	if failed > 0 {
		return predictionNotObserved
	}
	if matched > 0 {
		return predictionMatched
	}
	return predictionUnclear
}

func evaluatePredictionClause(clause, observed string, ruleCounts map[string]int) string {
	claim := predictionClaim(clause)
	subjects := predictionSubjects(claim)
	if len(subjects) == 0 {
		return predictionUnclear
	}
	if limit, ok := predictionLimit(claim); ok && len(ruleCounts) > 0 {
		if result := evaluatePredictionLimit(subjects, limit, ruleCounts); result != "" {
			return result
		}
	}
	found := false
	for _, subject := range subjects {
		if strings.Contains(observed, subject) {
			found = true
			break
		}
	}
	if predictionNegative(claim) {
		if found {
			return predictionNotObserved
		}
		return predictionMatched
	}
	if found {
		return predictionMatched
	}
	return predictionNotObserved
}

// predictionClaim drops the rationale after a claim. "X may still fire because
// Y" is a claim about X; grading Y as part of the same polarity made correct
// predictions fail on a trailing "not a regression".
func predictionClaim(clause string) string {
	lower := strings.ToLower(clause)
	cut := len(clause)
	for _, marker := range []string{" because ", " since ", " which ", " thereby ", " so that "} {
		if index := strings.Index(lower, marker); index >= 0 && index < cut {
			cut = index
		}
	}
	return strings.TrimRight(strings.TrimSpace(clause[:cut]), " ,;:")
}

var predictionLimitPattern = regexp.MustCompile(`(?i)(?:at most|no more than|up to|fewer than|less than|drops? to|reduces? to|decreases? to|from\s+\d+\s+to)\s+(\d+)`)

func predictionLimit(claim string) (int, bool) {
	match := predictionLimitPattern.FindStringSubmatch(claim)
	if len(match) != 2 {
		return 0, false
	}
	limit, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return limit, true
}

// evaluatePredictionLimit grades a reduction claim against the per-rule alert
// counts. A rule the claim names and that still exceeds the bound contradicts
// the prediction; matching rules under the bound satisfy it.
func evaluatePredictionLimit(subjects []string, limit int, ruleCounts map[string]int) string {
	seen := false
	for _, subject := range subjects {
		for rule, count := range ruleCounts {
			if !strings.Contains(rule, subject) {
				continue
			}
			seen = true
			if count > limit {
				return predictionNotObserved
			}
		}
	}
	if seen {
		return predictionMatched
	}
	return ""
}

var predictionContrasts = []string{
	" but ", " however ", " whereas ", " while ", " yet ",
	" although ", " though ", " meanwhile ",
}

// predictionClauses splits a prediction into independent claims. Sentence
// punctuation and contrast conjunctions separate claims; commas do not,
// because they carry subject lists such as "A and B disappear".
func predictionClauses(text string) []string {
	var out []string
	for _, sentence := range predictionSentences(text) {
		out = append(out, predictionContrastClaims(sentence)...)
	}
	return out
}

func predictionSentences(text string) []string {
	var out []string
	start := 0
	for i := range len(text) {
		switch text[i] {
		case '\n':
			if part := strings.TrimSpace(text[start:i]); part != "" {
				out = append(out, part)
			}
			start = i + 1
		case ';':
			if part := strings.TrimSpace(text[start:i]); part != "" {
				out = append(out, part)
			}
			start = i + 1
		case '.', '!', '?':
			if i+1 < len(text) && !predictionSpace(text[i+1]) {
				continue
			}
			if part := strings.TrimSpace(text[start:i]); part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	if part := strings.TrimSpace(text[start:]); part != "" {
		out = append(out, part)
	}
	return out
}

func predictionSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func predictionContrastClaims(text string) []string {
	lower := strings.ToLower(text)
	start := 0
	var out []string
	for {
		best, markerLen := -1, 0
		for _, marker := range predictionContrasts {
			i := strings.Index(lower[start:], marker)
			if i < 0 {
				continue
			}
			i += start
			if best < 0 || i < best {
				best, markerLen = i, len(marker)
			}
		}
		if best < 0 {
			break
		}
		if part := strings.TrimSpace(text[start:best]); part != "" {
			out = append(out, part)
		}
		start = best + markerLen
	}
	if part := strings.TrimSpace(text[start:]); part != "" {
		out = append(out, part)
	}
	return out
}

var predictionNegativeMarkers = []string{
	" no ", " not ", " without ", " avoid ", " remove ", " won't ",
	" never ", " disappear", " absent", " clear ", " clears ",
	" eliminate", " zero ",
}

func predictionNegative(clause string) bool {
	lower := " " + strings.ToLower(strings.Join(strings.Fields(clause), " ")) + " "
	for _, marker := range predictionNegativeMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

var (
	predictionQuoted = regexp.MustCompile(`'[^']{3,80}'|"[^"]{3,80}"`)
	predictionPath   = regexp.MustCompile(`/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+`)
	predictionIdent  = regexp.MustCompile(`[A-Za-z0-9_]+(?:[._/][A-Za-z0-9_]+)+`)
	predictionCamel  = regexp.MustCompile(`\b[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+\b`)
)

// predictionSubjects returns the concrete identifiers in one claim. Generic
// keywords are only used when the claim carries no identifier, path, or quoted
// indicator; otherwise words such as "maps" would match an unrelated alert and
// turn a correct negative claim into a failure.
func predictionSubjects(clause string) []string {
	var raw []string
	seen := map[string]struct{}{}
	add := func(value string) {
		value = normalizePredictionSubject(value)
		if len(value) < 3 {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		raw = append(raw, value)
	}
	for _, match := range predictionQuoted.FindAllString(clause, -1) {
		add(match)
	}
	for _, match := range predictionPath.FindAllString(clause, -1) {
		add(match)
	}
	for _, match := range predictionIdent.FindAllString(clause, -1) {
		add(match)
	}
	for _, match := range predictionCamel.FindAllString(clause, -1) {
		add(match)
	}
	if len(raw) == 0 {
		for _, term := range ftsTerms(clause) {
			if len(term) < 4 || predictionStopwords[term] {
				continue
			}
			add(term)
		}
	}
	// Drop fragments contained in a longer identifier: "PenguinBox" and
	// "ProcMaps" are part of "PenguinBox_ProcMaps", and matching the fragment
	// against an unrelated Falco rule would contradict the claim.
	subjects := make([]string, 0, len(raw))
	for i, value := range raw {
		contained := false
		for j, other := range raw {
			if i == j || value == other {
				continue
			}
			if len(other) > len(value) && strings.Contains(other, value) {
				contained = true
				break
			}
		}
		if !contained {
			subjects = append(subjects, value)
		}
	}
	if len(subjects) > 12 {
		subjects = subjects[:12]
	}
	return subjects
}

func normalizePredictionSubject(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `'"`)
	value = strings.TrimRight(value, ".,;:!?)]}")
	value = strings.Join(strings.Fields(strings.ToLower(value)), " ")
	return value
}

var predictionStopwords = map[string]bool{
	"the": true, "and": true, "with": true, "that": true, "this": true,
	"will": true, "should": true, "from": true, "into": true, "over": true,
	"for": true, "not": true, "without": true, "avoid": true, "remove": true,
	"detect": true, "detected": true, "cycle": true, "payload": true,
	"module": true, "using": true, "use": true, "than": true, "then": true,
	"when": true, "what": true, "where": true, "which": true, "would": true,
	"could": true, "might": true, "expected": true, "predict": true,
}
