package detection

import (
	"encoding/json"
	"fmt"
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
		current := e.computeSourceTreeHash()
		if current != "" && current == last.SourceTreeHash && e.activeShellcode() == last.Shellcode {
			return fmt.Errorf("no source or shellcode change since cycle %d; edit the module or build new shellcode before another cycle", e.last.Iteration)
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

func stageNames(stages []string) []string {
	seen := map[string]bool{}
	for _, stage := range stages {
		seen[strings.ToLower(strings.TrimSpace(stage))] = true
	}
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

// evaluatePrediction is deliberately a coarse keyword comparison. It records
// an explicit result for the model and for the mechanism-repetition guard; the
// structured Observed field remains the authority.
func evaluatePrediction(prediction string, feedback Feedback) string {
	prediction = strings.TrimSpace(prediction)
	if prediction == "" {
		return ""
	}
	lower := strings.ToLower(prediction)
	if index := strings.Index(lower, "predict="); index >= 0 {
		prediction = strings.TrimSpace(prediction[index+len("predict="):])
		lower = strings.ToLower(prediction)
	}
	terms := ftsTerms(prediction)
	meaningful := make([]string, 0, len(terms))
	for _, term := range terms {
		if len(term) < 4 || predictionStopwords[term] {
			continue
		}
		meaningful = append(meaningful, term)
	}
	if len(meaningful) == 0 {
		return predictionUnclear
	}
	observed := strings.ToLower(observedFindings(feedback))
	found := false
	for _, term := range meaningful {
		if strings.Contains(observed, term) {
			found = true
			break
		}
	}
	negative := strings.Contains(lower, "no ") || strings.Contains(lower, "not ") ||
		strings.Contains(lower, "without") || strings.Contains(lower, "avoid") ||
		strings.Contains(lower, "remove") || strings.Contains(lower, "won't") ||
		strings.Contains(lower, "never") || strings.Contains(lower, "disappear") ||
		strings.Contains(lower, "absent") || strings.Contains(lower, "no longer")
	if negative {
		if !found {
			return predictionMatched
		}
		return predictionNotObserved
	}
	if found {
		return predictionMatched
	}
	return predictionNotObserved
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
