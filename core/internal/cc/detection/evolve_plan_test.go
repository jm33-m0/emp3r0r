package detection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEvolveStagesAcceptsEDR(t *testing.T) {
	static, dynamic, edr, err := parseEvolveStages([]string{"static", "dynamic", "edr"})
	if err != nil {
		t.Fatal(err)
	}
	if !static || !dynamic || !edr {
		t.Fatalf("static=%v dynamic=%v edr=%v", static, dynamic, edr)
	}
	if _, _, _, err := parseEvolveStages([]string{"http"}); err == nil {
		t.Fatal("unknown stage was accepted")
	}
}

func TestCyclePreconditionsRejectsNoOp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loader.c"), []byte("int main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{roots: newSingleRoot(dir), shellcode: "agent.bin"}
	e.sourceTreeHash = e.computeSourceTreeHash()
	summary, _ := json.Marshal(cycleSummary{SourceTreeHash: e.sourceTreeHash, Shellcode: e.shellcode})
	e.last = &Cycle{Iteration: 1, Summary: string(summary)}
	err := e.cyclePreconditions("self-load")
	if err == nil || !strings.Contains(err.Error(), "no source or design change") {
		t.Fatalf("error = %v, want no-op rejection", err)
	}
}

func TestCyclePreconditionsRejectsShellcodeOnlyChange(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loader.c"), []byte("int main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{roots: newSingleRoot(dir), shellcode: "new-agent.bin"}
	e.sourceTreeHash = e.computeSourceTreeHash()
	summary, _ := json.Marshal(cycleSummary{SourceTreeHash: e.sourceTreeHash, Shellcode: "old-agent.bin"})
	e.last = &Cycle{Iteration: 1, Summary: string(summary)}
	err := e.cyclePreconditions("self-load")
	if err == nil || !strings.Contains(err.Error(), "no source or design change") {
		t.Fatalf("error = %v, want shellcode-only rotation rejected", err)
	}
}

func TestBindCycleMechanismUsesPlan(t *testing.T) {
	e := &evolver{plannedMechanism: "build-flags"}
	if _, err := e.bindCycleMechanism("other"); err == nil {
		t.Fatal("editor relabeled the planned mechanism")
	}
	got, err := e.bindCycleMechanism("BUILD-FLAGS")
	if err != nil || got != "build-flags" {
		t.Fatalf("bound mechanism = %q, err = %v", got, err)
	}
	got, err = e.bindCycleMechanism("")
	if err != nil || got != "build-flags" {
		t.Fatalf("empty mechanism = %q, err = %v", got, err)
	}
	e.plannedMechanism = ""
	got, err = e.bindCycleMechanism("")
	if err != nil || got != "other" {
		t.Fatalf("unplanned empty mechanism = %q, err = %v", got, err)
	}
}

func TestCyclePreconditionsAcceptsBuildOptionChange(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loader.c"), []byte("int main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{roots: newSingleRoot(dir), shellcode: "agent.bin"}
	e.sourceTreeHash = e.computeSourceTreeHash()
	summary, _ := json.Marshal(cycleSummary{
		SourceTreeHash: e.sourceTreeHash,
		Shellcode:      e.shellcode,
		BuildOptions:   map[string]string{"format": "exe"},
	})
	e.last = &Cycle{Iteration: 1, Summary: string(summary)}
	e.buildOpts.Store("format", "service")
	if err := e.cyclePreconditions("build-flags"); err != nil {
		t.Fatalf("build option change rejected: %v", err)
	}
	e.replaceBuildOptions(map[string]string{"format": "exe"})
	if err := e.cyclePreconditions("build-flags"); err == nil {
		t.Fatal("identical build options were accepted as a change")
	}
}

func TestCyclePreconditionsBlocksRepeatedMissedPrediction(t *testing.T) {
	summary := func(mechanism string) string {
		encoded, _ := json.Marshal(cycleSummary{
			Mechanism: mechanism, PredictionResult: predictionNotObserved,
		})
		return string(encoded)
	}
	e := &evolver{}
	e.cycles = []Cycle{
		{LoopID: "loop", Iteration: 1, Summary: summary("self-load")},
		{LoopID: "loop", Iteration: 2, Summary: summary("self-load")},
	}
	e.last = &e.cycles[1]
	err := e.cyclePreconditions("self-load")
	if err == nil || !strings.Contains(err.Error(), "last two predictions") {
		t.Fatalf("error = %v, want repeated-miss rejection", err)
	}
	if err := e.cyclePreconditions("module-stomp"); err != nil {
		t.Fatalf("different mechanism rejected: %v", err)
	}
}

func TestEvaluatePredictionMixedClaims(t *testing.T) {
	feedback := Feedback{Findings: []Finding{
		{Rule: "telemetry/namespace", Indicator: "Change thread namespace", Severity: "high"},
		{Rule: "falco/PenguinBox custom proc maps read", Indicator: "PenguinBox custom proc maps read", Severity: "medium"},
		{Rule: "falco/PenguinBox proc maps read", Indicator: "PenguinBox proc maps read", Severity: "medium"},
		{Rule: "elf/no-build-id", Indicator: "elf/no-build-id", Severity: "low"},
	}}
	prediction := "The high static findings elf/string indicator=/proc/self/maps and PenguinBox_ProcMaps (YARA $a) disappear from the static stage, so analyzer/static/elf and analyzer/static/yara no longer report high findings. " +
		"Dynamic Falco 'PenguinBox proc maps read' and 'PenguinBox custom proc maps read' medium alerts persist because the payload still opens the real /proc/self/maps. " +
		"Execution stays verified (agent checks in)."
	online := true
	if got := evaluatePredictionWithExecution(prediction, feedback, executionVerified, &online); got != predictionMatched {
		t.Fatalf("mixed prediction = %q, want matched", got)
	}
}

func TestEvaluatePredictionIgnoresRationaleNegation(t *testing.T) {
	feedback := Feedback{Findings: []Finding{
		{Rule: "falco/PenguinBox proc maps read", Indicator: "PenguinBox proc maps read", Severity: "medium"},
		{Rule: "falco/PenguinBox custom proc maps read", Indicator: "PenguinBox custom proc maps read", Severity: "medium"},
		{Rule: "elf/no-build-id", Indicator: "elf/no-build-id", Severity: "low"},
		{Rule: "elf/stripped", Indicator: "elf/stripped", Severity: "low"},
	}}
	prediction := "The rebuilt stager ELF and embedded malasada PIC contain no '/proc/self/maps' literal, so YARA PenguinBox_ProcMaps and elf/string no longer match and the analyzer/static/yara and analyzer/static/elf high aggregates drop to zero; execution stays verified with the agent online. " +
		"Dynamic Falco 'proc maps read' may still fire because the real path is opened at runtime (literal-only removal), which is expected and not a regression."
	online := true
	if got := evaluatePredictionWithExecution(prediction, feedback, executionVerified, &online); got != predictionMatched {
		t.Fatalf("prediction with a rationale negation = %q, want matched", got)
	}
}

func TestEvaluatePredictionRuleCountLimit(t *testing.T) {
	prediction := "The Falco 'PenguinBox proc maps read' and 'PenguinBox custom proc maps read' alerts drop from 7 raw alerts per rule to at most 2, with execution still verified."
	text := "falco/PenguinBox proc maps read PenguinBox proc maps read falco/PenguinBox custom proc maps read PenguinBox custom proc maps read execution=verified"
	below := predictionEvidence{text: text, ruleCounts: map[string]int{
		"falco/penguinbox proc maps read":        2,
		"falco/penguinbox custom proc maps read": 2,
	}}
	if got := evaluatePredictionAgainst(prediction, below); got != predictionMatched {
		t.Fatalf("rule count at the bound = %q, want matched", got)
	}
	above := predictionEvidence{text: text, ruleCounts: map[string]int{
		"falco/penguinbox proc maps read":        3,
		"falco/penguinbox custom proc maps read": 2,
	}}
	if got := evaluatePredictionAgainst(prediction, above); got != predictionNotObserved {
		t.Fatalf("rule count above the bound = %q, want not-observed", got)
	}
}

func TestEvaluatePredictionMixedClaimsFailsWhenTheRemovedClaimRemains(t *testing.T) {
	feedback := Feedback{Findings: []Finding{
		{Rule: "elf/string", Indicator: "/proc/self/maps", Severity: "high"},
		{Rule: "falco/PenguinBox proc maps read", Indicator: "PenguinBox proc maps read", Severity: "medium"},
	}}
	prediction := "The high static findings elf/string and PenguinBox_ProcMaps disappear. " +
		"The Falco proc maps read alerts persist."
	if got := evaluatePrediction(prediction, feedback); got != predictionNotObserved {
		t.Fatalf("mixed prediction with a surviving claim = %q, want not-observed", got)
	}
}

func TestEvaluatePrediction(t *testing.T) {
	feedback := Feedback{Findings: []Finding{{
		Rule: "telemetry/child-process", Indicator: "CreateProcessW", Severity: "medium",
	}}}
	if got := evaluatePrediction("CreateProcessW telemetry appears", feedback); got != predictionMatched {
		t.Fatalf("positive prediction = %q", got)
	}
	if got := evaluatePrediction("CreateProcessW should disappear", feedback); got != predictionNotObserved {
		t.Fatalf("failed negative prediction = %q", got)
	}
	if got := evaluatePrediction("no CreateProcessW telemetry", feedback); got != predictionNotObserved {
		t.Fatalf("negative prediction that still occurs = %q", got)
	}
	if got := evaluatePrediction("AMSI event", feedback); got != predictionNotObserved {
		t.Fatalf("missing prediction = %q", got)
	}
	if got := evaluatePrediction("", feedback); got != "" {
		t.Fatalf("empty prediction = %q", got)
	}
}
