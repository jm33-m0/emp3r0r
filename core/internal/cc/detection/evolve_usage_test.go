package detection

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func TestUsageTrackerSnapshot(t *testing.T) {
	var tracker usageTracker
	tracker.add(rolePlanner, llm.Usage{InputTokens: 1_000_000, OutputTokens: 100_000, CacheReadTokens: 200_000, CacheWriteTokens: 50_000})
	tracker.add(roleEditor, llm.Usage{InputTokens: 2_000_000, OutputTokens: 200_000})
	tracker.add(roleDebugger, llm.Usage{InputTokens: 500_000, OutputTokens: 50_000})
	pricing := TokenPricing{
		InputPerMillion: 3, OutputPerMillion: 15,
		CacheReadPerMillion: 0.3, CacheWritePerMillion: 3.75,
	}
	usage := tracker.snapshot(pricing)
	if usage.Input != 3_500_000 || usage.Output != 350_000 {
		t.Fatalf("totals = %d/%d, want 3500000/350000", usage.Input, usage.Output)
	}
	if usage.CacheRead != 200_000 || usage.CacheWrite != 50_000 {
		t.Fatalf("cache totals = %d/%d", usage.CacheRead, usage.CacheWrite)
	}
	want := 3*3.5 + 15*0.35 + 0.3*0.2 + 3.75*0.05
	if diff := usage.CostUSD - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("cost = %f, want %f", usage.CostUSD, want)
	}
	if !usage.PricingConfigured || len(usage.Roles) != 3 {
		t.Fatalf("configured=%v roles=%d", usage.PricingConfigured, len(usage.Roles))
	}
	if usage.Roles[0].Role != "planner" || usage.Roles[0].Input != 1_000_000 {
		t.Fatalf("planner role = %+v", usage.Roles[0])
	}
}

func TestUsageReportAndCost(t *testing.T) {
	pricing := TokenPricing{InputPerMillion: 3, OutputPerMillion: 15}
	usage := TokenUsage{
		Input: 20_990_000, Output: 1_860_000, PricingConfigured: true,
	}
	usage.CostUSD = pricing.Cost(usage)
	usage.Roles = []RoleUsage{
		{Role: "planner", Input: 1_970_000, Output: 330_000, CostUSD: pricing.Cost(TokenUsage{Input: 1_970_000, Output: 330_000})},
		{Role: "editor", Input: 11_240_000, Output: 1_030_000, CostUSD: pricing.Cost(TokenUsage{Input: 11_240_000, Output: 1_030_000})},
	}
	answer := map[string]any{"loop_id": "loop-test", "summary": "removed findings", "token_usage": usage}
	cycles := []Cycle{
		testReportCycle(1, 2, 3, 40, executionVerified, 1),
		testReportCycle(2, 0, 0, 30, executionVerified, 0),
	}
	report := RenderLoopReport(answer, cycles, nil)
	for _, want := range []string{
		"## Findings objective", "| High findings | 2 | 0 | -2 |",
		"| Static findings | 3 | 0 | -3 |", "## Model usage", "| planner |", "$10.86",
		"No static YARA/CheckPlz",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "| Score |") || strings.Contains(report, "**Score:**") {
		t.Fatalf("report still headlines the sandbox score:\n%s", report)
	}
	summary := RenderLoopSummary(answer, cycles, nil)
	for _, want := range []string{"| High findings | 2 | 0 | -2 |", "| Static findings | 3 | 0 | -3 |", "| Tokens | 20.99M in / 1.86M out |", "| Estimated cost | $90.87 |"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
}

func TestUsageReportWithoutPricing(t *testing.T) {
	answer := map[string]any{
		"loop_id": "loop-test", "summary": "done",
		"token_usage": TokenUsage{Input: 1000, Output: 200, Roles: []RoleUsage{{Role: "planner", Input: 1000, Output: 200}}},
	}
	report := RenderLoopReport(answer, []Cycle{testReportCycle(1, 0, 0, 1, executionVerified, 0)}, nil)
	for _, want := range []string{"Cost rates were not configured", "| planner | 1.0k | 200 | 0 | 0 | — |"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	if !strings.Contains(RenderLoopSummary(answer, []Cycle{testReportCycle(1, 0, 0, 1, executionVerified, 0)}, nil), "| Estimated cost | unconfigured |") {
		t.Fatal("summary does not mark the cost unconfigured")
	}
}

func testReportCycle(iteration, high, static, total int, execution string, verdicts int) Cycle {
	summary, _ := json.Marshal(cycleSummary{
		Execution: execution, HighFindings: high, StaticFindings: static,
	})
	return Cycle{
		Iteration: iteration, PayloadKey: "sha256:abcdef0123456789",
		Findings: total, Verdicts: verdicts, Execution: execution, Summary: string(summary),
	}
}

func TestProgressSummaryIncludesCost(t *testing.T) {
	e := &evolver{started: time.Now()}
	e.cfg.Iterations = 3
	e.cfg.Pricing = TokenPricing{InputPerMillion: 3, OutputPerMillion: 15}
	e.usage.add(roleEditor, llm.Usage{InputTokens: 1_000_000, OutputTokens: 100_000, CacheReadTokens: 10_000, CacheWriteTokens: 2_000})
	line := e.progressSummary()
	for _, want := range []string{
		"in=1000000", "out=100000", "cache_read=10000", "cache_write=2000",
		"cost=$4.50", "cycles=0/3",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line missing %q: %s", want, line)
		}
	}
	e.cfg.Pricing = TokenPricing{}
	if !strings.Contains(e.progressSummary(), "cost=unconfigured") {
		t.Fatalf("unpriced progress line: %s", e.progressSummary())
	}
}
