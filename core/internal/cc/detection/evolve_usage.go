package detection

import (
	"fmt"
	"sync/atomic"

	"github.com/Autumn-27/norma/llm"
)

// TokenPricing is the operator's price sheet in USD per million tokens. Zero
// rates mean the provider bills that class outside this calculation; the report
// still shows the token counts and marks the cost as unconfigured.
type TokenPricing struct {
	InputPerMillion      float64 `json:"input_per_million"`
	OutputPerMillion     float64 `json:"output_per_million"`
	CacheReadPerMillion  float64 `json:"cache_read_per_million"`
	CacheWritePerMillion float64 `json:"cache_write_per_million"`
}

// Configured reports whether any rate was supplied. Rates are independent:
// setting input and output leaves cache tokens at zero cost.
func (p TokenPricing) Configured() bool {
	return p.InputPerMillion > 0 || p.OutputPerMillion > 0 ||
		p.CacheReadPerMillion > 0 || p.CacheWritePerMillion > 0
}

// Cost returns the estimated USD cost of one usage record.
func (p TokenPricing) Cost(usage TokenUsage) float64 {
	return float64(usage.Input)*p.InputPerMillion/1e6 +
		float64(usage.Output)*p.OutputPerMillion/1e6 +
		float64(usage.CacheRead)*p.CacheReadPerMillion/1e6 +
		float64(usage.CacheWrite)*p.CacheWritePerMillion/1e6
}

// RoleUsage is one worker role's share of the loop's model usage.
type RoleUsage struct {
	Role       string  `json:"role"`
	Input      int64   `json:"input_tokens"`
	Output     int64   `json:"output_tokens"`
	CacheRead  int64   `json:"cache_read_tokens,omitempty"`
	CacheWrite int64   `json:"cache_write_tokens,omitempty"`
	CostUSD    float64 `json:"cost_usd,omitempty"`
}

// TokenUsage is the loop's cumulative model usage, including the per-role
// split used to show where the budget went.
type TokenUsage struct {
	Input             int64       `json:"input_tokens"`
	Output            int64       `json:"output_tokens"`
	CacheRead         int64       `json:"cache_read_tokens,omitempty"`
	CacheWrite        int64       `json:"cache_write_tokens,omitempty"`
	CostUSD           float64     `json:"cost_usd"`
	PricingConfigured bool        `json:"pricing_configured"`
	Roles             []RoleUsage `json:"roles,omitempty"`
}

// Total returns input, output, and cache tokens as one count. It is useful for
// a compact progress line; cost still uses the separate classes.
func (u TokenUsage) Total() int64 {
	return u.Input + u.Output + u.CacheRead + u.CacheWrite
}

// tokenCounter holds an immutable-on-read token total. Worker results are
// recorded from the coordinator loop while the progress heartbeat reads them.
type tokenCounter struct {
	input      atomic.Int64
	output     atomic.Int64
	cacheRead  atomic.Int64
	cacheWrite atomic.Int64
}

func (c *tokenCounter) add(usage llm.Usage) {
	if usage.InputTokens > 0 {
		c.input.Add(int64(usage.InputTokens))
	}
	if usage.OutputTokens > 0 {
		c.output.Add(int64(usage.OutputTokens))
	}
	if usage.CacheReadTokens > 0 {
		c.cacheRead.Add(int64(usage.CacheReadTokens))
	}
	if usage.CacheWriteTokens > 0 {
		c.cacheWrite.Add(int64(usage.CacheWriteTokens))
	}
}

func (c *tokenCounter) snapshot() TokenUsage {
	return TokenUsage{
		Input: c.input.Load(), Output: c.output.Load(),
		CacheRead: c.cacheRead.Load(), CacheWrite: c.cacheWrite.Load(),
	}
}

// usageTracker keeps the total and per-role counters used by the heartbeat,
// the final answer, and the report.
type usageTracker struct {
	total    tokenCounter
	planner  tokenCounter
	editor   tokenCounter
	debugger tokenCounter
}

func (t *usageTracker) add(role evolveRole, usage llm.Usage) {
	t.total.add(usage)
	switch role {
	case rolePlanner:
		t.planner.add(usage)
	case roleEditor:
		t.editor.add(usage)
	case roleDebugger:
		t.debugger.add(usage)
	}
}

func (t *usageTracker) snapshot(pricing TokenPricing) TokenUsage {
	out := t.total.snapshot()
	out.PricingConfigured = pricing.Configured()
	out.CostUSD = pricing.Cost(out)
	for _, entry := range []struct {
		role    evolveRole
		counter *tokenCounter
	}{
		{rolePlanner, &t.planner},
		{roleEditor, &t.editor},
		{roleDebugger, &t.debugger},
	} {
		counts := entry.counter.snapshot()
		out.Roles = append(out.Roles, RoleUsage{
			Role: string(entry.role), Input: counts.Input, Output: counts.Output,
			CacheRead: counts.CacheRead, CacheWrite: counts.CacheWrite,
			CostUSD: pricing.Cost(counts),
		})
	}
	return out
}

// formatTokenCount abbreviates token counts for the progress line and report.
func formatTokenCount(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.2fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.2fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// formatUSD keeps sub-cent estimates readable without hiding the amount.
func formatUSD(value float64) string {
	if value >= 1 {
		return fmt.Sprintf("$%.2f", value)
	}
	return fmt.Sprintf("$%.4f", value)
}

// costLabel renders the cost or explains why it is missing.
func costLabel(usage TokenUsage) string {
	if !usage.PricingConfigured {
		return "unconfigured"
	}
	return formatUSD(usage.CostUSD)
}
