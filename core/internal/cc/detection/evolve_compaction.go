package detection

import (
	"context"

	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

const (
	// workerContextWindow is the context window assumed for worker sessions.
	// It mirrors the summarizer reservation below and is the only place the
	// loop declares the window, so a model change updates both.
	workerContextWindow = 200000
	// workerKeepRecent is the number of recent messages AutoCompact preserves.
	workerKeepRecent = 8
	// workerMicroKeep is the number of recent compactable tool results kept
	// before older ones are cleared. A cleared result can be read again.
	workerMicroKeep = 5
	// clearedToolResult replaces a stale tool result body.
	clearedToolResult = "[Old tool result content cleared]"
)

// compactableDetectionTools lists the detection loop's read-only tools whose
// results can be cleared and produced again. Norma's built-in MicroCompact
// only knows Claude Code tool names (Read, Bash, Grep, ...), so without this
// list no detection result is ever cleared and the session grows until the
// provider rejects it.
var compactableDetectionTools = map[string]bool{
	"SourceTree":      true,
	"SourceList":      true,
	"SourceRead":      true,
	"SourceSearch":    true,
	"TelemetryQuery":  true,
	"InspectFeedback": true,
	"Payloads":        true,
	"ComparePayloads": true,
	"KnowledgeSearch": true,
	"KnowledgeRead":   true,
	"KnowledgeStats":  true,
	"KnowledgeList":   true,
	"GitHistory":      true,
	"GuestSSH":        true,
	"AgentStatus":     true,
}

// workerCompactor applies MicroCompact to detection tool names, then delegates
// boundary summaries to Norma's AutoCompact. Mutating tool results (edits,
// builds, cycle reports) are never cleared.
type workerCompactor struct {
	inner       harness.Compactor
	keep        int
	compactable map[string]bool
	threshold   int
}

// newWorkerCompactor builds the compactor for one worker session. AutoCompact
// still uses the worker model to summarize, so a cleared tool result does not
// remove the conversation's decisions.
func newWorkerCompactor(provider llm.Provider, maxOutputTokens int) *workerCompactor {
	cfg := compaction.Config{
		ContextWindow:   workerContextWindow,
		MaxOutputTokens: maxOutputTokens,
		KeepRecent:      workerKeepRecent,
	}
	inner := compaction.New(cfg, compaction.ProviderSummarizer(provider, maxOutputTokens, false))
	reserve := maxOutputTokens
	if reserve > compactionSummaryReserve || reserve == 0 {
		reserve = compactionSummaryReserve
	}
	return &workerCompactor{
		inner:       inner,
		keep:        workerMicroKeep,
		compactable: compactableDetectionTools,
		threshold:   (workerContextWindow - reserve) * 6 / 10,
	}
}

// compactionSummaryReserve is the output space AutoCompact reserves before it
// decides the window is full (Norma caps the reservation at 20000).
const compactionSummaryReserve = 20000

// Pre clears stale detection tool results once the request reaches the same
// 60% working-window mark Norma uses for MicroCompact, then runs AutoCompact.
func (c *workerCompactor) Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message {
	tok := lastInputTokens
	if tok <= 0 {
		tok = compaction.EstimateTokens(llm.MessagesForAPI(msgs)) * 4 / 3
	}
	if tok > c.threshold {
		if out, changed := clearStaleToolResults(msgs, c.compactable, c.keep); changed {
			// The cleared bodies invalidate lastInputTokens; let AutoCompact
			// estimate the new working set instead of trusting the stale count.
			return c.inner.Pre(ctx, out, 0)
		}
	}
	return c.inner.Pre(ctx, msgs, lastInputTokens)
}

func (c *workerCompactor) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	return c.inner.Reactive(ctx, msgs)
}

func (c *workerCompactor) IsOverflow(err error) bool { return c.inner.IsOverflow(err) }

// clearStaleToolResults replaces the bodies of all compactable tool results
// except the most recent keep, preserving every tool_use/tool_result pair. It
// never mutates the input slice or its messages.
func clearStaleToolResults(msgs []llm.Message, compactable map[string]bool, keep int) ([]llm.Message, bool) {
	if keep < 0 {
		keep = 0
	}
	var ids []string
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolUse && compactable[b.Name] {
				ids = append(ids, b.ID)
			}
		}
	}
	if len(ids) <= keep {
		return msgs, false
	}
	clear := make(map[string]bool, len(ids)-keep)
	for _, id := range ids[:len(ids)-keep] {
		clear[id] = true
	}
	out := append([]llm.Message(nil), msgs...)
	changed := false
	for i := range out {
		var content []llm.ContentBlock
		for j, b := range out[i].Content {
			if b.Type != llm.BlockToolResult || !clear[b.ToolUseID] || isClearedToolResult(b.Content) {
				continue
			}
			if content == nil {
				content = append([]llm.ContentBlock(nil), out[i].Content...)
			}
			content[j].Content = []llm.ContentBlock{llm.TextBlock(clearedToolResult)}
			changed = true
		}
		if content != nil {
			out[i].Content = content
		}
	}
	if !changed {
		return msgs, false
	}
	return out, true
}

func isClearedToolResult(content []llm.ContentBlock) bool {
	return len(content) == 1 && content[0].Type == llm.BlockText && content[0].Text == clearedToolResult
}
