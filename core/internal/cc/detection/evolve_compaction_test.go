package detection

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type passthroughCompactor struct{}

func (passthroughCompactor) Pre(_ context.Context, msgs []llm.Message, _ int) []llm.Message {
	return msgs
}

func (passthroughCompactor) Reactive(_ context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	return msgs, false
}

func (passthroughCompactor) IsOverflow(error) bool { return false }

func detectionReadPair(id, body string) []llm.Message {
	return []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: id, Name: "SourceRead"}}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText(id, body, false)}},
	}
}

func TestWorkerCompactorClearsStaleDetectionResults(t *testing.T) {
	body := strings.Repeat("x", 4000)
	msgs := []llm.Message{llm.UserText("start")}
	for i := range 10 {
		msgs = append(msgs, detectionReadPair(fmt.Sprintf("read-%d", i), body)...)
	}
	msgs = append(msgs,
		llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "edit-0", Name: "EditSource"}}},
		llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("edit-0", "edited file", false)}},
	)
	c := &workerCompactor{
		inner:       passthroughCompactor{},
		keep:        3,
		compactable: compactableDetectionTools,
		threshold:   1000,
	}
	out := c.Pre(context.Background(), msgs, 100000)

	got := map[string]string{}
	for _, m := range out {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult {
				got[b.ToolUseID] = b.Content[0].Text
			}
		}
	}
	if len(got) != 11 {
		t.Fatalf("tool results = %d, want 11 (pairing or unchanged count)", len(got))
	}
	for i := range 10 {
		id := fmt.Sprintf("read-%d", i)
		if i < 7 {
			if got[id] != clearedToolResult {
				t.Fatalf("%s = %q, want cleared", id, got[id])
			}
			continue
		}
		if got[id] != body {
			t.Fatalf("%s = %q, want its original body", id, got[id])
		}
	}
	if got["edit-0"] != "edited file" {
		t.Fatalf("mutating tool result = %q, want it preserved", got["edit-0"])
	}
	// The input history is shared with the transcript; clearing must copy.
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && b.ToolUseID == "read-0" && b.Content[0].Text != body {
				t.Fatal("clearStaleToolResults mutated the input history")
			}
		}
	}
}

func TestWorkerCompactorKeepsResultsBelowThreshold(t *testing.T) {
	body := strings.Repeat("x", 4000)
	var msgs []llm.Message
	for i := range 10 {
		msgs = append(msgs, detectionReadPair(fmt.Sprintf("read-%d", i), body)...)
	}
	c := &workerCompactor{
		inner:       passthroughCompactor{},
		keep:        3,
		compactable: compactableDetectionTools,
		threshold:   100000,
	}
	out := c.Pre(context.Background(), msgs, 500)
	for _, m := range out {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && b.Content[0].Text != body {
				t.Fatalf("%s cleared below the micro-compaction threshold", b.ToolUseID)
			}
		}
	}
}

func TestNewWorkerCompactorUsesDetectionTools(t *testing.T) {
	body := strings.Repeat("x", 4000)
	var msgs []llm.Message
	for i := range 10 {
		msgs = append(msgs, detectionReadPair(fmt.Sprintf("read-%d", i), body)...)
	}
	c := newWorkerCompactor(&roleScriptProvider{}, maxWorkerTokens)
	out := c.Pre(context.Background(), msgs, workerContextWindow)
	for i := range 10 {
		id := fmt.Sprintf("read-%d", i)
		want := body
		if i < 5 {
			want = clearedToolResult
		}
		for _, m := range out {
			for _, b := range m.Content {
				if b.Type == llm.BlockToolResult && b.ToolUseID == id && b.Content[0].Text != want {
					t.Fatalf("%s = %q, want %q", id, b.Content[0].Text, want)
				}
			}
		}
	}
}
