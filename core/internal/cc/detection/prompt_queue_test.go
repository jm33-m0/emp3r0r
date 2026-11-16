package detection

import (
	"strings"
	"testing"
)

func TestOperatorPromptQueueDrainsInOrder(t *testing.T) {
	queue := NewOperatorPromptQueue()
	if n, err := queue.Add("first instruction"); err != nil || n != 1 {
		t.Fatalf("add = %d err=%v", n, err)
	}
	if n, err := queue.Add("second instruction"); err != nil || n != 2 {
		t.Fatalf("add = %d err=%v", n, err)
	}
	if queue.Len() != 2 {
		t.Fatalf("len = %d", queue.Len())
	}
	prompts := queue.Drain()
	if len(prompts) != 2 || prompts[0] != "first instruction" || prompts[1] != "second instruction" {
		t.Fatalf("prompts = %#v", prompts)
	}
	if queue.Len() != 0 || queue.Drain() != nil {
		t.Fatalf("queue not empty after drain: len=%d", queue.Len())
	}
}

func TestOperatorPromptValidationAndFormatting(t *testing.T) {
	if _, err := ValidateOperatorPrompt("   "); err == nil {
		t.Fatal("empty prompt was accepted")
	}
	if _, err := ValidateOperatorPrompt(strings.Repeat("x", maxOperatorPromptBytes+1)); err == nil {
		t.Fatal("oversized prompt was accepted")
	}
	clean, err := ValidateOperatorPrompt("  focus on module overloading  ")
	if err != nil || clean != "focus on module overloading" {
		t.Fatalf("clean = %q err=%v", clean, err)
	}
	block := FormatOperatorPrompts([]string{"focus on module overloading", "  "})
	if !strings.Contains(block, "highest priority") || !strings.Contains(block, "focus on module overloading") {
		t.Fatalf("block = %q", block)
	}
}
