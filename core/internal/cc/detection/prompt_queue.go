package detection

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// maxOperatorPromptBytes bounds one queued instruction.
const maxOperatorPromptBytes = 4 << 10

// OperatorPromptQueue holds instructions an operator appends while the loop is
// running. The loop drains it at the next model turn or session start, so a
// prompt queued mid-session is not held until the next worker session.
type OperatorPromptQueue struct {
	prompts chan string
	count   atomic.Int64
}

// NewOperatorPromptQueue returns an empty queue.
func NewOperatorPromptQueue() *OperatorPromptQueue {
	return &OperatorPromptQueue{prompts: make(chan string, 1024)}
}

// Add validates and appends one operator instruction. It returns the number of
// instructions waiting.
func (q *OperatorPromptQueue) Add(text string) (int, error) {
	if q == nil {
		return 0, fmt.Errorf("operator prompt queue is disabled")
	}
	text, err := ValidateOperatorPrompt(text)
	if err != nil {
		return 0, err
	}
	if q.prompts == nil {
		return 0, fmt.Errorf("operator prompt queue is not initialized")
	}
	select {
	case q.prompts <- text:
		return int(q.count.Add(1)), nil
	default:
		return 0, fmt.Errorf("operator prompt queue is full")
	}
}

// Len returns the number of waiting instructions.
func (q *OperatorPromptQueue) Len() int {
	if q == nil {
		return 0
	}
	return int(q.count.Load())
}

// Drain returns and clears the waiting instructions.
func (q *OperatorPromptQueue) Drain() []string {
	if q == nil {
		return nil
	}
	var prompts []string
	for {
		select {
		case prompt := <-q.prompts:
			prompts = append(prompts, prompt)
			q.count.Add(-1)
		default:
			return prompts
		}
	}
}

// FormatOperatorPrompts renders drained prompts for the model.
func FormatOperatorPrompts(prompts []string) string {
	prompts = normalizeOperatorPrompts(prompts)
	if len(prompts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Operator instructions (highest priority; follow them in addition to the loop rules):\n")
	for _, prompt := range prompts {
		b.WriteString("- ")
		b.WriteString(prompt)
		b.WriteByte('\n')
	}
	return b.String()
}

func normalizeOperatorPrompts(prompts []string) []string {
	out := make([]string, 0, len(prompts))
	for _, prompt := range prompts {
		prompt = sanitizePrompt(prompt)
		if prompt == "" {
			continue
		}
		out = append(out, prompt)
	}
	return out
}

func sanitizePrompt(text string) string {
	return strings.TrimSpace(sanitize.SanitizeText(text))
}

// ValidateOperatorPrompt rejects empty or oversized operator input before it is
// appended to a queue.
func ValidateOperatorPrompt(text string) (string, error) {
	text = sanitizePrompt(text)
	if text == "" {
		return "", fmt.Errorf("prompt is empty")
	}
	if len(text) > maxOperatorPromptBytes {
		return "", fmt.Errorf("prompt exceeds %d bytes", maxOperatorPromptBytes)
	}
	return text, nil
}
