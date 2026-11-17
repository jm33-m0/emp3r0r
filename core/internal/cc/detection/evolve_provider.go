package detection

import (
	"context"
	"iter"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// emptyResponseRetries is the number of times a completed response with no
// text, thinking, or tool call is re-requested. The Responses wire format has
// no empty-response retry of its own, and an empty assistant turn otherwise
// looks like a deliberate stop to the agent loop.
const emptyResponseRetries = 2

// resilientProvider re-issues a model request when the upstream completes
// without producing any content event. It buffers the non-content preamble so
// a retry does not emit a duplicate message start.
type resilientProvider struct {
	next llm.Provider
	logf func(logging.Class, string, ...any)
}

func (p *resilientProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for attempt := 0; ; attempt++ {
			var pending []llm.StreamEvent
			emitted := false
			for event, err := range p.next.Stream(ctx, req) {
				if err != nil {
					if !flushEvents(yield, pending) {
						return
					}
					yield(llm.StreamEvent{}, err)
					return
				}
				if contentEvent(event) {
					if !emitted {
						if !flushEvents(yield, pending) {
							return
						}
						emitted = true
					}
					if !yield(event, nil) {
						return
					}
					continue
				}
				if emitted {
					if !yield(event, nil) {
						return
					}
					continue
				}
				pending = append(pending, event)
			}
			if emitted {
				return
			}
			if attempt >= emptyResponseRetries {
				flushEvents(yield, pending)
				return
			}
			if p.logf != nil {
				p.logf(logging.ClassWarning, "model returned an empty response; retrying (%d/%d)", attempt+1, emptyResponseRetries)
			}
			select {
			case <-ctx.Done():
				flushEvents(yield, pending)
				return
			case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
			}
		}
	}
}

func (p *resilientProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.next.Complete(ctx, req)
}

// contentEvent reports whether an event is part of an actual assistant turn.
// A thinking-only response counts: the model did work, so retrying would
// duplicate it; the worker's Stop hook handles a missing answer.
func contentEvent(event llm.StreamEvent) bool {
	switch event.Type {
	case llm.SETextDelta, llm.SEThinkingDelta, llm.SEThinkingSignature,
		llm.SEToolUseStart, llm.SEToolInputJSON, llm.SEToolUseSignature:
		return true
	}
	return false
}

func flushEvents(yield func(llm.StreamEvent, error) bool, events []llm.StreamEvent) bool {
	for _, event := range events {
		if !yield(event, nil) {
			return false
		}
	}
	return true
}
