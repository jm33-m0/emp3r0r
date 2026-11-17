package detection

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	maxCycleKnowledgeHits   = 6
	maxFindingKnowledgeHits = 2
)

// attachKnowledge adds the small, deduplicated reference hits that explain the
// cycle's new high/medium findings. The cycle row keeps the refs so a later
// attempt does not spend a turn rediscovering the same document.
func (e *evolver) attachKnowledge(ctx context.Context, summary *cycleSummary, feedback Feedback) {
	if e.knowledge == nil || summary == nil {
		return
	}
	e.knowledgeSeenOnce.Do(func() {
		for _, cycle := range e.recentCycles(0) {
			var prior cycleSummary
			if json.Unmarshal([]byte(cycle.Summary), &prior) != nil {
				continue
			}
			for _, top := range prior.TopFindings {
				fields := strings.SplitN(top, " ", 3)
				if len(fields) != 3 {
					continue
				}
				e.knowledgeSeen.Store(knowledgeFindingKey(fields[1], fields[2]), struct{}{})
			}
		}
	})
	seenURL := map[string]struct{}{}
	for _, finding := range feedback.Findings {
		if finding.Severity != "high" && finding.Severity != "medium" {
			continue
		}
		if finding.Signal == "noise" || finding.Signal == "baseline" || strings.TrimSpace(finding.Indicator) == "" {
			continue
		}
		key := knowledgeFindingKey(finding.Rule, finding.Indicator)
		if _, ok := e.knowledgeSeen.Load(key); ok {
			continue
		}
		e.knowledgeSeen.Store(key, struct{}{})
		query := strings.TrimSpace(finding.Rule + " " + finding.Indicator)
		hits, err := e.knowledge.Search(ctx, query, "", maxFindingKnowledgeHits+1)
		if err != nil {
			e.logClass(logging.ClassWarning, "knowledge search for %q: %v", finding.Indicator, err)
			continue
		}
		added := 0
		for _, hit := range hits {
			if hit.DocRef == "" {
				continue
			}
			urlKey := knowledgeURLKey(hit.URL)
			if urlKey == "" {
				urlKey = hit.DocRef
			}
			if _, ok := seenURL[urlKey]; ok {
				continue
			}
			seenURL[urlKey] = struct{}{}
			summary.Knowledge = append(summary.Knowledge, hit)
			summary.KBRefs = append(summary.KBRefs, "kb="+hit.DocRef)
			added++
			if added >= maxFindingKnowledgeHits {
				break
			}
		}
		if len(summary.Knowledge) >= maxCycleKnowledgeHits {
			break
		}
	}
}

func knowledgeFindingKey(rule, indicator string) string {
	return strings.ToLower(strings.TrimSpace(rule)) + "|" + strings.ToLower(strings.TrimSpace(indicator))
}
