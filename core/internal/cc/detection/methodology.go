package detection

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// methodologyEntry is one scenario playbook in the local methodology KB. It is
// versioned with the harness, so the model can search for what to do in a
// situation instead of relying on a long system prompt.
type methodologyEntry struct {
	ID           string
	Title        string
	Tags         []string
	Scenario     string
	Steps        []string
	Constraints  []string
	Verification string
}

var methodologyEntries = []methodologyEntry{
	{
		ID:       "offline-after-baseline",
		Title:    "An offline cycle after a verified baseline",
		Tags:     []string{"offline", "baseline", "execution", "verification", "agent"},
		Scenario: "The baseline checked in, but a later cycle did not. The cycle is not a detection result until execution is restored.",
		Steps: []string{
			"Check whether the baseline and the cycle had the same sandbox instrumentation (coverage.delivered and providers).",
			"If the coverage changed, stop editing source: stabilize the sandbox or use the debugger.",
			"Classify the failure layer from the trace: loader-start, payload-mapping, agent-network, or agent-checkin.",
			"Fix the layer that failed, not the layer that produced the last finding.",
			"Revert the previous edit if it did not execute; do not stack another hypothesis on an unverified change.",
		},
		Constraints: []string{
			"Do not compare findings from an offline cycle with a verified cycle.",
			"A loader that exits before calling the payload is a loader bug, not a producer bug.",
			"Do not edit the producer to fix a loader-side exit.",
		},
		Verification: "the expected agent UUID checks in and the execution gate reports verified",
	},
	{
		ID:       "instrumentation-changed",
		Title:    "Sandbox instrumentation changed since the baseline",
		Tags:     []string{"instrumentation", "coverage", "rededr", "hook", "kernel", "etwti", "baseline"},
		Scenario: "The current trace delivered different providers or hook injection than the baseline. The execution result is not attributable to the source edit.",
		Steps: []string{
			"Compare the baseline and current coverage: delivered features and provider names.",
			"Run the known-good baseline artifact and the candidate artifact under the same instrumentation, and measure the same signal (first TCP connection or check-in).",
			"If the baseline also fails under the instrumentation, treat it as a sandbox issue, not a payload defect.",
			"Stabilize the instrumentation or record the guest change; then run a fresh baseline.",
		},
		Constraints: []string{
			"A candidate that works only when instrumentation is absent proves an interaction, not that the baseline is safe.",
			"Do not attribute an offline cycle to source without a controlled baseline-vs-candidate test.",
		},
		Verification: "baseline and candidate behave the same under identical instrumentation, or the instrumentation is restored",
	},
	{
		ID:       "sandbox-rededr-hook-deadlock",
		Title:    "RedEdrDll injection deadlocks a self-loading payload",
		Tags:     []string{"sandbox", "instrumentation", "rededr", "hook", "loadlibrary", "deadlock", "loader-lock"},
		Scenario: "The payload starts and maps its PICO, but stalls when the PICO calls LoadLibraryA. RedEdr loaded RedEdrDll into the process and its DllMain calls OutputDebugStringA while the loader lock is held.",
		Steps: []string{
			"Compare coverage.delivered with the verified baseline; hook or kernel appearing after the baseline means the guest changed.",
			"Read the guest RedEdr log: dll_injection=1 with the target name confirms hook injection; a baseline line 'Target filename too long' means the long artifact name prevented kernel/hook on the baseline only.",
			"Reproduce outside LitterBox: run the same artifact manually and confirm it reaches the C2. If it checks in, the packer and loader are intact.",
			"Disable --hook in the LitterBox RedEdr command, restart LitterBox, and rerun. Remove --kernel too when the baseline did not deliver it.",
			"Confirm loaded_dlls has no RedEdrDll.dll and total_api_hooks=0 before treating the cycle as valid.",
		},
		Constraints: []string{
			"Do not edit loader or producer source for a guest instrumentation deadlock.",
			"A hook-stalled process is not a detection result; its telemetry describes RedEdrDll, not the payload.",
			"Baseline and candidate must use identical instrumentation; a long artifact name can silently disable kernel/hook for one side.",
		},
		Verification: "RedEdr loads without RedEdrDll.dll, the expected UUID checks in, and baseline and candidate have equal coverage",
	},
	{
		ID:       "agent-not-checking-in",
		Title:    "The payload executes but the agent does not check in",
		Tags:     []string{"agent", "checkin", "c2", "network", "preflight", "uuid", "tofu", "config"},
		Scenario: "The process and mapping exist, but the expected UUID never checks in or the C2 sees no connection.",
		Steps: []string{
			"Confirm the process is alive and whether it has a TCP connection to the configured C2.",
			"Test the C2 address, port, DNS, and TLS from inside the guest; do not test the operator host's loopback.",
			"Check preflight and operator presence: a closed preflight rejects check-in before the payload's network stage.",
			"Check the agent identity: expected UUID, signature, TOFU pin, and config magic must match this build.",
			"Run a fresh agent artifact manually in the guest to separate payload execution from the sandbox launch path.",
		},
		Constraints: []string{
			"A manual relaunch is remediation evidence, not a clean detection baseline.",
			"An agent that checked in once is pinned: a second process with the same UUID and a new key is rejected.",
			"A live AgentStatus is the health signal. Do not require a BOF result: LitterBox terminates the beacon at the capture boundary, so the BOF may never run.",
		},
		Verification: "the expected UUID checks in and AgentStatus reports it online",
	},
	{
		ID:       "packed-payload-entropy",
		Title:    "High entropy on a packed or encrypted payload",
		Tags:     []string{"entropy", "rdata", "static", "packing", "encryption", "yara", "stringnalyzer"},
		Scenario: "A static analyzer reports high entropy on a large section that holds an encrypted or compressed payload.",
		Steps: []string{
			"Identify the container and the transformation: encrypted blob, compressed blob, or embedded shellcode.",
			"Decide whether the finding is a residual (expected for a packed payload) or part of the planned mechanism.",
			"Change the container or encoding in the component that embeds the blob; do not edit an unrelated producer.",
			"If encoding, account for size and entropy: base64 is about 6 bits/byte and grows 33%; hex is about 4 bits/byte and doubles size.",
			"Compress before encrypting if size matters; encrypted-compressed data is still high entropy.",
		},
		Constraints: []string{
			"Do not add literals, strings, or code to chase an entropy finding; a new static high is a regression.",
			"Static hygiene does not change the loading path and cannot fix dynamic execution.",
		},
		Verification: "the targeted static finding disappears without a new high finding or an execution regression",
	},
	{
		ID:       "static-high-regression",
		Title:    "An edit added a new high static finding",
		Tags:     []string{"high", "regression", "static", "entropy", "strings", "score"},
		Scenario: "The cycle's high findings grew compared with the baseline, or a new high string/section appeared.",
		Steps: []string{
			"Compare the high top-findings with the baseline, not just the total count.",
			"Revert the edit that introduced the new high before testing another hypothesis.",
			"Do not report a worse static surface as progress.",
		},
		Constraints: []string{
			"An offline cycle's findings are not comparable for detection, but a new static high is still a regression.",
		},
		Verification: "the new high is gone and the baseline high set is unchanged",
	},
	{
		ID:       "producer-agent-compatibility",
		Title:    "Choosing the agent type for a shellcode producer",
		Tags:     []string{"producer", "agent", "dll", "exe", "shellcode", "build"},
		Scenario: "A producer wraps an agent artifact; the agent type must match the producer's declared input.",
		Steps: []string{
			"Read the producer's config.json and find its input parameter.",
			"If the input is a DLL, GenerateAgent must use agent_type=windows_dll.",
			"If the input is a PE, choose the compatible agent type and keep it for the BuildShellcode call.",
			"Build the producer artifact, inspect its type and size, then run the cycle.",
		},
		Constraints: []string{
			"A source edit of the active producer is mechanism=producer; switching producer is mechanism=producer-swap.",
			"Neither producer nor agent can fix a loader that never reaches the payload.",
		},
		Verification: "the producer's artifact is active and the expected agent checks in",
	},
	{
		ID:       "build-failure",
		Title:    "A module build fails",
		Tags:     []string{"build", "compile", "link", "toolchain", "compiler", "nasm", "java"},
		Scenario: "The build log ends with a compiler, linker, or missing-tool error, and no new artifact exists.",
		Steps: []string{
			"Read the build log tail; fix the named compiler, linker, or tool, not an unrelated source file.",
			"Do not change the module contract or delete required resources to silence a build error.",
			"Rebuild and confirm the expected artifact path exists before calling DetectionCycle.",
		},
		Constraints: []string{
			"A build failure is not a detection result and does not consume a cycle.",
		},
		Verification: "the build reports a generated payload at the expected path",
	},
	{
		ID:       "no-comparable-baseline",
		Title:    "No comparable verified baseline",
		Tags:     []string{"baseline", "verified", "restore", "comparison"},
		Scenario: "The last verified execution is absent, stale, or was restored incompletely.",
		Steps: []string{
			"Restore the last verified source and shellcode before another hypothesis.",
			"If the restore is incomplete, say so and fix execution before comparing findings.",
			"Do not use an offline or recovered_by=guest-debugger cycle as a detection baseline.",
		},
		Constraints: []string{
			"Finding counts are comparable only between verified cycles.",
		},
		Verification: "a verified baseline exists and its source/shellcode are the active ones",
	},
}

func methodologyEntriesAll() []methodologyEntry {
	entries := append([]methodologyEntry{}, methodologyEntries...)
	for _, name := range mechanismNames() {
		spec := mechanismSpecs[name]
		entries = append(entries, methodologyEntry{
			ID:           "mechanism-" + spec.Name,
			Title:        "Mechanism: " + spec.Name,
			Tags:         []string{"mechanism", spec.Name, spec.Layer},
			Scenario:     spec.Summary,
			Steps:        spec.Signals,
			Constraints:  spec.Constraints,
			Verification: spec.Verification,
		})
	}
	return entries
}

func methodologyTerms(query string) []string {
	return strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	})
}

// methodologySearch ranks local scenario playbooks against a query. It runs
// without the external knowledge DB, so the harness always has methodology.
func methodologySearch(query string, limit int) []KnowledgeHit {
	terms := methodologyTerms(query)
	if len(terms) == 0 {
		return nil
	}
	type scored struct {
		entry methodologyEntry
		score int
	}
	var candidates []scored
	for _, entry := range methodologyEntriesAll() {
		text := strings.ToLower(strings.Join([]string{
			entry.ID, entry.Title, strings.Join(entry.Tags, " "), entry.Scenario,
			strings.Join(entry.Steps, " "), strings.Join(entry.Constraints, " "),
		}, " "))
		score := 0
		for _, term := range terms {
			if strings.Contains(text, term) {
				score++
			}
		}
		if score > 0 {
			candidates = append(candidates, scored{entry: entry, score: score})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].entry.ID < candidates[j].entry.ID
	})
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	hits := make([]KnowledgeHit, 0, limit)
	for _, candidate := range candidates[:limit] {
		hits = append(hits, KnowledgeHit{
			DocRef:   "methodology/" + candidate.entry.ID,
			Notebook: "methodology",
			Title:    candidate.entry.Title,
			Snippet:  candidate.entry.Scenario,
			Score:    float64(candidate.score),
		})
	}
	return hits
}

// methodologyDoc renders one local entry for KnowledgeRead.
func methodologyDoc(ref string) (KnowledgeDoc, bool) {
	id := strings.TrimPrefix(strings.TrimSpace(ref), "methodology/")
	for _, entry := range methodologyEntriesAll() {
		if entry.ID != id {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# %s\n\n%s\n", entry.Title, entry.Scenario)
		if len(entry.Steps) > 0 {
			b.WriteString("\n## Steps\n")
			for _, step := range entry.Steps {
				fmt.Fprintf(&b, "- %s\n", step)
			}
		}
		if len(entry.Constraints) > 0 {
			b.WriteString("\n## Constraints\n")
			for _, constraint := range entry.Constraints {
				fmt.Fprintf(&b, "- %s\n", constraint)
			}
		}
		if entry.Verification != "" {
			fmt.Fprintf(&b, "\n## Verification\n%s\n", entry.Verification)
		}
		return KnowledgeDoc{
			DocRef:   ref,
			Notebook: "methodology",
			Title:    entry.Title,
			Artifact: "content",
			Content:  b.String(),
		}, true
	}
	return KnowledgeDoc{}, false
}

// searchKnowledge merges the local methodology entries with the external
// reference cache. Methodology is always available; the external cache is
// optional. Results are deduplicated by document reference.
func (e *evolver) searchKnowledge(ctx context.Context, query, notebook string, limit int) []KnowledgeHit {
	if limit <= 0 || limit > maxKnowledgeHits {
		limit = 10
	}
	notebook = strings.ToLower(strings.TrimSpace(notebook))
	var hits []KnowledgeHit
	if notebook == "" || notebook == "methodology" {
		hits = methodologySearch(query, limit)
	}
	if e.knowledge != nil && notebook != "methodology" {
		external, err := e.knowledge.Search(ctx, query, notebook, limit)
		if err == nil {
			hits = append(hits, external...)
		}
	}
	seen := make(map[string]bool, len(hits))
	merged := hits[:0]
	for _, hit := range hits {
		if hit.DocRef == "" || seen[hit.DocRef] {
			continue
		}
		seen[hit.DocRef] = true
		merged = append(merged, hit)
		if len(merged) == limit {
			break
		}
	}
	return merged
}
