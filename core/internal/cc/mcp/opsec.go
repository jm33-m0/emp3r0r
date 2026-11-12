package mcp

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/opsec"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// maxBand orders low/medium/high for noise. An empty band is lower than any
// known band, so a rule can raise a review's noise without inventing a value.
func maxBand(a, b string) string {
	if opsec.BandRank(a) >= opsec.BandRank(b) {
		if opsec.BandRank(a) == 0 {
			return strings.ToLower(strings.TrimSpace(b))
		}
		return strings.ToLower(strings.TrimSpace(a))
	}
	return strings.ToLower(strings.TrimSpace(b))
}

// opsecRule is one deterministic detectability capability. Source names the
// telemetry or detection rule the capability is grounded in, so a review can
// be checked against the EDR/audit pipeline that would see it.
type opsecRule struct {
	id        string
	platform  string // "", "any", "windows", or "linux"
	source    string
	noise     string
	reason    string
	artifacts []string
	patterns  []string
	// contextPatterns match only a module's name, comment, and help. They are
	// for high-confidence descriptions such as "dump a process to a file";
	// generic prose is not a capability.
	contextPatterns []string
	// tokens and contextTokens match only as whole words.
	tokens        []string
	contextTokens []string
	// irreversible marks capabilities that change target state. Reading a
	// credential or listing tickets is not irreversible.
	irreversible bool
}

// Rules are deliberately narrow substring matches. A missing match is not a
// safety claim; reviewers see the unknowns beside the verdict.
//
// The rule set is detectability-first. Each rule ID is also a policy
// capability. Sources are documented telemetry: Sysmon event IDs, Windows
// Security events, auditd syscalls, Sysmon for Linux, Falco rules, and
// Sigma/Elastic rule families.
var opsecRules = defaultOpsecRules()

// ReviewModule scores a validated module invocation. flags are the normalized
// values; rendered is the exact console command.
func ReviewModule(mod *def.ModuleConfig, flags map[string]string, rendered string, target *def.Emp3r0rAgent) def.OpsecReview {
	if mod != nil && mod.IsLocal {
		// A local module builds on the C2 and never touches the target.
		return def.OpsecReview{
			Noise:      "low",
			Reversible: true,
			Reasons:    []string{"local C2 module; no target execution"},
			Artifacts:  []string{"local build artifact"},
			Unknowns:   contextUnknowns(target),
		}
	}
	review := def.OpsecReview{Reversible: true}
	var reasons []string
	var unknowns []string

	if mod != nil && mod.Opsec != nil {
		p := mod.Opsec
		if noise := strings.ToLower(strings.TrimSpace(p.Noise)); noise != "" {
			if opsec.BandRank(noise) == 0 {
				unknowns = append(unknowns, "module opsec noise is not low, medium, or high")
			} else {
				review.Noise = noise
			}
		}
		if p.RequiresAdmin {
			review.Requires = append(review.Requires, "admin")
		}
		if p.WritesDisk {
			review.Artifacts = append(review.Artifacts, "file write (Sysmon 11)")
			review.Rules = append(review.Rules, "filesystem-artifact")
		}
		if p.TouchesCredentials {
			review.Rules = append(review.Rules, "credential-access")
			reasons = append(reasons, "module metadata marks credential access")
		}
		for _, egress := range p.NetworkEgress {
			if e := strings.TrimSpace(egress); e != "" {
				review.Artifacts = append(review.Artifacts, "network egress: "+e)
			}
		}
		review.Artifacts = append(review.Artifacts, p.Artifacts...)
		if p.Reversible != nil {
			review.Reversible = *p.Reversible
		}
		if notes := strings.TrimSpace(p.Notes); notes != "" {
			reasons = append(reasons, notes)
		}
	} else if mod != nil {
		unknowns = append(unknowns, "module has no opsec metadata; capabilities are matched from its description")
	} else {
		unknowns = append(unknowns, "no module context")
	}

	if mod != nil && mod.Opsec != nil && mod.Opsec.RequiresAdmin && target != nil && !target.HasRoot {
		reasons = append(reasons, fmt.Sprintf("module requires admin, target %s is not elevated", target.User))
		review.Requires = append(review.Requires, "admin")
	}

	commandHaystack := rendered
	for _, v := range flags {
		commandHaystack += " " + v
	}
	contextHaystack := ""
	if mod != nil {
		contextHaystack = mod.Name + " " + mod.Comment + " " + mod.Help
	}
	platform := ""
	if target != nil {
		platform = platformOf(target.GOOS)
	} else if mod != nil {
		platform = platformOf(mod.Platform)
	}
	if platform == "" {
		unknowns = append(unknowns, "target platform unknown; Windows and Linux rules were both considered")
	}
	for _, m := range matchRules(commandHaystack, contextHaystack, platform) {
		if m.rule.noise != "" {
			review.Noise = maxBand(review.Noise, m.rule.noise)
		}
		reasons = append(reasons, m.rule.reason)
		review.Artifacts = append(review.Artifacts, m.rule.artifacts...)
		review.Rules = append(review.Rules, m.rule.id)
		if m.rule.irreversible {
			review.Reversible = false
		}
	}
	if review.Noise == "" {
		review.Noise = moduleNoise(mod)
	}
	review.Reasons = dedupe(reasons)
	review.Artifacts = dedupe(review.Artifacts)
	review.Rules = dedupe(review.Rules)
	review.Unknowns = dedupe(append(unknowns, contextUnknowns(target)...))
	return review
}

// ReviewBuiltin scores a built-in agent command. It runs inside the agent
// process, so it has no process-creation footprint. Rules still apply: a
// built-in that writes a file or performs a broad query is gated.
func ReviewBuiltin(command string, target *def.Emp3r0rAgent) def.OpsecReview {
	review := def.OpsecReview{
		Noise:      "low",
		Reversible: true,
		Reasons:    []string{"built-in agent command; no child process"},
		Artifacts:  []string{"target query"},
		Unknowns:   contextUnknowns(target),
	}
	return scoreCommand(command, review, platformOf(targetGOOS(target)))
}

func scoreCommand(command string, review def.OpsecReview, platform string) def.OpsecReview {
	if platform == "" {
		review.Unknowns = append(review.Unknowns, "target platform unknown; Windows and Linux rules were both considered")
	}
	for _, m := range matchRules(command, "", platform) {
		if m.rule.noise != "" {
			review.Noise = maxBand(review.Noise, m.rule.noise)
		}
		review.Reasons = append(review.Reasons, m.rule.reason)
		review.Artifacts = append(review.Artifacts, m.rule.artifacts...)
		review.Rules = append(review.Rules, m.rule.id)
		if m.rule.irreversible {
			review.Reversible = false
		}
	}
	review.Reasons = dedupe(review.Reasons)
	review.Artifacts = dedupe(review.Artifacts)
	review.Rules = dedupe(review.Rules)
	review.Unknowns = dedupe(review.Unknowns)
	return review
}

func targetGOOS(target *def.Emp3r0rAgent) string {
	if target == nil {
		return ""
	}
	return target.GOOS
}

func platformOf(goos string) string {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return ""
	}
}

// moduleNoise estimates detection noise from how the module runs. A COFF/BOF
// executes in-process and leaves no child process; other payload types have a
// loader or interpreter artifact.
func moduleNoise(mod *def.ModuleConfig) string {
	if mod == nil {
		return "medium"
	}
	switch strings.ToLower(strings.TrimSpace(mod.AgentConfig.Type)) {
	case "coff":
		return "low"
	default:
		return "medium"
	}
}

type ruleMatch struct {
	rule opsecRule
}

func matchRules(command, context, platform string) []ruleMatch {
	command = strings.ToLower(command)
	context = strings.ToLower(context)
	var out []ruleMatch
	for _, rule := range opsecRules {
		if !ruleApplies(rule, platform) {
			continue
		}
		matched := matchesAny(command, rule.patterns, rule.tokens)
		if !matched && context != "" {
			matched = matchesAny(context, rule.contextPatterns, rule.contextTokens)
		}
		if !matched && rule.id == "filesystem-artifact" && hasFileRedirection(command) {
			matched = true
		}
		if matched {
			out = append(out, ruleMatch{rule: rule})
		}
	}
	return out
}

func matchesAny(haystack string, patterns, tokens []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(haystack, pattern) {
			return true
		}
	}
	for _, token := range tokens {
		if containsToken(haystack, token) {
			return true
		}
	}
	return false
}

func ruleApplies(rule opsecRule, platform string) bool {
	switch rule.platform {
	case "", "any":
		return true
	}
	if platform == "" {
		// Unknown target: show both platform-specific rule sets. The review
		// records that the platform was unknown.
		return true
	}
	return rule.platform == platform
}

// hasFileRedirection reports whether a shell command redirects stdout or
// stderr to a real path. Device sinks and file-descriptor duplication do not
// create a filesystem artifact.
func hasFileRedirection(haystack string) bool {
	for i := 0; i < len(haystack); i++ {
		if haystack[i] != '>' {
			continue
		}
		j := i + 1
		for j < len(haystack) && haystack[j] == '>' {
			j++
		}
		for j < len(haystack) && (haystack[j] == ' ' || haystack[j] == '\t') {
			j++
		}
		if j >= len(haystack) {
			return false
		}
		if haystack[j] == '&' {
			i = j
			continue
		}
		end := j
		for end < len(haystack) && !strings.ContainsRune(" \t;|&", rune(haystack[end])) {
			end++
		}
		target := strings.Trim(haystack[j:end], `"'`)
		switch target {
		case "", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty":
			i = end
			continue
		}
		return true
	}
	return false
}

// containsToken reports whether token appears as a whole word. Letters,
// digits, and underscores are word bytes, so klist matches "klist" and
// "klist.exe" but not "blacklist".
func containsToken(haystack, token string) bool {
	if token == "" {
		return false
	}
	for start := 0; ; {
		index := strings.Index(haystack[start:], token)
		if index < 0 {
			return false
		}
		index += start
		end := index + len(token)
		beforeOK := index == 0 || !isWordByte(haystack[index-1])
		afterOK := end == len(haystack) || !isWordByte(haystack[end])
		if beforeOK && afterOK {
			return true
		}
		start = index + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func contextUnknowns(target *def.Emp3r0rAgent) []string {
	if target == nil {
		return []string{"no target context"}
	}
	return nil
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
