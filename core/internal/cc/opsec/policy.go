// Package opsec holds the deterministic action screen used by the MCP server.
// It maps an action's matched capability rules to a per-capability disposition,
// then applies noise and reversibility limits.
package opsec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// Mode is the policy's disposition for one capability.
type Mode string

const (
	// ModeAllow runs the action without a warning.
	ModeAllow Mode = "allow"
	// ModeWarn runs the action and returns the matched rule to the caller.
	ModeWarn Mode = "warn"
	// ModeBlock refuses the action before it reaches the target.
	ModeBlock Mode = "block"
)

// capabilityOrder is the stable list used for defaults, validation, and
// operator-facing policy output.
var capabilityOrder = []string{
	"process-creation",
	"filesystem-artifact",
	"script-execution",
	"clr-loading",
	"lolbin-execution",
	"credential-access",
	"credential-prompt",
	"kerberos-credential",
	"directory-credential-read",
	"injection",
	"persistence",
	"defense-tampering",
	"privilege-change",
	"account-manipulation",
	"adcs-abuse",
	"remote-execution",
	"service-control",
	"noisy-query",
	"data-transfer",
	"destructive",
	"kernel-module-load",
	"container-tools",
	"network-capture",
}

// DefaultCapabilities is the detectability-first baseline. Common in-process
// BOFs run without a warning. Every operational capability that leaves an
// observable footprint runs with a warning, so the caller sees the matched
// rules and can stop before a higher-footprint step. The operator may set any
// capability to block in the policy file.
func DefaultCapabilities() map[string]Mode {
	return map[string]Mode{
		"process-creation":          ModeWarn,
		"filesystem-artifact":       ModeWarn,
		"script-execution":          ModeWarn,
		"clr-loading":               ModeWarn,
		"lolbin-execution":          ModeWarn,
		"credential-access":         ModeWarn,
		"credential-prompt":         ModeWarn,
		"kerberos-credential":       ModeWarn,
		"directory-credential-read": ModeWarn,
		"injection":                 ModeWarn,
		"persistence":               ModeWarn,
		"defense-tampering":         ModeWarn,
		"privilege-change":          ModeWarn,
		"account-manipulation":      ModeWarn,
		"adcs-abuse":                ModeWarn,
		"remote-execution":          ModeWarn,
		"service-control":           ModeWarn,
		"noisy-query":               ModeWarn,
		"data-transfer":             ModeWarn,
		"destructive":               ModeWarn,
		"kernel-module-load":        ModeWarn,
		"container-tools":           ModeWarn,
		"network-capture":           ModeWarn,
	}
}

// Policy is the on-disk screen. Capabilities missing from the map inherit the
// defaults, so a policy file only names the dispositions it changes.
type Policy struct {
	MaxNoise            string          `json:"max_noise"`
	AllowIrreversible   bool            `json:"allow_irreversible"`
	MaxActionsPerMinute int             `json:"max_actions_per_minute"`
	AllowedModules      []string        `json:"allowed_modules"`
	DeniedModules       []string        `json:"denied_modules"`
	Capabilities        map[string]Mode `json:"capabilities"`
}

// DefaultPolicy returns the baseline screen.
func DefaultPolicy() Policy {
	return Policy{
		MaxNoise:            "high",
		MaxActionsPerMinute: 30,
		Capabilities:        DefaultCapabilities(),
	}
}

// LoadPolicy reads path. A missing file yields the defaults; a malformed file
// is an error so the server never starts with an unintended screen.
func LoadPolicy(path string) (Policy, error) {
	policy := DefaultPolicy()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policy, policy.Validate()
		}
		return policy, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return policy, fmt.Errorf("parse %s: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr == nil && isGroupOrWorldWritable(info) {
		return policy, fmt.Errorf("%s is group- or world-writable; chmod 600 it before starting MCP", path)
	}
	if err := policy.Validate(); err != nil {
		return policy, fmt.Errorf("%s: %w", path, err)
	}
	return policy, nil
}

// Validate normalizes the policy and rejects unknown noise bands, unknown
// capability names, invalid dispositions, and a zero rate limit.
func (p *Policy) Validate() error {
	p.MaxNoise = strings.ToLower(strings.TrimSpace(p.MaxNoise))
	if p.MaxNoise == "" {
		p.MaxNoise = "high"
	}
	if BandRank(p.MaxNoise) == 0 {
		return fmt.Errorf("max_noise must be low, medium, or high")
	}
	if p.MaxActionsPerMinute <= 0 {
		p.MaxActionsPerMinute = 30
	}
	if p.MaxActionsPerMinute > 600 {
		return fmt.Errorf("max_actions_per_minute must be at most 600")
	}
	if p.Capabilities == nil {
		p.Capabilities = DefaultCapabilities()
	}
	defaults := DefaultCapabilities()
	known := make(map[string]struct{}, len(capabilityOrder))
	for _, id := range capabilityOrder {
		known[id] = struct{}{}
	}
	for id := range p.Capabilities {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("unknown capability %q", id)
		}
	}
	for id, fallback := range defaults {
		mode, ok := p.Capabilities[id]
		if !ok {
			p.Capabilities[id] = fallback
			continue
		}
		mode = Mode(strings.ToLower(strings.TrimSpace(string(mode))))
		switch mode {
		case ModeAllow, ModeWarn, ModeBlock:
			p.Capabilities[id] = mode
		default:
			return fmt.Errorf("capability %q has invalid mode %q; use allow, warn, or block", id, mode)
		}
	}
	return nil
}

// Decision is the engine's answer for one action. Reason is stable prose, not
// a model-generated explanation. Warnings are matched capabilities that are
// allowed with an explicit caution.
type Decision struct {
	Allowed  bool     `json:"allowed"`
	Warnings []string `json:"warnings,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// BandRank orders low/medium/high. Zero is an absent or unknown band.
func BandRank(band string) int {
	switch strings.ToLower(strings.TrimSpace(band)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}

// Evaluate applies the policy to one review. module may be empty for raw
// commands. The function is pure; rate limiting and auditing are the caller's
// responsibility.
func (p Policy) Evaluate(module string, review def.OpsecReview) Decision {
	if p.MaxNoise == "" && p.MaxActionsPerMinute == 0 && len(p.Capabilities) == 0 {
		p = DefaultPolicy()
	}
	deny := func(reason string) Decision { return Decision{Allowed: false, Reason: reason} }

	if module != "" {
		if containsFold(p.DeniedModules, module) {
			return deny(fmt.Sprintf("module %q is denied by policy", module))
		}
		if len(p.AllowedModules) > 0 && !containsFold(p.AllowedModules, module) {
			return deny(fmt.Sprintf("module %q is not in allowed_modules", module))
		}
	}

	var warnings []string
	for _, rule := range review.Rules {
		mode, reason, known := p.capability(rule)
		if !known {
			return deny(fmt.Sprintf("unknown capability %q; refusing to run it", rule))
		}
		switch mode {
		case ModeBlock:
			return deny(reason)
		case ModeWarn:
			warnings = append(warnings, reason)
		}
	}

	if BandRank(review.Noise) > BandRank(p.MaxNoise) {
		return deny(fmt.Sprintf("noise %s exceeds max_noise %s", review.Noise, p.MaxNoise))
	}
	if !review.Reversible && !p.AllowIrreversible {
		return deny("action is irreversible; set allow_irreversible to permit it")
	}
	warnings = dedupeStrings(warnings)
	if len(warnings) > 0 {
		return Decision{
			Allowed:  true,
			Warnings: warnings,
			Reason:   "allowed with warnings",
		}
	}
	return Decision{Allowed: true, Reason: "all matched capabilities are permitted"}
}

func (p Policy) capability(rule string) (mode Mode, reason string, known bool) {
	id := strings.ToLower(strings.TrimSpace(rule))
	if _, ok := DefaultCapabilities()[id]; !ok {
		return "", "", false
	}
	mode, ok := p.Capabilities[id]
	if !ok || mode == "" {
		mode = DefaultCapabilities()[id]
	}
	reason = capabilityReason(id)
	switch mode {
	case ModeWarn:
		reason = "warning: " + reason
	case ModeBlock:
		reason = "blocked: " + reason
	}
	return mode, reason, true
}

func capabilityReason(id string) string {
	switch id {
	case "process-creation":
		return "starts a child process; process creation and its command line are audited"
	case "filesystem-artifact":
		return "writes a file on the target"
	case "script-execution":
		return "runs a script or script host; script content and command line are logged"
	case "clr-loading":
		return "loads a CLR assembly; .NET runtime and AMSI telemetry"
	case "lolbin-execution":
		return "runs a signed system binary as an execution proxy"
	case "credential-access":
		return "reads or exports host credential material"
	case "credential-prompt":
		return "prompts a user for credentials; the prompt is visible to the user"
	case "kerberos-credential":
		return "reads or abuses Kerberos ticket material"
	case "directory-credential-read":
		return "reads directory-stored credential material"
	case "injection":
		return "writes into or controls another process"
	case "persistence":
		return "installs or modifies persistence"
	case "defense-tampering":
		return "tampers with logging, auditing, or defenses"
	case "privilege-change":
		return "changes privileges or group membership"
	case "account-manipulation":
		return "creates, enables, disables, or modifies an account"
	case "adcs-abuse":
		return "requests or abuses an AD certificate"
	case "remote-execution":
		return "executes on a remote host through a service, WMI, SMB, or WinRM path"
	case "service-control":
		return "starts, stops, or reconfigures a service"
	case "noisy-query":
		return "broad or aggressive enumeration"
	case "data-transfer":
		return "moves data between the operator and the target"
	case "destructive":
		return "destructive or irreversible command class"
	case "kernel-module-load":
		return "loads or removes a kernel module"
	case "container-tools":
		return "uses container or namespace management tools"
	case "network-capture":
		return "captures network traffic on the target"
	default:
		return "matched capability"
	}
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
