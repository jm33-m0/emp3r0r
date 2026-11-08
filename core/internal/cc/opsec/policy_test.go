package opsec

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func testReview(rules []string, noise string, reversible bool) def.OpsecReview {
	return def.OpsecReview{Rules: rules, Noise: noise, Reversible: reversible}
}

func TestDefaultPolicyWarnsForModerateActions(t *testing.T) {
	p := DefaultPolicy()
	for _, rule := range []string{
		"kerberos-credential", "noisy-query", "privilege-change",
		"account-manipulation", "adcs-abuse", "data-transfer",
		"clr-loading", "container-tools", "credential-prompt",
		"service-control", "directory-credential-read",
	} {
		got := p.Evaluate("", testReview([]string{rule}, "low", true))
		if !got.Allowed {
			t.Errorf("%s blocked by default: %+v", rule, got)
		}
		if len(got.Warnings) == 0 {
			t.Errorf("%s allowed without a warning: %+v", rule, got)
		}
	}
}

func TestDefaultPolicyWarnsForSevereActions(t *testing.T) {
	p := DefaultPolicy()
	for _, rule := range []string{
		"process-creation", "filesystem-artifact", "script-execution",
		"lolbin-execution", "credential-access",
		"injection", "persistence", "defense-tampering", "remote-execution",
		"destructive", "kernel-module-load", "network-capture",
	} {
		got := p.Evaluate("", testReview([]string{rule}, "low", true))
		if !got.Allowed {
			t.Errorf("%s blocked by default: %+v", rule, got)
		}
		if len(got.Warnings) == 0 {
			t.Errorf("%s allowed without a warning: %+v", rule, got)
		}
	}
}

func TestCapabilityModes(t *testing.T) {
	p := DefaultPolicy()
	p.Capabilities["process-creation"] = ModeAllow
	p.Capabilities["credential-access"] = ModeWarn
	if got := p.Evaluate("", testReview([]string{"process-creation"}, "low", true)); !got.Allowed || len(got.Warnings) != 0 {
		t.Fatalf("allowed process creation: %+v", got)
	}
	if got := p.Evaluate("", testReview([]string{"credential-access"}, "low", true)); !got.Allowed || len(got.Warnings) == 0 {
		t.Fatalf("warned credential access: %+v", got)
	}
	p.Capabilities["noisy-query"] = ModeBlock
	if got := p.Evaluate("", testReview([]string{"noisy-query"}, "low", true)); got.Allowed {
		t.Fatalf("blocked noisy query: %+v", got)
	}
}

func TestUnknownCapabilityFailsClosed(t *testing.T) {
	p := DefaultPolicy()
	if got := p.Evaluate("", testReview([]string{"not-a-capability"}, "low", true)); got.Allowed {
		t.Fatalf("unknown capability allowed: %+v", got)
	}
}

func TestNoiseAndReversibility(t *testing.T) {
	p := DefaultPolicy()
	p.MaxNoise = "low"
	if got := p.Evaluate("", testReview(nil, "high", true)); got.Allowed {
		t.Fatalf("noisy action allowed above max_noise: %+v", got)
	}
	p.MaxNoise = "high"
	if got := p.Evaluate("", testReview(nil, "high", true)); !got.Allowed {
		t.Fatalf("noisy action denied after max_noise=high: %+v", got)
	}
	if got := p.Evaluate("", testReview(nil, "low", false)); got.Allowed {
		t.Fatalf("irreversible action allowed: %+v", got)
	}
	p.AllowIrreversible = true
	if got := p.Evaluate("", testReview(nil, "low", false)); !got.Allowed {
		t.Fatalf("irreversible action denied after allow_irreversible: %+v", got)
	}
}

func TestPolicyModuleLists(t *testing.T) {
	p := DefaultPolicy()
	p.DeniedModules = []string{"cred_dump"}
	if got := p.Evaluate("CRED_DUMP", testReview(nil, "low", true)); got.Allowed {
		t.Fatalf("denied module allowed: %+v", got)
	}
	p = DefaultPolicy()
	p.AllowedModules = []string{"sa_whoami"}
	if got := p.Evaluate("sa_ps", testReview(nil, "low", true)); got.Allowed {
		t.Fatalf("module outside allow list allowed: %+v", got)
	}
	if got := p.Evaluate("sa_whoami", testReview(nil, "low", true)); !got.Allowed {
		t.Fatalf("allowed module blocked: %+v", got)
	}
}

func TestLoadPolicyMergesCapabilityDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(`{"max_noise":"medium","capabilities":{"process-creation":"allow"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxNoise != "medium" || p.Capabilities["process-creation"] != ModeAllow {
		t.Fatalf("policy = %+v", p)
	}
	if p.Capabilities["credential-access"] != ModeWarn {
		t.Fatalf("missing capability did not inherit the default: %+v", p.Capabilities)
	}
	if p.MaxActionsPerMinute != 30 {
		t.Fatalf("missing rate limit did not inherit the default: %d", p.MaxActionsPerMinute)
	}
}

func TestLoadPolicyNullCapabilitiesUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(`{"capabilities":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Capabilities) != len(DefaultCapabilities()) {
		t.Fatalf("capabilities = %+v", p.Capabilities)
	}
	if p.MaxNoise != "high" {
		t.Fatalf("max_noise = %q", p.MaxNoise)
	}
}

func TestLoadPolicyRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	for _, body := range []string{
		`{"max_noise":"impossible"}`,
		`{"capabilities":{"process-creation":"maybe"}}`,
		`{"capabilities":{"not-a-capability":"allow"}}`,
		`{"max_actions_per_minute":601}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil {
			t.Fatalf("expected %s to be rejected", body)
		}
	}
	if runtime.GOOS != "windows" {
		permPath := filepath.Join(dir, "writable.json")
		if err := os.WriteFile(permPath, []byte(`{"max_noise":"high"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(permPath, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(permPath); err == nil {
			t.Fatal("group/world-writable policy was accepted")
		}
	}
}
