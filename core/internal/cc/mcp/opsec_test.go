package mcp

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestReviewExecBaseline(t *testing.T) {
	review := ReviewExec("whoami", &def.Emp3r0rAgent{Tag: "t", User: "alice", GOOS: "linux"})
	if review.Noise != "medium" {
		t.Fatalf("noise = %q, want medium", review.Noise)
	}
	if !review.Reversible {
		t.Fatal("whoami should be reversible")
	}
	if !contains(review.Rules, "process-creation") {
		t.Fatalf("rules = %v, want process-creation", review.Rules)
	}
	if !contains(review.Reasons, "child process") {
		t.Fatalf("reasons = %v", review.Reasons)
	}
}

func TestReviewExecCapabilities(t *testing.T) {
	cases := []struct {
		command string
		rule    string
	}{
		{"powershell -enc SQBFAFgA", "script-execution"},
		{"execute-assembly /tmp/a.exe", "clr-loading"},
		{"rundll32 comsvcs.dll, MiniDump", "lolbin-execution"},
		{"echo x > /tmp/y", "filesystem-artifact"},
		{"memfd_create", "filesystem-artifact"},
		{"cat /etc/shadow", "credential-access"},
		{"klist", "kerberos-credential"},
		{"ldapsearch --filter '(objectclass=*)'", "noisy-query"},
		{"scp /tmp/x user@example.test:/x", "data-transfer"},
		{"rm -rf /tmp/x", "destructive"},
	}
	for _, tc := range cases {
		review := ReviewExec(tc.command, nil)
		if !contains(review.Rules, tc.rule) {
			t.Errorf("%q rules = %v, want %s", tc.command, review.Rules, tc.rule)
		}
	}
}

func TestReviewExecRedirectionToDeviceIsNotAFile(t *testing.T) {
	review := ReviewExec("cat /etc/hosts 2>/dev/null", nil)
	if contains(review.Rules, "filesystem-artifact") {
		t.Fatalf("/dev/null redirect marked as a file write: %v", review.Rules)
	}
	review = ReviewExec("echo x > /tmp/y", nil)
	if !contains(review.Rules, "filesystem-artifact") {
		t.Fatalf("file redirect not marked: %v", review.Rules)
	}
}

func TestReviewExecTokenBoundaries(t *testing.T) {
	review := ReviewExec("blacklist", nil)
	if contains(review.Rules, "kerberos-credential") {
		t.Fatalf("blacklist matched the klist token: %v", review.Rules)
	}
	review = ReviewExec("cat config.json", nil)
	if contains(review.Rules, "script-execution") {
		t.Fatalf(".json matched the .js script token: %v", review.Rules)
	}
	review = ReviewExec("cat excellent.txt", nil)
	if contains(review.Rules, "lolbin-execution") {
		t.Fatalf("excellent matched the excel token: %v", review.Rules)
	}
}

func TestReviewETWMatchesOnlyWholeWord(t *testing.T) {
	network := &def.ModuleConfig{
		Name:        "get_netsession",
		Comment:     "Enumerate network sessions established to a computer using NetSessionEnum",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	if review := ReviewModule(network, nil, "get_netsession", nil); contains(review.Rules, "defense-tampering") {
		t.Fatalf("network description matched etw: %v", review.Rules)
	}

	smbinfo := &def.ModuleConfig{
		Name:        "smbinfo",
		Comment:     "Get remote system version information with NetWkstaGetInfo (no SMB port scan)",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	if review := ReviewModule(smbinfo, nil, "smbinfo --target winterfell", nil); contains(review.Rules, "defense-tampering") {
		t.Fatalf("NetWkstaGetInfo matched etw: %v", review.Rules)
	}

	etw := &def.ModuleConfig{
		Name:        "etw-stop",
		Comment:     "Disable ETW logging",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	if review := ReviewModule(etw, nil, "etw-stop", nil); !contains(review.Rules, "defense-tampering") {
		t.Fatalf("ETW logging description not matched: %v", review.Rules)
	}
}

func TestReviewExecDestructiveUsesWordBoundaries(t *testing.T) {
	for _, command := range []string{"echo model", "skill", "Perform S4U constrained delegation abuse"} {
		review := ReviewExec(command, nil)
		if contains(review.Rules, "destructive") {
			t.Fatalf("%q matched destructive inside a word: %v", command, review.Rules)
		}
	}
	review := ReviewExec("rm -rf /tmp/x", nil)
	if !contains(review.Rules, "destructive") || review.Reversible {
		t.Fatalf("rm -rf review = %+v", review)
	}
}

func TestReviewBuiltinHasNoProcessCreation(t *testing.T) {
	review := ReviewBuiltin("ls --path /tmp", nil)
	if contains(review.Rules, "process-creation") {
		t.Fatalf("built-in command marked as process creation: %v", review.Rules)
	}
	if review.Noise != "low" {
		t.Fatalf("noise = %q, want low", review.Noise)
	}
}

func TestReviewModuleUsesMetadata(t *testing.T) {
	reversible := true
	mod := &def.ModuleConfig{
		Name: "sa_demo",
		Opsec: &def.OpsecProfile{
			Noise:      "low",
			WritesDisk: true,
			Artifacts:  []string{"event 4688"},
			Reversible: &reversible,
		},
	}
	review := ReviewModule(mod, nil, "sa_demo", &def.Emp3r0rAgent{Tag: "t", GOOS: "windows"})
	if review.Noise != "low" {
		t.Fatalf("noise = %q", review.Noise)
	}
	if !review.Reversible {
		t.Fatal("metadata reversible=true was not honored")
	}
	if !contains(review.Rules, "filesystem-artifact") {
		t.Fatalf("rules = %v, want filesystem-artifact", review.Rules)
	}
	if !contains(review.Artifacts, "file write") || !contains(review.Artifacts, "event 4688") {
		t.Fatalf("artifacts = %v", review.Artifacts)
	}
	if len(review.Unknowns) != 0 {
		t.Fatalf("unknowns = %v", review.Unknowns)
	}
}

func TestReviewModuleMetadataCredentials(t *testing.T) {
	mod := &def.ModuleConfig{
		Name:  "m",
		Opsec: &def.OpsecProfile{Noise: "low", TouchesCredentials: true},
	}
	review := ReviewModule(mod, nil, "m", nil)
	if !contains(review.Rules, "credential-access") {
		t.Fatalf("rules = %v, want credential-access", review.Rules)
	}
}

func TestReviewModuleHeuristicsByDescription(t *testing.T) {
	klist := &def.ModuleConfig{
		Name:        "klist",
		Comment:     "List, purge, or request Kerberos tickets from the current logon session",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	review := ReviewModule(klist, nil, "klist", nil)
	if !contains(review.Rules, "kerberos-credential") {
		t.Fatalf("klist rules = %v", review.Rules)
	}
	if review.Noise != "low" {
		t.Fatalf("klist noise = %q, want low for a BOF", review.Noise)
	}

	s4u := &def.ModuleConfig{
		Name:        "kerbeus_s4u",
		Comment:     "Perform S4U constrained delegation abuse",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	withoutParams := ReviewModule(s4u, nil, "kerbeus_s4u", nil)
	withParams := ReviewModule(s4u, map[string]string{"params": "/impersonateuser:Administrator"}, "kerbeus_s4u --params '/impersonateuser:Administrator'", nil)
	for name, r := range map[string]def.OpsecReview{"without": withoutParams, "with": withParams} {
		if !contains(r.Rules, "kerberos-credential") {
			t.Fatalf("s4u %s params rules = %v", name, r.Rules)
		}
		if r.Noise != "low" {
			t.Fatalf("s4u %s params noise = %q, want low for a BOF", name, r.Noise)
		}
	}
}

func TestReviewModuleFlagRule(t *testing.T) {
	mod := &def.ModuleConfig{Name: "m", Opsec: &def.OpsecProfile{Noise: "low"}}
	review := ReviewModule(mod, map[string]string{"filter": "lsass"}, "m --filter lsass", nil)
	if !contains(review.Rules, "credential-access") {
		t.Fatalf("rules = %v", review.Rules)
	}
}

func TestReviewModuleRequiresAdminOnNonRootTarget(t *testing.T) {
	mod := &def.ModuleConfig{Name: "m", Opsec: &def.OpsecProfile{Noise: "low", RequiresAdmin: true}}
	review := ReviewModule(mod, nil, "m", &def.Emp3r0rAgent{Tag: "t", User: "alice", HasRoot: false})
	if !contains(review.Requires, "admin") {
		t.Fatalf("requires = %v", review.Requires)
	}
	if !contains(review.Reasons, "requires admin") {
		t.Fatalf("reasons = %v", review.Reasons)
	}
}

func TestReviewModulePerModuleTicket(t *testing.T) {
	mod := &def.ModuleConfig{
		Name:        "kerbeus_asktgt",
		Comment:     "Retrieve a TGT",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	review := ReviewModule(mod, map[string]string{"params": "/user:jdoe /ptt"}, "kerbeus_asktgt --params '/user:jdoe /ptt'", nil)
	if contains(review.Rules, "logon-ticket-import") {
		t.Fatalf("/ptt was screened as an OPSEC capability: %v", review.Rules)
	}
	if !contains(review.Rules, "kerberos-credential") {
		t.Fatalf("rules = %v, want kerberos-credential", review.Rules)
	}

	ticket := &def.ModuleConfig{
		Name:        "kerbeus_asktgs",
		Comment:     "Retrieve a TGS",
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
	}
	if got := ReviewModule(ticket, map[string]string{"ticket": "base64"}, "kerbeus_asktgs --ticket base64", nil); contains(got.Rules, "logon-ticket-import") {
		t.Fatalf("per-module --ticket flagged as global import: %v", got.Rules)
	}
}

func TestReviewLocalModuleHasNoTargetFootprint(t *testing.T) {
	mod := &def.ModuleConfig{Name: "stager", IsLocal: true, Build: "bash ./build.sh", Comment: "payload stager with injection"}
	review := ReviewModule(mod, nil, "stager", nil)
	if review.Noise != "low" || len(review.Rules) != 0 {
		t.Fatalf("local module review = %+v", review)
	}
}

func TestReviewDedupes(t *testing.T) {
	review := ReviewExec("lsass lsass", nil)
	seen := map[string]int{}
	for _, r := range review.Reasons {
		seen[r]++
	}
	for reason, count := range seen {
		if count > 1 {
			t.Fatalf("reason %q repeated %d times", reason, count)
		}
	}
}

func TestValidateCommandLine(t *testing.T) {
	if err := ValidateCommandLine("whoami"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\x01b", "a\u202Eb", "a\u200Bb"} {
		if err := ValidateCommandLine(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

func contains(list []string, needle string) bool {
	for _, v := range list {
		if strings.Contains(strings.ToLower(v), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
