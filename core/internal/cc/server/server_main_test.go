package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestLoadOrProvisionWgKeepsExistingIdentities verifies the provisioning
// policy: first run creates the requested named operators, later runs keep
// them, --operators is refused once the file exists, and --add-operator appends
// without disturbing existing keys.
func TestLoadOrProvisionWgKeepsExistingIdentities(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "wg_config.json")

	// First run creates the named operators.
	cfg, err := loadOrProvisionWg(configFile, []string{"alice", "bob"}, nil, false)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if len(cfg.Operators) != 2 {
		t.Fatalf("operators = %d, want 2", len(cfg.Operators))
	}
	if cfg.Operators[0].Name != "alice" || cfg.Operators[1].Name != "bob" {
		t.Fatalf("operator names = %q, %q; want alice, bob", cfg.Operators[0].Name, cfg.Operators[1].Name)
	}
	firstPriv := cfg.Operators[0].PrivateKey
	firstServerIP := cfg.ServerIP

	// Re-run without flags keeps the existing identities.
	cfg2, err := loadOrProvisionWg(configFile, nil, nil, false)
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if len(cfg2.Operators) != 2 {
		t.Fatalf("re-run operators = %d, want 2 (existing must be kept)", len(cfg2.Operators))
	}
	if cfg2.Operators[0].PrivateKey != firstPriv || cfg2.ServerIP != firstServerIP {
		t.Fatal("re-run regenerated existing server/operator identities")
	}

	// Explicit --operators against an existing config is refused.
	if _, err := loadOrProvisionWg(configFile, []string{"carl"}, nil, true); err == nil {
		t.Fatal("expected an error when --operators is used with an existing config")
	}

	// --add-operator appends and keeps the existing ones.
	cfg3, err := loadOrProvisionWg(configFile, nil, []string{"carl", "dave"}, false)
	if err != nil {
		t.Fatalf("add operators: %v", err)
	}
	if len(cfg3.Operators) != 4 {
		t.Fatalf("operators after add = %d, want 4", len(cfg3.Operators))
	}
	if cfg3.Operators[0].PrivateKey != firstPriv {
		t.Fatal("--add-operator changed an existing identity")
	}
	if cfg3.Operators[2].Name != "carl" || cfg3.Operators[3].Name != "dave" {
		t.Fatalf("appended names = %q, %q; want carl, dave", cfg3.Operators[2].Name, cfg3.Operators[3].Name)
	}

	// A duplicate name is rejected.
	if _, err := loadOrProvisionWg(configFile, nil, []string{"alice"}, false); err == nil {
		t.Fatal("expected an error when adding an existing operator name")
	}

	// The result is persisted, not just returned.
	reloaded, err := loadOrProvisionWg(configFile, nil, nil, false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Operators) != 4 {
		t.Fatalf("persisted operators = %d, want 4", len(reloaded.Operators))
	}
}

// TestLoadOrProvisionWgDefaults verifies the count form, the empty default and
// that --add-operator also works when no config exists yet.
func TestLoadOrProvisionWgDefaults(t *testing.T) {
	dir := t.TempDir()

	// No names falls back to one default operator.
	cfg, err := loadOrProvisionWg(filepath.Join(dir, "a.json"), nil, nil, false)
	if err != nil || len(cfg.Operators) != 1 {
		t.Fatalf("default first run: operators=%d err=%v, want 1", len(cfg.Operators), err)
	}
	if cfg.Operators[0].Name != "operator-1" {
		t.Fatalf("default name = %q, want operator-1", cfg.Operators[0].Name)
	}

	// A single integer still means a count.
	cfg2, err := loadOrProvisionWg(filepath.Join(dir, "b.json"), []string{"3"}, nil, false)
	if err != nil || len(cfg2.Operators) != 3 {
		t.Fatalf("count form: operators=%d err=%v, want 3", len(cfg2.Operators), err)
	}
	if cfg2.Operators[2].Name != "operator-3" {
		t.Fatalf("count-form name = %q, want operator-3", cfg2.Operators[2].Name)
	}

	// --add-operator with no file creates the named operators.
	cfg3, err := loadOrProvisionWg(filepath.Join(dir, "c.json"), nil, []string{"carl", "dave"}, false)
	if err != nil || len(cfg3.Operators) != 2 {
		t.Fatalf("add on first run: operators=%d err=%v, want 2", len(cfg3.Operators), err)
	}
}

// TestValidateOperatorNames rejects blank, control-character and duplicate
// names so the audit log cannot be spoofed.
func TestValidateOperatorNames(t *testing.T) {
	if _, err := validateOperatorNames([]string{"alice", "alice"}); err == nil {
		t.Fatal("duplicate names must be rejected")
	}
	if _, err := validateOperatorNames([]string{"   "}); err == nil {
		t.Fatal("blank names must be rejected")
	}
	if _, err := validateOperatorNames([]string{"ali\nce"}); err == nil {
		t.Fatal("control characters must be rejected")
	}
	if _, err := validateOperatorNames([]string{"ok"}); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
}

// TestLoadOrProvisionWgRejectsIncomplete verifies a truncated config is an
// error rather than a silently broken server.
func TestLoadOrProvisionWgRejectsIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"server_ip":"10.0.0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrProvisionWg(path, nil, nil, false); err == nil {
		t.Fatal("expected an error for an incomplete config")
	}
}

// TestAuditOperatorAction verifies the audit log records the timestamp, the
// operator name, its WireGuard IP/public key and the target.
func TestAuditOperatorAction(t *testing.T) {
	dir := t.TempDir()
	origWorkSpace := live.EmpWorkSpace
	live.EmpWorkSpace = dir
	t.Cleanup(func() { live.EmpWorkSpace = origWorkSpace })

	registerOperators([]OperatorConfig{{Name: "alice", IP: "10.44.0.2", PublicKey: "PUBKEY"}})
	t.Cleanup(func() { operatorIndex.Delete("10.44.0.2") })

	auditOperatorAction("10.44.0.2", "command", "abcd1234 (uuid-1)", "id")

	data, err := os.ReadFile(operatorAuditPath())
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := string(data)
	for _, want := range []string{
		`operator="alice"`,
		`wg_ip="10.44.0.2"`,
		`wg_pubkey="PUBKEY"`,
		`action="command"`,
		`target="abcd1234 (uuid-1)"`,
		`detail="id"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("audit log missing %s:\n%s", want, line)
		}
	}
}
