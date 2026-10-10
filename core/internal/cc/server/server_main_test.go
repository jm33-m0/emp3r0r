package server

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrProvisionWgKeepsExistingIdentities verifies the provisioning
// policy: first run creates the requested operators, later runs keep them,
// --operators is refused once the file exists, and --add-operator appends
// without disturbing existing keys.
func TestLoadOrProvisionWgKeepsExistingIdentities(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "wg_config.json")

	// First run creates N operators.
	cfg, err := loadOrProvisionWg(configFile, 2, 0, false)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if len(cfg.Operators) != 2 {
		t.Fatalf("operators = %d, want 2", len(cfg.Operators))
	}
	firstPriv := cfg.Operators[0].PrivateKey
	firstServerIP := cfg.ServerIP

	// Re-run without flags keeps the existing identities.
	cfg2, err := loadOrProvisionWg(configFile, 1, 0, false)
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
	if _, err := loadOrProvisionWg(configFile, 3, 0, true); err == nil {
		t.Fatal("expected an error when --operators is used with an existing config")
	} else if len(cfg2.Operators) != 2 {
		t.Fatalf("refused run mutated the config: %d operators", len(cfg2.Operators))
	}

	// --add-operator appends and keeps the existing ones.
	cfg3, err := loadOrProvisionWg(configFile, 1, 2, false)
	if err != nil {
		t.Fatalf("add operators: %v", err)
	}
	if len(cfg3.Operators) != 4 {
		t.Fatalf("operators after add = %d, want 4", len(cfg3.Operators))
	}
	if cfg3.Operators[0].PrivateKey != firstPriv {
		t.Fatal("--add-operator changed an existing identity")
	}
	if cfg3.Operators[2].Name != "operator-3" || cfg3.Operators[3].Name != "operator-4" {
		t.Fatalf("appended names = %q, %q; want operator-3, operator-4",
			cfg3.Operators[2].Name, cfg3.Operators[3].Name)
	}

	// The result is persisted, not just returned.
	reloaded, err := loadOrProvisionWg(configFile, 1, 0, false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Operators) != 4 {
		t.Fatalf("persisted operators = %d, want 4", len(reloaded.Operators))
	}
}

// TestLoadOrProvisionWgDefaults verifies first-run defaults and that
// --add-operator also works when no config exists yet.
func TestLoadOrProvisionWgDefaults(t *testing.T) {
	dir := t.TempDir()

	// numOperators 0 falls back to one operator.
	cfg, err := loadOrProvisionWg(filepath.Join(dir, "a.json"), 0, 0, false)
	if err != nil || len(cfg.Operators) != 1 {
		t.Fatalf("default first run: operators=%d err=%v, want 1", len(cfg.Operators), err)
	}

	// --add-operator with no file creates that many.
	cfg2, err := loadOrProvisionWg(filepath.Join(dir, "b.json"), 1, 3, false)
	if err != nil || len(cfg2.Operators) != 3 {
		t.Fatalf("add on first run: operators=%d err=%v, want 3", len(cfg2.Operators), err)
	}
}

// TestLoadOrProvisionWgRejectsIncomplete verifies a truncated config is an
// error rather than a silently broken server.
func TestLoadOrProvisionWgRejectsIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"server_ip":"10.0.0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrProvisionWg(path, 1, 0, false); err == nil {
		t.Fatal("expected an error for an incomplete config")
	}
}
