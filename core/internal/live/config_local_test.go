package live

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDownloadExtractOperatorConfigSkipsLocalC2 is the regression test for the
// local-operator data loss bug: operator startup ran the full download +
// cleanupConfig path even when the C2 was on the same host, which deleted the
// shared workspace's private keys (ca-key.pem, server-key.pem) and
// wg_config.json while only restoring the public bundle files.
func TestDownloadExtractOperatorConfigSkipsLocalC2(t *testing.T) {
	tmpDir := t.TempDir()
	originalWorkSpace := EmpWorkSpace
	t.Cleanup(func() { EmpWorkSpace = originalWorkSpace })
	EmpWorkSpace = tmpDir

	// Files a running C2 keeps in its workspace, including secrets that the
	// operator bundle never carries.
	files := map[string]string{
		"ca-cert.pem":     "CA CERT",
		"ca-key.pem":      "CA PRIVATE KEY",
		"server-cert.pem": "SERVER CERT",
		"server-key.pem":  "SERVER PRIVATE KEY",
		"emp3r0r.json":    "{}",
		"wg_config.json":  `{"operators":[]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	downloaderCalled := false
	err := DownloadExtractOperatorConfig("127.0.0.1", "http://dummy/url", func(url, dest string) error {
		downloaderCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("DownloadExtractOperatorConfig: %v", err)
	}
	if downloaderCalled {
		t.Fatal("local operator must not download the config bundle")
	}

	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(tmpDir, name))
		if err != nil {
			t.Fatalf("local operator deleted %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s changed: got %q, want %q", name, got, want)
		}
	}
}
