package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLabsMergesBothPlatforms(t *testing.T) {
	t.Setenv("EMP3R0R_DETECTION_LABS", "")
	t.Setenv("EMP3R0R_DETECTION_SANDBOX", "")
	root := t.TempDir()
	file := filepath.Join(root, "labs.json")
	body := `{
  "windows": {"url": "http://127.0.0.1:4444", "guest_ssh": "sandbox@127.0.0.1:2222", "guest_ssh_key": "/tmp/lab-key"},
  "linux": {"url": "http://127.0.0.1:5555"}
}`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	labs, err := LoadLabs(root)
	if err != nil {
		t.Fatal(err)
	}
	if labs.Windows.URL != "http://127.0.0.1:4444" || labs.Linux.URL != "http://127.0.0.1:5555" {
		t.Fatalf("labs = %+v", labs)
	}
	guest, err := labs.Windows.GuestConfig("windows")
	if err != nil {
		t.Fatal(err)
	}
	if guest == nil || guest.User != "sandbox" || guest.Host != "127.0.0.1" || guest.Port != 2222 || guest.KeyPath != "/tmp/lab-key" {
		t.Fatalf("guest = %+v", guest)
	}
}

func TestLoadLabsFillsMissingPlatform(t *testing.T) {
	t.Setenv("EMP3R0R_DETECTION_LABS", "")
	t.Setenv("EMP3R0R_DETECTION_SANDBOX", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "labs.json"), []byte(`{"linux":{"url":"http://10.0.0.2:1338"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	labs, err := LoadLabs(root)
	if err != nil {
		t.Fatal(err)
	}
	if labs.Windows.URL != DefaultSandboxURL {
		t.Fatalf("windows default = %q, want %q", labs.Windows.URL, DefaultSandboxURL)
	}
	if labs.Linux.URL != "http://10.0.0.2:1338" {
		t.Fatalf("linux = %q", labs.Linux.URL)
	}
}

func TestLoopSelectsPlatformClient(t *testing.T) {
	labs := LabsConfig{
		Windows: LabConfig{URL: "http://127.0.0.1:1337"},
		Linux:   LabConfig{URL: "http://127.0.0.1:1338"},
	}
	loop, err := NewLoop(LoopConfig{Labs: labs, StoreRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := loop.ClientFor("linux").URL(); got != "http://127.0.0.1:1338" {
		t.Fatalf("linux client = %q", got)
	}
	if got := loop.ClientFor("windows").URL(); got != "http://127.0.0.1:1337" {
		t.Fatalf("windows client = %q", got)
	}
}
