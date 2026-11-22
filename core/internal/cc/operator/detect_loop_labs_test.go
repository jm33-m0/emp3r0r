package operator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestApplyDetectLoopLabsOnResume(t *testing.T) {
	old := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = old })
	root := filepath.Join(live.EmpWorkSpace, "detection")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "labs.json"), []byte(`{"linux":{"url":"http://127.0.0.1:1338","guest_ssh":"penguinbox@127.0.0.1:2223","guest_ssh_key":"/tmp/penguinbox-key"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := detectLoopOptions{Platform: "linux"}
	applyDetectLoopLabs(&opts)
	if opts.Sandbox != "http://127.0.0.1:1338" || opts.GuestSSH != "penguinbox@127.0.0.1:2223" || opts.GuestSSHKey != "/tmp/penguinbox-key" {
		t.Fatalf("resume lab hydration = %+v", opts)
	}
}
