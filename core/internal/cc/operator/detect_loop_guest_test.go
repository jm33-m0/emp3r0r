package operator

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDetectLoopRegistersWorkerGuestAndGitFlags(t *testing.T) {
	cmd := detectLoopCmd()
	for _, name := range []string{
		"guest-ssh", "guest-ssh-key", "guest-ssh-exclude", "guest-ssh-known-hosts",
		"guest-ssh-fingerprint", "guest-ssh-insecure", "guest-ssh-timeout",
		"planner-turns", "editor-turns", "debugger-turns", "debugger-timeout", "worker-model", "git",
	} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("detect_loop is missing --%s", name)
		}
	}
}

func TestParseGuestSSHEndpoint(t *testing.T) {
	user, host, port, err := parseGuestSSHEndpoint("litterbox@127.0.0.1:2222")
	if err != nil || user != "litterbox" || host != "127.0.0.1" || port != 2222 {
		t.Fatalf("endpoint = %q %q %d err=%v", user, host, port, err)
	}
	user, host, port, err = parseGuestSSHEndpoint("litterbox@guest")
	if err != nil || user != "litterbox" || host != "guest" || port != 22 {
		t.Fatalf("default port = %q %q %d err=%v", user, host, port, err)
	}
	for _, value := range []string{"127.0.0.1:2222", "litterbox@", "litterbox@guest:notaport"} {
		if _, _, _, err := parseGuestSSHEndpoint(value); err == nil {
			t.Fatalf("invalid endpoint accepted: %q", value)
		}
	}
}

func TestGuestConfigResolvesFlags(t *testing.T) {
	key := filepath.Join(t.TempDir(), "guest_key")
	if err := os.WriteFile(key, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH", "")
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH_KEY", "")
	cfg, err := detectLoopOptions{
		GuestSSH: "litterbox@127.0.0.1:2222", GuestSSHKey: key,
		GuestSSHExclude: `D:\stage`, GuestSSHFingerprint: "SHA256:test",
		GuestSSHTimeout: 5 * time.Second,
	}.guestConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.Host != "127.0.0.1" || cfg.Port != 2222 || cfg.User != "litterbox" ||
		cfg.KeyPath != key || cfg.ExcludePath != `D:\stage` || cfg.Fingerprint != "SHA256:test" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Timeout != 5*time.Second {
		t.Fatalf("timeout = %s", cfg.Timeout)
	}
}

func TestGuestConfigEnvFallback(t *testing.T) {
	key := filepath.Join(t.TempDir(), "guest_key")
	if err := os.WriteFile(key, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH", "litterbox@127.0.0.1:2222")
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH_KEY", key)
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH_EXCLUDE", `C:\LitterBox\emp-debug`)
	cfg, err := (detectLoopOptions{}).guestConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.Host != "127.0.0.1" || cfg.Port != 2222 ||
		cfg.User != "litterbox" || cfg.KeyPath != key || cfg.ExcludePath != `C:\LitterBox\emp-debug` {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestGuestConfigRequiresKey(t *testing.T) {
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH", "")
	t.Setenv("EMP3R0R_DETECTION_GUEST_SSH_KEY", "")
	if cfg, err := (detectLoopOptions{}).guestConfig(); err != nil || cfg != nil {
		t.Fatalf("disabled guest = %+v err=%v", cfg, err)
	}
	if _, err := (detectLoopOptions{GuestSSH: "litterbox@127.0.0.1:2222"}).guestConfig(); err == nil {
		t.Fatal("guest endpoint without a key was accepted")
	}
}
