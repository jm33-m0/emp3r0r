package detection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"golang.org/x/crypto/ssh"
)

func TestPowershellEncodedRoundTrip(t *testing.T) {
	script := "Get-Process | Where-Object { $_.ProcessName -eq 'loader' }"
	decoded, err := base64.StdEncoding.DecodeString(powershellEncoded(script))
	if err != nil {
		t.Fatal(err)
	}
	values := make([]uint16, 0, len(decoded)/2)
	for i := 0; i+1 < len(decoded); i += 2 {
		values = append(values, uint16(decoded[i])|uint16(decoded[i+1])<<8)
	}
	if got := string(utf16.Decode(values)); got != script {
		t.Fatalf("decoded = %q, want %q", got, script)
	}
}

func TestGuestSSHKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	key := filepath.Join(t.TempDir(), "guest_key")
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := GuestSSHConfig{Host: "127.0.0.1", User: "litterbox", KeyPath: key, ExcludePath: guestStageDir}
	if err := cfg.normalize(t.TempDir()); err == nil {
		t.Fatal("a group/world-readable key was accepted")
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.normalize(t.TempDir()); err != nil {
		t.Fatalf("a 0600 key was rejected: %v", err)
	}
}

func TestValidateGuestExcludePath(t *testing.T) {
	for _, path := range []string{`C:\LitterBox\emp-debug`, `D:\stage`, `C:\LitterBox\Config`, `C:\LitterBox\Uploads`} {
		if err := validateGuestExcludePath(path); err != nil {
			t.Fatalf("valid path rejected: %v", err)
		}
	}
	for _, path := range []string{
		`C:\`, `relative\stage`, `C:\Windows\System32\..\stage`, `C:\Stage` + "\x00",
	} {
		if err := validateGuestExcludePath(path); err == nil {
			t.Fatalf("invalid path accepted: %q", path)
		}
	}
}

func TestGuestHostKeyTOFUAndPin(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(key)
	known := filepath.Join(t.TempDir(), "known_hosts")
	g := &guestSSH{cfg: GuestSSHConfig{
		Host: "127.0.0.1", Port: 2222, KnownHostsPath: known,
		ExcludePath: guestStageDir,
	}}
	if err := g.verifyHostKey(key); err != nil {
		t.Fatalf("first host key rejected: %v", err)
	}
	recorded, err := g.knownHostKey()
	if err != nil || recorded != fingerprint {
		t.Fatalf("recorded = %q err=%v, want %q", recorded, err, fingerprint)
	}
	if err := g.verifyHostKey(key); err != nil {
		t.Fatalf("recorded host key rejected: %v", err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ssh.NewPublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.verifyHostKey(otherKey); err == nil {
		t.Fatal("a changed host key was accepted")
	}

	pinned := &guestSSH{cfg: GuestSSHConfig{Fingerprint: "SHA256:wrong", KnownHostsPath: known}}
	if err := pinned.verifyHostKey(key); err == nil {
		t.Fatal("a pinned fingerprint mismatch was accepted")
	}
}

type fakeGuestRunner struct {
	commands []string
	excluded bool
}

func (f *fakeGuestRunner) Exec(_ context.Context, command string, _ time.Duration) (GuestExecResult, error) {
	f.commands = append(f.commands, command)
	return GuestExecResult{Stdout: `{"ok":true}`, ExitCode: 0}, nil
}

func (f *fakeGuestRunner) ReadFile(_ context.Context, _ string, _, _ int64) ([]byte, error) {
	return []byte("guest-bytes"), nil
}

func (f *fakeGuestRunner) EnsureExclusion(_ context.Context) (GuestExclusionStatus, error) {
	f.excluded = true
	return GuestExclusionStatus{Path: guestStageDir, Present: true, Added: true}, nil
}

func (f *fakeGuestRunner) Close() error { return nil }

func newGuestToolTestEvolver(t *testing.T, guest GuestRunner) *evolver {
	t.Helper()
	store := t.TempDir()
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", StoreRoot: store,
			Guest: &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
		},
		guest: guest,
		logf:  func(logging.Class, string, ...any) {},
	}
	return e
}

func TestGuestSSHToolActions(t *testing.T) {
	fake := &fakeGuestRunner{}
	e := newGuestToolTestEvolver(t, fake)
	toolUnderTest := e.guestSSHTool()

	res, err := toolUnderTest.Call(context.Background(), json.RawMessage(`{"action":"ensure_exclusion"}`), nil)
	if err != nil || res.IsError || !fake.excluded {
		t.Fatalf("ensure_exclusion: err=%v result=%+v", err, res)
	}

	res, err = toolUnderTest.Call(context.Background(), json.RawMessage(`{"action":"exec","command":"Get-Process"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("exec: err=%v result=%+v", err, res)
	}
	if len(fake.commands) != 1 || fake.commands[0] != "Get-Process" {
		t.Fatalf("commands = %v", fake.commands)
	}

	res, err = toolUnderTest.Call(context.Background(),
		json.RawMessage(`{"action":"read","path":"C:\\LitterBox\\Results\\x\\dynamic.json"}`), nil)
	if err != nil || res.IsError || res.Flatten() != "guest-bytes" {
		t.Fatalf("read: err=%v result=%+v", err, res)
	}
}

func TestGuestSSHToolRequiresConfig(t *testing.T) {
	e := &evolver{cfg: EvolveConfig{LoopID: "loop", StoreRoot: t.TempDir()}, logf: func(logging.Class, string, ...any) {}}
	res, err := e.guestSSHTool().Call(context.Background(), json.RawMessage(`{"action":"exec","command":"Get-Process"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("GuestSSH worked without a configured guest: %+v", res)
	}
	if !strings.Contains(res.Flatten(), "not configured") {
		t.Fatalf("result = %s", res.Flatten())
	}
}
