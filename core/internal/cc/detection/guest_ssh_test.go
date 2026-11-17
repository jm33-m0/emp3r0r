package detection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestGuestCommandPolicy(t *testing.T) {
	g := &guestSSH{cfg: GuestSSHConfig{ExcludePath: guestStageDir}}
	allowed := []string{
		`Get-Process | Select-Object Id,ProcessName,Path`,
		`Get-MpThreatDetection | ConvertTo-Json -Depth 4`,
		`Start-Process 'C:\LitterBox\Uploads\loader.exe'`,
		`[IO.File]::WriteAllBytes('C:\LitterBox\emp-debug\dump.bin', $bytes)`,
		`procdump64.exe -accepteula -ma 1234 C:\LitterBox\emp-debug\loader.dmp`,
		`Test-NetConnection 10.0.0.1 -Port 443`,
	}
	for _, command := range allowed {
		if err := g.screenCommand(command); err != nil {
			t.Fatalf("allowed command rejected: %v\n%s", err, command)
		}
	}
	denied := []string{
		`Set-MpPreference -DisableRealtimeMonitoring $true`,
		`Add-MpPreference -ExclusionPath C:\`,
		`Remove-MpPreference -ExclusionPath C:\LitterBox`,
		`netsh advfirewall set allprofiles state off`,
		`Stop-Service WinDefend`,
		`Remove-Item C:\LitterBox\Results -Recurse -Force`,
		`[IO.File]::WriteAllBytes('C:\LitterBox\Config\config.json', $bytes)`,
		`Start-Process C:\Windows\System32\cmd.exe`,
		`Invoke-WebRequest https://example.com`,
		`wevtutil cl System`,
	}
	for _, command := range denied {
		if err := g.screenCommand(command); err == nil {
			t.Fatalf("denied command accepted: %s", command)
		}
	}
}

func TestGuestReadPathProtectsKeyMaterial(t *testing.T) {
	for _, path := range []string{
		`C:\ProgramData\ssh\ssh_host_ed25519_key`,
		`C:\Users\litterbox\.ssh\authorized_keys`,
		`C:\ProgramData\ssh`,
	} {
		if err := screenGuestReadPath(path); err == nil {
			t.Fatalf("key material path accepted: %s", path)
		}
	}
	if err := screenGuestReadPath(`C:\LitterBox\Results\x\dynamic.json`); err != nil {
		t.Fatalf("result path rejected: %v", err)
	}
	g := &guestSSH{cfg: GuestSSHConfig{ExcludePath: guestStageDir}}
	if err := g.screenCommand(`Get-Content C:\ProgramData\ssh\ssh_host_ed25519_key`); err == nil {
		t.Fatal("a command reading the host key was accepted")
	}
}

func TestGuestUploadPathConfined(t *testing.T) {
	g := &guestSSH{cfg: GuestSSHConfig{ExcludePath: guestStageDir}}
	if err := g.screenUploadPath(`C:\LitterBox\emp-debug\helper.ps1`); err != nil {
		t.Fatalf("staging upload rejected: %v", err)
	}
	for _, path := range []string{
		`C:\LitterBox\Config\helper.ps1`,
		`C:\Windows\Temp\helper.ps1`,
		`C:\LitterBox\emp-debug-evil\helper.ps1`,
	} {
		if err := g.screenUploadPath(path); err == nil {
			t.Fatalf("upload outside the staging directory accepted: %s", path)
		}
	}
}

func TestValidateGuestExcludePath(t *testing.T) {
	for _, path := range []string{`C:\LitterBox\emp-debug`, `D:\stage`} {
		if err := validateGuestExcludePath(path); err != nil {
			t.Fatalf("valid path rejected: %v", err)
		}
	}
	for _, path := range []string{
		`C:\`, `relative\stage`, `C:\LitterBox\Config`, `C:\LitterBox\Uploads`,
		`C:\Windows\System32\..\stage`, `C:\Stage` + "\x00",
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
	uploads  []string
	excluded bool
}

func (f *fakeGuestRunner) Exec(_ context.Context, command string, _ time.Duration) (GuestExecResult, error) {
	f.commands = append(f.commands, command)
	return GuestExecResult{Stdout: `{"ok":true}`, ExitCode: 0}, nil
}

func (f *fakeGuestRunner) ReadFile(_ context.Context, _ string, _, _ int64) ([]byte, error) {
	return []byte("guest-bytes"), nil
}

func (f *fakeGuestRunner) Download(_ context.Context, _, local string, _ int64) error {
	return os.WriteFile(local, []byte("downloaded"), 0o600)
}

func (f *fakeGuestRunner) Upload(_ context.Context, local, remote string, _ int64) error {
	f.uploads = append(f.uploads, local+"->"+remote)
	return nil
}

func (f *fakeGuestRunner) EnsureExclusion(_ context.Context) (GuestExclusionStatus, error) {
	f.excluded = true
	return GuestExclusionStatus{Path: guestStageDir, Present: true, Added: true}, nil
}

func (f *fakeGuestRunner) Close() error { return nil }

func newGuestToolTestEvolver(t *testing.T, guest GuestRunner) (*evolver, string) {
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
	return e, store
}

func TestGuestSSHToolActions(t *testing.T) {
	fake := &fakeGuestRunner{}
	e, store := newGuestToolTestEvolver(t, fake)
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

	evidence := filepath.Join(store, "guest", "loop")
	local := filepath.Join(evidence, "dump.bin")
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = toolUnderTest.Call(context.Background(),
		json.RawMessage(`{"action":"upload","local":"`+local+`","path":"C:\\LitterBox\\emp-debug\\helper.ps1"}`), nil)
	if err != nil || res.IsError || len(fake.uploads) != 1 {
		t.Fatalf("upload: err=%v result=%+v uploads=%v", err, res, fake.uploads)
	}

	res, err = toolUnderTest.Call(context.Background(),
		json.RawMessage(`{"action":"download","path":"C:\\LitterBox\\Results\\x\\dynamic.json","local":"dynamic.json"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("download: err=%v result=%+v", err, res)
	}
	if _, err := os.Stat(filepath.Join(evidence, "dynamic.json")); err != nil {
		t.Fatalf("download destination missing: %v", err)
	}

	res, err = toolUnderTest.Call(context.Background(),
		json.RawMessage(`{"action":"download","path":"C:\\x","local":"../../escape.json"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("download outside the evidence directory was accepted")
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
