package modules

import (
	"bytes"
	"crypto/rc4"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// svcLoaderModulesRoot resolves <repo>/core/modules relative to this test
// file. Named uniquely: the package already has windows-only helpers called
// modulesRootFromTest / findConfig in other test files.
func svcLoaderModulesRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve caller path")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))), "modules")
}

func svcLoaderDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(svcLoaderModulesRoot(t), "svc_loader")
}

func svcLoaderFindConfig(t *testing.T, configs []*def.ModuleConfig, name string) *def.ModuleConfig {
	t.Helper()
	for _, c := range configs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("module %q not found in config.json", name)
	return nil
}

// svcLoaderHostCC returns the first native C compiler on PATH, skipping the
// test when there is none (the pack helper is compiled with it).
func svcLoaderHostCC(t *testing.T) string {
	t.Helper()
	for _, c := range []string{"cc", "gcc", "clang"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	t.Skip("svc_loader pack test: no host C compiler (cc/gcc/clang) in PATH")
	return ""
}

// TestSharedModuleDirsMirrored verifies that the shared payload directories
// (bof_common for BOF headers, common for cross-platform payload C sources)
// are mirrored from the search dirs into the operator workspace, where
// buildable modules reference them via relative paths.
func TestSharedModuleDirsMirrored(t *testing.T) {
	searchDir, workspace := newWatchTestRoot(t)
	defer setTestModuleDirs(t, searchDir, workspace)()

	for _, dir := range []string{"bof_common", "common"} {
		if err := os.MkdirAll(filepath.Join(searchDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(searchDir, "common", "rc4.h")
	if err := os.WriteFile(marker, []byte("shared-marker"), 0o644); err != nil {
		t.Fatal(err)
	}

	loadModFromDirs()

	for _, dir := range []string{"bof_common", "common"} {
		dst := filepath.Join(workspace, "modules", dir)
		st, err := os.Stat(dst)
		if err != nil || !st.IsDir() {
			t.Fatalf("shared dir %q was not mirrored into the workspace", dir)
		}
	}
	mirrored, err := os.ReadFile(filepath.Join(workspace, "modules", "common", "rc4.h"))
	if err != nil || string(mirrored) != "shared-marker" {
		t.Fatalf("mirrored common/rc4.h content mismatch: %q, %v", mirrored, err)
	}
}

// TestSvcLoaderConfigParse verifies the local module registry: it must be a
// local module driven by build.sh and expose the parameters operators use.
func TestSvcLoaderConfigParse(t *testing.T) {
	configs, err := readModConfigs(filepath.Join(svcLoaderDir(t), "config.json"))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}

	cfg := svcLoaderFindConfig(t, configs, "svc_loader")
	if !cfg.IsLocal {
		t.Fatalf("svc_loader should be a local (C2-side) module, got IsLocal=%v", cfg.IsLocal)
	}
	if cfg.Build != "bash ./build.sh" {
		t.Fatalf("svc_loader build = %q, want %q", cfg.Build, "bash ./build.sh")
	}
	if !strings.EqualFold(cfg.Platform, "windows") {
		t.Fatalf("svc_loader platform = %q, want Windows", cfg.Platform)
	}

	mustOption := func(name string) *def.ModOption {
		t.Helper()
		opt := cfg.Options[name]
		if opt == nil {
			t.Fatalf("parameter %q missing from svc_loader config", name)
		}
		return opt
	}
	sc := mustOption("shellcode")
	if !sc.Required {
		t.Fatalf("shellcode parameter should be required")
	}
	proc := mustOption("process")
	if proc.Val != "svchost.exe" {
		t.Fatalf("process default = %q, want svchost.exe", proc.Val)
	}
	arch := mustOption("arch")
	if arch.Val != "x64" {
		t.Fatalf("arch default = %q, want x64", arch.Val)
	}
	if len(arch.Vals) != 2 || arch.Vals[0] != "x64" || arch.Vals[1] != "x86" {
		t.Fatalf("arch choices = %v, want [x64 x86]", arch.Vals)
	}
}

// TestSvcLoaderPackRC4RoundTrip builds the production RC4 pack helper with the
// host C compiler and checks it against the Go standard library's crypto/rc4
// as an independent reference: fixed-key ciphertext must match exactly, the
// Go decrypt must recover the original blob, and the random-key/invalid-key
// paths must behave.
func TestSvcLoaderPackRC4RoundTrip(t *testing.T) {
	cc := svcLoaderHostCC(t)
	dir := svcLoaderDir(t)
	tmp := t.TempDir()

	packExe := filepath.Join(tmp, "pack")
	if runtime.GOOS == "windows" {
		packExe += ".exe"
	}
	buildPack := exec.Command(cc, "-O2", "-Wall", "-I", "../common", "-o", packExe,
		"pack.c", "../common/rc4.c")
	buildPack.Dir = dir
	if out, err := buildPack.CombinedOutput(); err != nil {
		t.Fatalf("compiling pack: %v\n%s", err, out)
	}

	// Deterministic pseudo-shellcode (pattern bytes are fine; this is not a
	// key). A 6 MB Donut blob would be wasteful here; 64 KiB covers stream
	// state carry-over across many KSA/PRGA rounds.
	plain := make([]byte, 1<<16)
	for i := range plain {
		plain[i] = byte((i*7 + 3) % 251)
	}
	plainPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	keyHex := "000102030405060708090a0b0c0d0e0f"
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	payloadPath := filepath.Join(tmp, "payload.bin")
	keyPath := filepath.Join(tmp, "key.bin")

	if out, err := exec.Command(packExe, plainPath, payloadPath, keyPath, keyHex).
		CombinedOutput(); err != nil {
		t.Fatalf("pack encrypt: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if len(payload) != len(plain) {
		t.Fatalf("payload length = %d, want %d", len(payload), len(plain))
	}
	storedKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !bytes.Equal(storedKey, key) {
		t.Fatalf("stored key = %x, want %x", storedKey, key)
	}

	// Ciphertext must match an independent RC4 implementation exactly.
	stream, err := rc4.NewCipher(key)
	if err != nil {
		t.Fatalf("rc4.NewCipher: %v", err)
	}
	want := make([]byte, len(plain))
	stream.XORKeyStream(want, plain)
	if !bytes.Equal(payload, want) {
		t.Fatalf("pack ciphertext differs from Go crypto/rc4 reference")
	}

	// Decryption round trip (RC4 is symmetric) must recover the input.
	back := make([]byte, len(payload))
	stream2, err := rc4.NewCipher(key)
	if err != nil {
		t.Fatalf("rc4.NewCipher: %v", err)
	}
	stream2.XORKeyStream(back, payload)
	if !bytes.Equal(back, plain) {
		t.Fatalf("decrypted payload differs from original plaintext")
	}

	// Random-key mode: a fresh 16-byte key file and different ciphertext.
	randPayload := filepath.Join(tmp, "rand_payload.bin")
	randKey := filepath.Join(tmp, "rand_key.bin")
	if out, err := exec.Command(packExe, plainPath, randPayload, randKey).
		CombinedOutput(); err != nil {
		t.Fatalf("pack random key: %v\n%s", err, out)
	}
	randKeyBytes, err := os.ReadFile(randKey)
	if err != nil {
		t.Fatalf("read random key: %v", err)
	}
	if len(randKeyBytes) != 16 {
		t.Fatalf("random key length = %d, want 16", len(randKeyBytes))
	}
	randPayloadBytes, err := os.ReadFile(randPayload)
	if err != nil {
		t.Fatalf("read random payload: %v", err)
	}
	if bytes.Equal(randPayloadBytes, payload) {
		t.Fatalf("random-key ciphertext must differ from the fixed-key one")
	}

	// Invalid key hex must be rejected.
	badPayload := filepath.Join(tmp, "bad_payload.bin")
	if out, err := exec.Command(packExe, plainPath, badPayload, randKey, "zznothex").
		CombinedOutput(); err == nil {
		t.Fatalf("pack accepted an invalid hex key:\n%s", out)
	}
}
