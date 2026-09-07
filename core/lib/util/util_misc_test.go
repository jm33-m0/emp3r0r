package util

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// util_misc_test.go — coverage for small pure helpers that had no tests.

func TestFormatUptime(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0d 0h 0m 0s"},
		{59, "0d 0h 0m 59s"},
		{61, "0d 0h 1m 1s"},
		{3600, "0d 1h 0m 0s"},
		{86400, "1d 0h 0m 0s"},
		{90061, "1d 1h 1m 1s"},
		{-5, "0d 0h 0m -5s"}, // negative input never occurs in practice; assert no crash and current % semantics
	}
	for _, c := range cases {
		if got := FormatUptime(c.in); got != c.want {
			t.Errorf("FormatUptime(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDumpFileTextAndTruncation(t *testing.T) {
	tmp := t.TempDir()

	// Text file: returned as-is.
	text := filepath.Join(tmp, "text.txt")
	if err := os.WriteFile(text, []byte("hello plain text\nsecond line"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DumpFile(text)
	if err != nil {
		t.Fatalf("DumpFile(text): %v", err)
	}
	if got != "hello plain text\nsecond line" {
		t.Fatalf("DumpFile(text) = %q", got)
	}

	// Text file over the truncation limit gets marked.
	big := filepath.Join(tmp, "big.txt")
	long := strings.Repeat("A", truncateLimit+100)
	if err := os.WriteFile(big, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = DumpFile(big)
	if err != nil {
		t.Fatalf("DumpFile(big text): %v", err)
	}
	if !strings.Contains(got, "(Output truncated)") || len(got) > truncateLimit+len("(Output truncated)\n") {
		t.Fatalf("large text not truncated: len=%d", len(got))
	}
}

func TestDumpFileBinaryHex(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin.dat")
	content := []byte{0x00, 0x01, 0x02, 0xff, 'A', 'B'}
	if err := os.WriteFile(bin, content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DumpFile(bin)
	if err != nil {
		t.Fatalf("DumpFile(binary): %v", err)
	}
	// Hex dump must contain offsets, hex bytes and the printable ASCII column.
	if !strings.Contains(got, "00000000:") || !strings.Contains(got, "ff") || !strings.Contains(got, "AB") {
		t.Fatalf("binary dump missing expected sections: %q", got)
	}
}

func TestDumpFileMissing(t *testing.T) {
	if _, err := DumpFile(filepath.Join(t.TempDir(), "nope.bin")); err == nil {
		t.Fatal("DumpFile on missing file should error")
	}
}

func TestAreBytesPrintable(t *testing.T) {
	if !AreBytesPrintable([]byte("plain text 123")) {
		t.Fatal("printable bytes rejected")
	}
	if AreBytesPrintable([]byte("line\nbreak")) {
		t.Fatal("newline should not be printable in C-string terms")
	}
	// C-string semantics: content after the first NUL is ignored. An empty
	// prefix (leading NUL) is printable, as is a printable NUL-terminated
	// prefix.
	if !AreBytesPrintable([]byte{0x00, 'a', 'b'}) {
		t.Fatal("leading NUL yields empty printable prefix")
	}
	if !AreBytesPrintable([]byte("abc\x00binary")) {
		t.Fatal("NUL-terminated printable prefix should pass")
	}
	if AreBytesPrintable([]byte("ab\x7fcd")) {
		t.Fatal("DEL byte before NUL should be rejected")
	}
}

func TestAppendToFileAgent_PlainAndEncrypted(t *testing.T) {
	defer SetFileCryptoKey(nil)
	SetFileCryptoKey(nil)

	// Plain append on a fresh file.
	f := filepath.Join(t.TempDir(), "append.log")
	if err := AppendToFileAgent(f, []byte("one\n")); err != nil {
		t.Fatalf("append1: %v", err)
	}
	if err := AppendToFileAgent(f, []byte("two\n")); err != nil {
		t.Fatalf("append2: %v", err)
	}
	data, err := ReadFileAgent(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "one\ntwo\n" {
		t.Fatalf("plain append mismatch: %q", data)
	}

	// Encrypted append: file must be AES-GCM protected at rest, and
	// read back decrypts to the concatenation.
	key := []byte("0123456789abcdef0123456789abcdef")
	SetFileCryptoKey(key)
	ef := filepath.Join(t.TempDir(), "secret.log")
	if err := AppendToFileAgent(ef, []byte("alpha")); err != nil {
		t.Fatalf("enc append1: %v", err)
	}
	if err := AppendTextToFileAgent(ef, "beta"); err != nil {
		t.Fatalf("enc append2: %v", err)
	}
	raw, err := os.ReadFile(ef)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("alpha")) {
		t.Fatal("plaintext found in encrypted-at-rest file")
	}
	dec, err := ReadFileAgent(ef)
	if err != nil {
		t.Fatalf("enc read: %v", err)
	}
	if string(dec) != "alphabeta" {
		t.Fatalf("encrypted append mismatch: %q", dec)
	}
	SetFileCryptoKey(nil)
}

func TestAppendToFileAgent_Memfs(t *testing.T) {
	defer SetFileCryptoKey(nil)
	SetFileCryptoKey([]byte("0123456789abcdef0123456789abcdef"))
	resetMemfsState()
	defer resetMemfsState()

	key := "mem:///append_mem.bin"
	if err := AppendToFileAgent(key, []byte("hello ")); err != nil {
		t.Fatalf("mem append: %v", err)
	}
	if err := AppendToFileAgent(key, []byte("world")); err != nil {
		t.Fatalf("mem append2: %v", err)
	}
	got, err := ReadFileAgent(key)
	if err != nil {
		t.Fatalf("mem read: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("mem append mismatch: %q", got)
	}
}

func TestGetWritablePathsBounds(t *testing.T) {
	// Negative depth must error, not recurse.
	if _, err := GetWritablePaths(t.TempDir(), -1, 10); err == nil {
		t.Fatal("negative depth should error")
	}
	// A read-only-ish deep tree: depth 0 returns only writable immediate dirs
	// and honours the max cap without hanging.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	paths, err := GetWritablePaths(root, 0, 1)
	if err != nil {
		// No writable dir at depth 0 (files are files) is also acceptable.
		if len(paths) == 0 {
			t.Logf("no writable paths at depth 0 (ok): %v", err)
		}
	} else if len(paths) > 1 {
		t.Fatalf("max=1 violated: %v", paths)
	}
}
