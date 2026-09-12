package agentutils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSplitPathPreservesAbsoluteEntries is the regression test for the old
// trimming logic: it stripped the leading separator, turning "/usr/bin" into
// the relative "usr/bin" (and the Windows equivalent into "windows\system32"),
// which silently breaks PATH lookups. Duplicate removal is InitializePath's job,
// so splitPath must return entries verbatim and in order.
func TestSplitPathPreservesAbsoluteEntries(t *testing.T) {
	sep := string(os.PathListSeparator)
	var entries, want []string
	if runtime.GOOS == "windows" {
		entries = []string{`c:\windows`, `c:\windows\system32`, `\\server\share`, `c:\windows`}
		want = []string{`c:\windows`, `c:\windows\system32`, `\\server\share`, `c:\windows`}
	} else {
		entries = []string{"/usr/bin", "/usr/local/bin", "/usr/bin"}
		want = []string{"/usr/bin", "/usr/local/bin", "/usr/bin"}
	}

	got := splitPath(strings.Join(entries, sep))
	if len(got) != len(want) {
		t.Fatalf("splitPath returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitPath returned %v, want %v", got, want)
		}
	}
}

func TestSplitPathDropsEmptyEntries(t *testing.T) {
	sep := string(os.PathListSeparator)
	host := "host"
	input := strings.Join([]string{"", "   ", host, ""}, sep)
	if got := splitPath(input); len(got) != 1 || got[0] != host {
		t.Fatalf("splitPath(%q) returned %v, want [%s]", input, got, host)
	}
}

// TestInitializePathAugmentsAndPreserves verifies the real function through its
// observable effect on the process environment: existing entries survive and
// take precedence, the platform defaults are appended, and entries are unique.
func TestInitializePathAugmentsAndPreserves(t *testing.T) {
	original, had := os.LookupEnv("PATH")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("PATH", original)
		} else {
			_ = os.Unsetenv("PATH")
		}
	})

	sep := string(os.PathListSeparator)
	marker := filepath.Join(t.TempDir(), "emp3r0r-test-bin")
	if err := os.Setenv("PATH", marker); err != nil {
		t.Fatalf("set PATH: %v", err)
	}

	InitializePath()

	after := os.Getenv("PATH")
	parts := strings.Split(after, sep)

	// Windows canonicalises entry case for deduplication, so compare folded.
	first, want := parts[0], marker
	if runtime.GOOS == "windows" {
		first, want = strings.ToLower(first), strings.ToLower(want)
	}
	if first != want {
		t.Errorf("existing PATH entry lost its precedence: got %q want %q (full PATH %q)", parts[0], marker, after)
	}

	seen := make(map[string]int, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		seen[p]++
	}
	for p, count := range seen {
		if count > 1 {
			t.Errorf("PATH entry %q appears %d times: %q", p, count, after)
		}
	}

	defaults := []string{"/bin", "/usr/bin", "/usr/local/bin"}
	if runtime.GOOS == "windows" {
		defaults = []string{`c:\windows\system32`, `c:\windows`}
	}
	folded := strings.ToLower(after)
	for _, d := range defaults {
		if !strings.Contains(folded, strings.ToLower(d)) {
			t.Errorf("PATH missing default %q: %q", d, after)
		}
	}
}
