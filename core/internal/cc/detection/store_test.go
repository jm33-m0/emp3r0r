package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPruneArtifactsWithNonJSONEntries(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(artifact, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		name := filepath.Join(dir, fmt.Sprintf("entry-%d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The directory has more entries than the limit, but only one JSON
	// artifact. Pruning must not slice past the artifact list.
	(&Store{}).pruneArtifacts(dir, 2)

	if _, err := os.Stat(artifact); err != nil {
		t.Fatalf("prune removed the only JSON artifact: %v", err)
	}
}
