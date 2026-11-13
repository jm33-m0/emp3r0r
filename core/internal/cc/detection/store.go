package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,160}$`)

// Store persists detection runs under one operator workspace directory.
type Store struct {
	Root string

	// artifactMu serializes the read-modify-write of the artifact registry.
	// Every other file is replaced atomically, so readers never need it.
	artifactMu sync.Mutex
}

// NewStore returns a store rooted at dir.
func NewStore(dir string) *Store { return &Store{Root: strings.TrimSpace(dir)} }

func (s *Store) runsDir() string   { return filepath.Join(s.Root, "runs") }
func (s *Store) latestDir() string { return filepath.Join(s.Root, "latest") }

// Save writes a run atomically and updates the module's latest pointer.
func (s *Store) Save(run Run) (Run, error) {
	if s.Root == "" {
		return run, fmt.Errorf("detection store root is not configured")
	}
	if run.ID == "" {
		run.ID = newRunID(run.Module, run.Plan.Artifact.SHA256)
	}
	if !safeID.MatchString(run.ID) {
		return run, fmt.Errorf("invalid run id %q", run.ID)
	}
	if err := os.MkdirAll(s.runsDir(), 0o700); err != nil {
		return run, fmt.Errorf("create run directory: %w", err)
	}
	if err := writeJSONAtomic(filepath.Join(s.runsDir(), run.ID+".json"), run); err != nil {
		return run, err
	}
	if run.Module != "" {
		if err := os.MkdirAll(s.latestDir(), 0o700); err != nil {
			return run, fmt.Errorf("create latest directory: %w", err)
		}
		if err := writeJSONAtomic(filepath.Join(s.latestDir(), sanitizeName(run.Module)+".json"), run.Summary()); err != nil {
			return run, err
		}
	}
	return run, nil
}

// Load reads one run by ID.
func (s *Store) Load(id string) (Run, error) {
	if !safeID.MatchString(id) {
		return Run{}, fmt.Errorf("invalid run id %q", id)
	}
	if s.Root == "" {
		return Run{}, fmt.Errorf("detection store root is not configured")
	}
	data, err := os.ReadFile(filepath.Join(s.runsDir(), id+".json"))
	if err != nil {
		return Run{}, fmt.Errorf("read detection run %s: %w", id, err)
	}
	var run Run
	if err := json.Unmarshal(data, &run); err != nil {
		return Run{}, fmt.Errorf("decode detection run %s: %w", id, err)
	}
	return run, nil
}

// Latest returns the newest run recorded for a module.
func (s *Store) Latest(module string) (Run, bool, error) {
	if s.Root == "" {
		return Run{}, false, nil
	}
	data, err := os.ReadFile(filepath.Join(s.latestDir(), sanitizeName(module)+".json"))
	if os.IsNotExist(err) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, fmt.Errorf("read latest detection run: %w", err)
	}
	var summary RunSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return Run{}, false, fmt.Errorf("decode latest detection run: %w", err)
	}
	run, err := s.Load(summary.ID)
	if err != nil {
		return Run{}, false, err
	}
	return run, true, nil
}

// List returns the run summaries, newest first.
func (s *Store) List() ([]RunSummary, error) {
	if s.Root == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(s.runsDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list detection runs: %w", err)
	}
	out := make([]RunSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		run, err := s.Load(id)
		if err != nil {
			continue
		}
		out = append(out, run.Summary())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out, nil
}

func newRunID(module, sha string) string {
	short := sha
	if len(short) > 10 {
		short = short[:10]
	}
	if short == "" {
		short = "unknown"
	}
	return sanitizeName(module) + "-" + short
}

func sanitizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "module"
	}
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".detection-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", filepath.Base(path), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// RecordArtifact remembers one artifact produced by a module build. The MCP
// detection tools only detonate artifacts recorded here, so a caller cannot
// point the sandbox at an arbitrary operator file.
func (s *Store) RecordArtifact(module string, artifact Artifact) error {
	if s.Root == "" {
		return fmt.Errorf("detection store root is not configured")
	}
	s.artifactMu.Lock()
	defer s.artifactMu.Unlock()
	dir := filepath.Join(s.Root, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	path := filepath.Join(dir, sanitizeName(module)+".json")
	known := s.knownArtifacts(path)
	replaced := false
	for i, existing := range known {
		if existing.Path == artifact.Path {
			known[i] = artifact
			replaced = true
			break
		}
	}
	if !replaced {
		known = append(known, artifact)
	}
	if len(known) > 50 {
		known = known[len(known)-50:]
	}
	return writeJSONAtomic(path, known)
}

// KnownArtifact returns a recorded artifact by path.
func (s *Store) KnownArtifact(module, path string) (Artifact, bool) {
	if s.Root == "" {
		return Artifact{}, false
	}
	file := filepath.Join(s.Root, "artifacts", sanitizeName(module)+".json")
	for _, artifact := range s.knownArtifacts(file) {
		if artifact.Path == path {
			return artifact, true
		}
	}
	return Artifact{}, false
}

// LatestArtifact returns the newest recorded artifact for a module.
func (s *Store) LatestArtifact(module string) (Artifact, bool) {
	if s.Root == "" {
		return Artifact{}, false
	}
	file := filepath.Join(s.Root, "artifacts", sanitizeName(module)+".json")
	known := s.knownArtifacts(file)
	if len(known) == 0 {
		return Artifact{}, false
	}
	return known[len(known)-1], true
}

func (s *Store) knownArtifacts(path string) []Artifact {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var artifacts []Artifact
	if json.Unmarshal(data, &artifacts) != nil {
		return nil
	}
	return artifacts
}
