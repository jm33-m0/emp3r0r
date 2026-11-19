package operator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// detectLoopManifest is the on-disk resume state for one logical detection
// loop. It stores the resolved options and the current attempt so a loop that
// was stopped or interrupted can be listed and restarted after a console
// restart. Runtime model credentials and GuestSSH key contents are not stored.
type detectLoopManifest struct {
	LoopID        string            `json:"loop_id"`
	BaseLoopID    string            `json:"base_loop_id,omitempty"`
	CurrentLoopID string            `json:"current_loop_id,omitempty"`
	Attempt       int               `json:"attempt"`
	Status        string            `json:"status"`
	StartedAt     time.Time         `json:"started_at,omitempty"`
	UpdatedAt     time.Time         `json:"updated_at"`
	LogPath       string            `json:"log_path,omitempty"`
	Verified      bool              `json:"verified,omitempty"`
	Error         string            `json:"error,omitempty"`
	Options       detectLoopOptions `json:"options"`
}

func detectLoopStateDir() string {
	return filepath.Join(live.EmpWorkSpace, "detection", "loops")
}

func safeLoopFileName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// detectLoopLogPath keeps a resumed loop's log under the detection store.
// A manifest is operator-local state, but a stale or hand-edited path must not
// turn resume into an append to an unrelated file.
func detectLoopLogPath(saved string) string {
	root, err := filepath.Abs(filepath.Join(live.EmpWorkSpace, "detection"))
	if err != nil {
		root = filepath.Join(live.EmpWorkSpace, "detection")
	}
	defaultPath := filepath.Join(root, "detect-loop-"+time.Now().UTC().Format("20060102-150405")+".log")
	saved = strings.TrimSpace(saved)
	if saved == "" {
		return defaultPath
	}
	abs, err := filepath.Abs(saved)
	if err != nil {
		return defaultPath
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return defaultPath
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return defaultPath
	}
	return abs
}

func detectLoopManifestPath(baseLoopID string) string {
	return filepath.Join(detectLoopStateDir(), safeLoopFileName(baseLoopID)+".json")
}

// writeDetectLoopManifest atomically replaces one manifest. Manifests are
// operator-local state: 0700 directory, 0600 file. Existing state directories
// are tightened too, because MkdirAll leaves a pre-existing mode unchanged.
func writeDetectLoopManifest(m *detectLoopManifest) error {
	if m == nil || strings.TrimSpace(m.LoopID) == "" {
		return fmt.Errorf("loop manifest has no loop id")
	}
	if strings.TrimSpace(m.BaseLoopID) == "" {
		m.BaseLoopID = m.LoopID
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = time.Now().UTC()
	}
	dir := detectLoopStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create loop state directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure loop state directory: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode loop manifest: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".loop-*.tmp")
	if err != nil {
		return fmt.Errorf("create loop manifest: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod loop manifest: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write loop manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close loop manifest: %w", err)
	}
	if err := os.Rename(tmpName, detectLoopManifestPath(m.BaseLoopID)); err != nil {
		return fmt.Errorf("install loop manifest: %w", err)
	}
	return nil
}

// readDetectLoopManifest resolves a base, current, or attempt id to the base
// manifest written by the loop.
func readDetectLoopManifest(id string) (*detectLoopManifest, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("loop id is required")
	}
	path := detectLoopManifestPath(id)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("loop manifest %s is a symlink", id)
	}
	data, readErr := os.ReadFile(path)
	if readErr == nil {
		var m detectLoopManifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("decode loop manifest %s: %w", id, err)
		}
		return &m, nil
	}
	if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("read loop manifest %s: %w", id, readErr)
	}
	manifests, err := listDetectLoopManifests()
	if err != nil {
		return nil, err
	}
	for _, m := range manifests {
		if strings.EqualFold(m.LoopID, id) || strings.EqualFold(m.BaseLoopID, id) || strings.EqualFold(m.CurrentLoopID, id) {
			return m, nil
		}
	}
	return nil, os.ErrNotExist
}

func listDetectLoopManifests() ([]*detectLoopManifest, error) {
	entries, err := os.ReadDir(detectLoopStateDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read loop state directory: %w", err)
	}
	var manifests []*detectLoopManifest
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(detectLoopStateDir(), entry.Name()))
		if err != nil {
			continue
		}
		var m detectLoopManifest
		if err := json.Unmarshal(data, &m); err != nil || strings.TrimSpace(m.LoopID) == "" {
			continue
		}
		if strings.TrimSpace(m.BaseLoopID) == "" {
			m.BaseLoopID = m.LoopID
		}
		manifests = append(manifests, &m)
	}
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].StartedAt.Equal(manifests[j].StartedAt) {
			return manifests[i].LoopID < manifests[j].LoopID
		}
		return manifests[i].StartedAt.Before(manifests[j].StartedAt)
	})
	return manifests, nil
}

// absoluteLoopPath normalizes a persisted path. A resumed loop runs from a
// new console process, so a relative module or shellcode path would otherwise
// resolve against a different working directory.
func absoluteLoopPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "~" || strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		return path
	}
	if filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func absoluteLoopOptions(opts detectLoopOptions) detectLoopOptions {
	opts.ModuleDir = absoluteLoopPath(opts.ModuleDir)
	opts.Shellcode = absoluteLoopPath(opts.Shellcode)
	opts.AgentArtifact = absoluteLoopPath(opts.AgentArtifact)
	opts.Knowledge = absoluteLoopPath(opts.Knowledge)
	opts.GuestSSHKey = absoluteLoopPath(opts.GuestSSHKey)
	opts.GuestSSHKnownHosts = absoluteLoopPath(opts.GuestSSHKnownHosts)
	for i := range opts.ReadRoots {
		opts.ReadRoots[i] = absoluteLoopPath(opts.ReadRoots[i])
	}
	for i, producer := range opts.Producers {
		if at := strings.IndexByte(producer, '='); at > 0 {
			opts.Producers[i] = producer[:at+1] + absoluteLoopPath(producer[at+1:])
		}
	}
	return opts
}

// saveLoopManifest records the current attempt and status. Existing fields
// such as StartedAt survive an update.
func saveLoopManifest(baseLoopID, currentLoopID string, attempt int, status string, opts detectLoopOptions, run *detectRun) {
	baseLoopID = strings.TrimSpace(baseLoopID)
	if baseLoopID == "" {
		return
	}
	m, err := readDetectLoopManifest(baseLoopID)
	if err != nil || m == nil {
		m = &detectLoopManifest{LoopID: baseLoopID, BaseLoopID: baseLoopID}
	}
	if m.StartedAt.IsZero() && run != nil {
		m.StartedAt = run.started
	}
	if currentLoopID == "" {
		currentLoopID = baseLoopID
	}
	m.CurrentLoopID = currentLoopID
	m.Attempt = attempt
	m.Status = status
	if run != nil {
		m.LogPath = run.logPath
		m.Verified = status == "verified"
		if status == "failed" {
			m.Error = run.info().Error
		} else {
			m.Error = ""
		}
	}
	m.Options = absoluteLoopOptions(opts)
	m.UpdatedAt = time.Now().UTC()
	if err := writeDetectLoopManifest(m); err != nil {
		// Manifest writes are best effort: a failed loop run must still be
		// allowed to finish and print its report.
		return
	}
}

// detectLoopResumable excludes completed loops. A stopped, interrupted, or
// failed loop can continue; a verified or done loop has already spent its
// purpose and needs a new loop id.
func detectLoopResumable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "verified", "done":
		return false
	default:
		return true
	}
}

// onDiskLoopInfos lists manifests and report-only loops that are not in the
// in-memory registry. Report-only rows are visible but not resumable because
// their original options were not persisted.
func onDiskLoopInfos(seen map[string]bool) []detectRunInfo {
	var infos []detectRunInfo
	manifests, _ := listDetectLoopManifests()
	for _, m := range manifests {
		base := strings.TrimSpace(m.BaseLoopID)
		if base == "" {
			base = m.LoopID
		}
		if seen[base] || seen[m.CurrentLoopID] {
			continue
		}
		status := m.Status
		if status == "" {
			status = "on-disk"
		}
		if status == "running" && findDetectRun(base) == nil && findDetectRun(m.CurrentLoopID) == nil {
			status = "interrupted"
		}
		resumable := !m.Verified && detectLoopResumable(status)
		resumeAttempt := 0
		if resumable {
			resumeAttempt = m.Attempt + 1
		}
		infos = append(infos, detectRunInfo{
			LoopID: m.LoopID, CurrentLoopID: m.CurrentLoopID, Attempt: m.Attempt,
			Status: status, StartedAt: m.StartedAt, LogPath: m.LogPath,
			Verified: m.Verified, Error: m.Error, OnDisk: true, Resumable: resumable,
			ResumeAttempt: resumeAttempt,
		})
		seen[base] = true
		seen[m.CurrentLoopID] = true
	}
	// Older loops predate the manifest. Their reports are still useful in
	// list, but resuming them would guess options, so mark them not resumable.
	reportDir := filepath.Join(live.EmpWorkSpace, "detection", "reports")
	entries, _ := os.ReadDir(reportDir)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "loop-") || !strings.HasSuffix(name, ".md") || strings.HasSuffix(name, "-summary.md") {
			continue
		}
		id := strings.TrimSuffix(name, ".md")
		if seen[id] || findDetectRun(id) != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		infos = append(infos, detectRunInfo{
			LoopID: id, Status: "on-disk", StartedAt: info.ModTime(),
			LogPath: "", OnDisk: true, Resumable: false,
		})
		seen[id] = true
	}
	return infos
}
