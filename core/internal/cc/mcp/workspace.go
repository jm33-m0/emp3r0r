package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxWorkspaceRead  = 1 << 20
	maxWorkspaceWrite = 1 << 20
	maxWorkspaceList  = 500
	defaultReadSize   = 64 << 10
)

// Workspace confines model file edits to one directory. Paths are relative to
// Root and every component is resolved before use, so a symlink cannot turn a
// source edit into a write outside the workspace.
type Workspace struct {
	root     string
	realRoot string
	mu       sync.Mutex
}

// NewWorkspace creates root when needed and resolves it once. The MCP server
// only serves file tools when this succeeds.
func NewWorkspace(root string) (*Workspace, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("workspace root is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("workspace %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace %s: %w", abs, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace %s: %w", abs, err)
	}
	return &Workspace{root: abs, realRoot: real}, nil
}

// Root returns the configured absolute root.
func (w *Workspace) Root() string { return w.root }

// List returns one directory. It never recurses, so the model chooses the
// traversal and the result stays bounded.
func (w *Workspace) List(rel string) (any, error) {
	path, err := w.resolve(rel, false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", rel, err)
	}
	if len(entries) > maxWorkspaceList {
		entries = entries[:maxWorkspaceList]
	}
	rows := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := entry.Name()
		rows = append(rows, map[string]any{
			"name":     name,
			"path":     filepath.ToSlash(filepath.Join(strings.TrimPrefix(rel, "/"), name)),
			"dir":      entry.IsDir(),
			"size":     info.Size(),
			"mode":     info.Mode().String(),
			"mod_time": info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
	return map[string]any{
		"path":      filepath.ToSlash(strings.TrimPrefix(rel, "/")),
		"entries":   rows,
		"truncated": len(entries) == maxWorkspaceList,
	}, nil
}

// Read returns a bounded text or base64 slice. Binary files are not decoded
// into a lossy string, so an edit cannot silently corrupt them.
func (w *Workspace) Read(rel string, offset, limit int64) (any, error) {
	path, err := w.resolve(rel, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory; use workspace_list", rel)
	}
	if limit <= 0 {
		limit = defaultReadSize
	}
	if limit > maxWorkspaceRead {
		limit = maxWorkspaceRead
	}
	if offset < 0 {
		offset = 0
	}
	if offset > info.Size() {
		offset = info.Size()
	}
	f, err := openRead(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", rel, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	truncated := offset+int64(len(data)) < info.Size()
	if utf8.Valid(data) {
		return map[string]any{
			"path":      filepath.ToSlash(rel),
			"size":      info.Size(),
			"offset":    offset,
			"truncated": truncated,
			"encoding":  "utf-8",
			"content":   string(data),
		}, nil
	}
	return map[string]any{
		"path":      filepath.ToSlash(rel),
		"size":      info.Size(),
		"offset":    offset,
		"truncated": truncated,
		"encoding":  "base64",
		"content":   base64.StdEncoding.EncodeToString(data),
	}, nil
}

// Write replaces or creates one file atomically. It refuses symlinks and
// hardlinks: either can point outside the workspace even though the path looks
// contained.
func (w *Workspace) Write(rel, content string) (any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(content) > maxWorkspaceWrite {
		return nil, fmt.Errorf("content is %d bytes, above the %d-byte limit", len(content), maxWorkspaceWrite)
	}
	path, err := w.resolve(rel, true)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", rel)
	}
	mode := os.FileMode(0o600)
	if info, err := os.Lstat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := atomicWrite(path, []byte(content), mode); err != nil {
		return nil, fmt.Errorf("write %s: %w", rel, err)
	}
	return fileResult(rel, content), nil
}

// Edit applies an exact replacement. A non-unique old string is rejected
// unless replace_all is set, so an edit cannot fan out unexpectedly.
func (w *Workspace) Edit(rel, old, replacement string, replaceAll bool) (any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if old == "" {
		return nil, fmt.Errorf("old_string is empty")
	}
	path, err := w.resolve(rel, true)
	if err != nil {
		return nil, err
	}
	f, err := openRead(path)
	if err != nil {
		return nil, fmt.Errorf("edit %s: %w", rel, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWorkspaceWrite+1))
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("edit %s: %w", rel, err)
	}
	if len(data) > maxWorkspaceWrite {
		return nil, fmt.Errorf("%s is larger than %d bytes", rel, maxWorkspaceWrite)
	}
	text := string(data)
	count := strings.Count(text, old)
	if count == 0 {
		return nil, fmt.Errorf("old_string not found in %s", rel)
	}
	if count > 1 && !replaceAll {
		return nil, fmt.Errorf("old_string occurs %d times in %s; add surrounding context or set replace_all", count, rel)
	}
	next := strings.ReplaceAll(text, old, replacement)
	if len(next) > maxWorkspaceWrite {
		return nil, fmt.Errorf("result is larger than %d bytes", maxWorkspaceWrite)
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := atomicWrite(path, []byte(next), mode); err != nil {
		return nil, fmt.Errorf("edit %s: %w", rel, err)
	}
	result := fileResult(rel, next)
	result["replacements"] = count
	return result, nil
}

func fileResult(rel, content string) map[string]any {
	sum := sha256.Sum256([]byte(content))
	return map[string]any{
		"path":   filepath.ToSlash(rel),
		"bytes":  len(content),
		"sha256": hex.EncodeToString(sum[:]),
	}
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// resolve returns an absolute path inside the workspace. It rejects absolute
// paths, traversal, symlinks, and hardlinked existing files on writes.
func (w *Workspace) resolve(rel string, write bool) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" || rel == "." {
		return w.root, nil
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path must be relative to the workspace")
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes the workspace")
	}
	full := filepath.Join(w.root, clean)
	if !within(w.root, full) {
		return "", fmt.Errorf("path escapes the workspace")
	}
	if forbiddenPath(full) {
		return "", fmt.Errorf("%s is not readable or writable through the workspace", rel)
	}

	real, err := evalExisting(full)
	if err != nil {
		return "", err
	}
	if !within(w.realRoot, real) {
		return "", fmt.Errorf("path resolves outside the workspace")
	}
	if forbiddenPath(real) {
		return "", fmt.Errorf("%s resolves to a protected path", rel)
	}
	if write {
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return "", fmt.Errorf("create parent of %s: %w", rel, err)
		}
	}
	if info, err := os.Lstat(full); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s is a symlink", rel)
		}
		if info.Mode().IsRegular() && hasMultipleLinks(info) {
			return "", fmt.Errorf("%s has multiple hardlinks", rel)
		}
	}
	return full, nil
}

func forbiddenPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "assistant.json", "mcp.json", "mcp_audit.log", "emp3r0r.log",
		"operator_audit.log", "wg_config.json", "emp3r0r.json",
		"id_rsa", "id_ed25519", ".env", "magic_string", "emp3r0r.history":
		return true
	}
	if strings.HasPrefix(base, "stub-") {
		return true
	}
	if strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") ||
		strings.HasSuffix(base, ".crt") || strings.HasSuffix(base, ".log") {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case ".git", ".ssh", ".gnupg", ".omp", ".module-toolchain":
			return true
		}
	}
	return false
}

func within(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}

// evalExisting resolves symlinks for the longest existing ancestor and
// reattaches the missing suffix.
func evalExisting(path string) (string, error) {
	var missing []string
	current := path
	for {
		if _, err := os.Lstat(current); err == nil {
			real, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", current, err)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return real, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("cannot resolve %s", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
