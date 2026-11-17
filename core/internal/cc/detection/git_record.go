package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	gitMaxOutput  = 64 << 10
	gitMaxLogRows = 50
)

var gitCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// gitRecorder keeps a shadow repository for every writable source root. The
// repositories live under the detection store, so the module's own checkout
// (and the operator's repository) is never touched. It uses go-git directly:
// no git binary, hooks, user config, or shell invocation.
type gitRecorder struct {
	baseDir string
	roots   []sourceRoot
	logf    func(logging.Class, string, ...any)
}

func newGitRecorder(storeRoot, baseLoopID string, roots *sourceRoots, logf func(logging.Class, string, ...any)) (*gitRecorder, error) {
	if roots == nil {
		return nil, fmt.Errorf("source roots are required for git versioning")
	}
	baseDir := filepath.Join(storeRoot, "git", sanitizeName(baseLoopID))
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create git directory: %w", err)
	}
	var writable []sourceRoot
	for _, name := range roots.names {
		root, ok := roots.roots[name]
		if !ok || !root.Writable {
			continue
		}
		writable = append(writable, root)
	}
	sort.Slice(writable, func(i, j int) bool { return writable[i].Name < writable[j].Name })
	if len(writable) == 0 {
		return nil, fmt.Errorf("no writable source root to version")
	}
	return &gitRecorder{baseDir: baseDir, roots: writable, logf: logf}, nil
}

// workTree is the shadow copy that go-git commits. The real module tree is
// never modified and never contains a nested repository.
func (g *gitRecorder) workTree(root sourceRoot) string {
	return filepath.Join(g.baseDir, root.Name)
}

// Init creates each shadow repository, mirrors the source tree, and records
// the baseline commit.
func (g *gitRecorder) Init(ctx context.Context) error {
	for _, root := range g.roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir := g.workTree(root)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create git work tree %s: %w", root.Name, err)
		}
		if _, err := git.PlainOpen(dir); errors.Is(err, git.ErrRepositoryNotExists) {
			if _, err := git.PlainInit(dir, false); err != nil {
				return fmt.Errorf("init git %s: %w", root.Name, err)
			}
		} else if err != nil {
			return fmt.Errorf("open git %s: %w", root.Name, err)
		}
		head, err := g.Commit(ctx, root, "baseline")
		if err != nil {
			return fmt.Errorf("git baseline %s: %w", root.Name, err)
		}
		g.log(logging.ClassLine, "git %s: %s (baseline %s)", root.Name, dir, shortSHA(head))
	}
	return nil
}

// Commit mirrors the current source into the shadow tree and commits when it
// differs from HEAD. Only source-like files are copied, so build outputs never
// enter the history.
func (g *gitRecorder) Commit(ctx context.Context, root sourceRoot, message string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	dir := g.workTree(root)
	if err := syncSourceTree(root.Dir, dir); err != nil {
		return "", fmt.Errorf("sync %s: %w", root.Name, err)
	}
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return "", fmt.Errorf("open git %s: %w", root.Name, err)
	}
	head, headErr := repo.Head()
	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("work tree %s: %w", root.Name, err)
	}
	status, err := worktree.Status()
	if err != nil {
		return "", fmt.Errorf("status %s: %w", root.Name, err)
	}
	if status.IsClean() {
		if headErr != nil {
			return "", nil
		}
		return head.Hash().String(), nil
	}
	if err := worktree.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		return "", fmt.Errorf("stage %s: %w", root.Name, err)
	}
	msg := clip(sanitize.SanitizeOneLine(message), 240)
	if msg == "" {
		msg = "cycle"
	}
	commit, err := worktree.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name: "detect-loop", Email: "detect-loop@localhost", When: time.Now(),
		},
	})
	if err != nil {
		if errors.Is(err, git.ErrEmptyCommit) && headErr == nil {
			return head.Hash().String(), nil
		}
		return "", fmt.Errorf("commit %s: %w", root.Name, err)
	}
	return commit.String(), nil
}

// CommitAll records every writable root and returns root -> commit.
func (g *gitRecorder) CommitAll(ctx context.Context, message string) (map[string]string, error) {
	out := make(map[string]string, len(g.roots))
	for _, root := range g.roots {
		commit, err := g.Commit(ctx, root, message+": "+root.Name)
		if err != nil {
			return out, fmt.Errorf("%s: %w", root.Name, err)
		}
		out[root.Name] = commit
	}
	return out, nil
}

// Log returns a bounded commit history for one root.
func (g *gitRecorder) Log(ctx context.Context, root sourceRoot, limit int) (string, error) {
	if limit <= 0 || limit > gitMaxLogRows {
		limit = 10
	}
	repo, err := git.PlainOpen(g.workTree(root))
	if err != nil {
		return "", fmt.Errorf("open git %s: %w", root.Name, err)
	}
	head, err := repo.Head()
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return "no commits recorded", nil
		}
		return "", fmt.Errorf("head %s: %w", root.Name, err)
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return "", fmt.Errorf("log %s: %w", root.Name, err)
	}
	defer iter.Close()
	var b strings.Builder
	for n := 0; n < limit; n++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		commit, err := iter.Next()
		if err != nil {
			break
		}
		writeCommitSummary(&b, commit)
	}
	if b.Len() == 0 {
		return "no commits recorded", nil
	}
	return clip(b.String(), gitMaxOutput), nil
}

// Show returns one commit's message and changed-file stats.
func (g *gitRecorder) Show(ctx context.Context, root sourceRoot, commit string) (string, error) {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !gitCommitPattern.MatchString(commit) {
		return "", fmt.Errorf("commit must be a full 40-character hex object name")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	repo, err := git.PlainOpen(g.workTree(root))
	if err != nil {
		return "", fmt.Errorf("open git %s: %w", root.Name, err)
	}
	objectCommit, err := repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return "", fmt.Errorf("commit %s: %w", commit, err)
	}
	var b strings.Builder
	writeCommitSummary(&b, objectCommit)
	return clip(b.String(), gitMaxOutput), nil
}

func writeCommitSummary(b *strings.Builder, commit *object.Commit) {
	subject := strings.TrimSpace(strings.SplitN(commit.Message, "\n", 2)[0])
	fmt.Fprintf(b, "%s %s\n", commit.Hash.String(), subject)
	stats, err := commit.Stats()
	if err != nil {
		return
	}
	for _, stat := range stats {
		fmt.Fprintf(b, "  %s (+%d -%d)\n", stat.Name, stat.Addition, stat.Deletion)
	}
}

func (g *gitRecorder) rootByName(name string) (sourceRoot, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, root := range g.roots {
		if root.Name == name {
			return root, nil
		}
	}
	names := make([]string, 0, len(g.roots))
	for _, root := range g.roots {
		names = append(names, root.Name)
	}
	return sourceRoot{}, fmt.Errorf("root %q is not versioned; available: %s", name, strings.Join(names, ", "))
}

func (g *gitRecorder) log(class logging.Class, format string, args ...any) {
	if g.logf != nil {
		g.logf(class, format, args...)
	}
}

// syncSourceTree replaces the shadow work tree contents (except .git) with a
// copy of the current source files.
func syncSourceTree(sourceDir, destDir string) error {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(destDir, entry.Name())); err != nil {
			return err
		}
	}
	files, err := collectSourceFiles(sourceDir)
	if err != nil {
		return err
	}
	for _, rel := range files {
		src := filepath.Join(sourceDir, filepath.FromSlash(rel))
		dst := filepath.Join(destDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		info, err := os.Stat(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// collectSourceFiles lists the files walkSourceFiles would hash.
func collectSourceFiles(dir string) ([]string, error) {
	var files []string
	err := walkSourceFiles(dir, func(rel, _ string) error {
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// gitHistoryTool exposes the commit record to the workers. It is read-only and
// accepts only a versioned root, a row limit, and an object name.
func (e *evolver) gitHistoryTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "GitHistory",
		Description: "Read the loop's source-versioning record. Without commit, return the most recent commit messages " +
			"and changed files for a versioned root. With commit, return that commit's message and file stats. Use it " +
			"to see what earlier cycles actually changed when the SQLite edit summary is not enough.",
		Prompt: "Inspect the source commit history.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"root":   map[string]any{"type": "string", "description": "Versioned source root; defaults to the payload module."},
				"limit":  map[string]any{"type": "integer", "description": "Commit rows, default 10, at most 50."},
				"commit": map[string]any{"type": "string", "description": "Full 40-character hex commit object name to show."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Root   string `json:"root"`
				Limit  int    `json:"limit"`
				Commit string `json:"commit"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.git == nil {
				return tool.Errorf("git versioning is disabled for this loop"), nil
			}
			rootName := strings.TrimSpace(args.Root)
			if rootName == "" {
				rootName = e.cfg.Module
			}
			root, err := e.git.rootByName(rootName)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			var out string
			if strings.TrimSpace(args.Commit) != "" {
				out, err = e.git.Show(ctx, root, args.Commit)
			} else {
				out, err = e.git.Log(ctx, root, args.Limit)
			}
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			return tool.Text(out), nil
		},
	})
}
