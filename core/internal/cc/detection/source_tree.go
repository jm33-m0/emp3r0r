package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
)

const (
	defaultSourceTreeDepth   = 2
	maxSourceTreeDepth       = 4
	defaultSourceTreeEntries = 200
	maxSourceTreeEntries     = 1000
)

// sourceTreeTool lists a directory as a bounded, indented tree. It is the
// discovery tool for large roots such as go_agent, where a flat file list is
// thousands of dependency files and no help at all.
func sourceTreeTool(trees *sourceRoots) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceTree",
		Description: "List one source directory as a bounded tree. Defaults to the payload module root, depth 2, and 200 entries. " +
			"Dependency directories (vendor, node_modules, .git) are hidden unless include_vendor is true. " +
			"Use path to descend and depth to control recursion; SourceRead reads a file and SourceSearch searches contents.",
		Prompt: "Map a source root before reading files. Start with depth 2 and a path from the previous listing.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":         map[string]any{"type": "string", "description": "Source root name; default: the payload module."},
				"path":           map[string]any{"type": "string", "description": "Directory relative to the root; default: the root."},
				"depth":          map[string]any{"type": "integer", "description": "Directory levels below path, 1-4. Default 2."},
				"max_entries":    map[string]any{"type": "integer", "description": "Maximum output entries, 1-1000. Default 200."},
				"include_vendor": map[string]any{"type": "boolean", "description": "Show vendor, node_modules, and VCS directories."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module        string `json:"module"`
				Path          string `json:"path"`
				Depth         int    `json:"depth"`
				MaxEntries    int    `json:"max_entries"`
				IncludeVendor bool   `json:"include_vendor"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			root, err := trees.pick(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			dir := root.Dir
			if strings.TrimSpace(args.Path) != "" {
				_, resolved, err := trees.resolve(root.Name, args.Path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("%v", err)), nil
				}
				dir = resolved
			}
			info, err := os.Stat(dir)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("list %s: %v", args.Path, err)), nil
			}
			if !info.IsDir() {
				return tool.Errorf(fmt.Sprintf("%s is a file; use SourceRead", args.Path)), nil
			}
			depth := args.Depth
			if depth <= 0 {
				depth = defaultSourceTreeDepth
			}
			if depth > maxSourceTreeDepth {
				depth = maxSourceTreeDepth
			}
			budget := args.MaxEntries
			if budget <= 0 {
				budget = defaultSourceTreeEntries
			}
			if budget > maxSourceTreeEntries {
				budget = maxSourceTreeEntries
			}
			rel, err := filepath.Rel(root.Dir, dir)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("resolve relative path: %v", err)), nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." {
				rel = "."
			}
			return tool.Text(listSourceTree(root, rel, dir, depth, budget, args.IncludeVendor)), nil
		},
	})
}

func listSourceTree(root sourceRoot, rel, dir string, depth, budget int, includeVendor bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s/%s\n", root.Name, rel)
	lines := 0
	var walk func(path, prefix string, level int)
	walk = func(path, prefix string, level int) {
		if lines >= budget {
			return
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			fmt.Fprintf(&b, "%s[error: %v]\n", prefix, err)
			lines++
			return
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].IsDir() != entries[j].IsDir() {
				return entries[i].IsDir()
			}
			return entries[i].Name() < entries[j].Name()
		})
		for _, entry := range entries {
			if lines >= budget {
				return
			}
			name := entry.Name()
			if entry.IsDir() {
				if skipSourceTreeDir(name, includeVendor) {
					fmt.Fprintf(&b, "%s%s/ (skipped; set include_vendor=true)\n", prefix, name)
					lines++
					continue
				}
				dirs, files := countSourceTreeChildren(filepath.Join(path, name))
				fmt.Fprintf(&b, "%s%s/ (%d dirs, %d files)\n", prefix, name, dirs, files)
				lines++
				if level+1 < depth {
					walk(filepath.Join(path, name), prefix+"  ", level+1)
				}
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				fmt.Fprintf(&b, "%s%s (symlink)\n", prefix, name)
				lines++
				continue
			}
			var size int64
			if info, err := entry.Info(); err == nil {
				size = info.Size()
			}
			fmt.Fprintf(&b, "%s%s (%s)\n", prefix, name, humanSourceSize(size))
			lines++
		}
	}
	walk(dir, "  ", 0)
	if lines >= budget {
		b.WriteString("  ... truncated; narrow with path= or depth=, or raise max_entries ...\n")
	}
	return b.String()
}

func skipSourceTreeDir(name string, includeVendor bool) bool {
	if includeVendor && strings.EqualFold(name, "vendor") {
		return false
	}
	return skipSourceDir(name)
}

func countSourceTreeChildren(dir string) (dirs, files int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if entry.IsDir() {
			dirs++
			continue
		}
		files++
	}
	return dirs, files
}

func humanSourceSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}
