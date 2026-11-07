package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
)

// Toolset merges the read-only assistant tools with the screened action tools.
// Definitions and Lookup remain deterministic and name-sorted.
type Toolset struct {
	base    ToolSet
	actions map[string]assistant.Tool
}

// NewToolset combines base with the action tools. A nil base is allowed for
// tests; a nil Actions exposes only the base.
func NewToolset(base ToolSet, actions *Actions) *Toolset {
	t := &Toolset{base: base}
	if actions != nil {
		t.actions = actions.Tools()
	}
	return t
}

// Definitions returns both tool sets in name order. An action replaces a base
// definition with the same name, matching Lookup's precedence.
func (t *Toolset) Definitions() []assistant.ToolDef {
	byName := make(map[string]assistant.ToolDef)
	if t.base != nil {
		for _, def := range t.base.Definitions() {
			byName[def.Function.Name] = def
		}
	}
	for _, tool := range t.actions {
		byName[tool.Def.Function.Name] = tool.Def
	}
	defs := make([]assistant.ToolDef, 0, len(byName))
	for _, def := range byName {
		defs = append(defs, def)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Function.Name < defs[j].Function.Name })
	return defs
}

// Lookup returns one tool, preferring an action on a name collision.
func (t *Toolset) Lookup(name string) (assistant.Tool, bool) {
	if tool, ok := t.actions[name]; ok {
		return tool, true
	}
	if t.base != nil {
		return t.base.Lookup(name)
	}
	return assistant.Tool{}, false
}

// Call runs one tool.
func (t *Toolset) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := t.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	return tool.Run(ctx, args)
}
