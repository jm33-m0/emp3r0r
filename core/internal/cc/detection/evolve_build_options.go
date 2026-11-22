package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
)

// Build options are module parameters consumed by the build script. They are
// part of the payload design, not harness knobs: the loader's inject path,
// container, sacrificial process, and call-stack spoofing, and a producer's
// wrapper or linker transforms all come from this surface. The state is kept in
// sync.Map because an editor tool goroutine may read it while another tool
// writes it; a snapshot is an immutable copy.
const (
	buildOptionOutput = "output"
	buildOptionArch   = "arch"
)

// optionView is one declared build option and its effective value.
type optionView struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Default     string   `json:"default,omitempty"`
	Choices     []string `json:"choices,omitempty"`
	Description string   `json:"description,omitempty"`
	Origin      string   `json:"origin"`
	HostManaged bool     `json:"host_managed,omitempty"`
}

// initialBuildOptions copies the operator-supplied loader overrides. Empty
// values are omitted so the module's own default applies.
func initialBuildOptions(cfg EvolveConfig) map[string]string {
	out := map[string]string{}
	for name, value := range map[string]string{
		"format":  cfg.Format,
		"smw":     cfg.SMW,
		"inject":  cfg.Inject,
		"process": cfg.Process,
	} {
		if strings.TrimSpace(value) != "" {
			out[name] = strings.TrimSpace(value)
		}
	}
	return out
}

func (e *evolver) initBuildOptions(opts map[string]string) {
	for name, value := range opts {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "shellcode", "output", "arch":
			continue
		}
		e.buildOpts.Store(strings.ToLower(name), value)
	}
}

// payloadBuildFlags layers the model-chosen options over the host-owned
// shellcode, arch, and output values. Host values win so a restored or
// malformed option map cannot redirect a build.
func (e *evolver) payloadBuildFlags(shellcode string, iteration int) map[string]string {
	flags := map[string]string{}
	declared, _ := moduleOptions(e.cfg.ModuleDir, e.cfg.Module)
	for name, value := range e.buildOptionsSnapshot() {
		if strings.TrimSpace(value) == "" {
			continue
		}
		key := strings.ToLower(name)
		switch key {
		case "shellcode", "output", "arch", "agent-pic":
			continue
		}
		// A resumed loop can carry options from a different payload design.
		// Never pass an option the module does not declare.
		if declared != nil {
			if opt, ok := declared[key]; !ok || opt == nil {
				continue
			}
		}
		flags[key] = value
	}
	if e.platform() == platformLinux {
		flags["agent-pic"] = shellcode
		// The Linux detonation container executes an ELF; the stager's raw and
		// packed formats are shellcode for a loader that this loop does not
		// build, and a shared object has no entry point. The model can change
		// stager source and build options, not the artifact contract the
		// sandbox needs to run it.
		flags["format"] = "executable"
		return flags
	}
	flags["shellcode"] = shellcode
	flags["arch"] = "x64"
	if e.cfg.StoreRoot != "" && strings.EqualFold(e.cfg.Module, "loader_windows") {
		format := flags["format"]
		if strings.TrimSpace(format) == "" {
			format = e.cfg.Format
		}
		flags[buildOptionOutput] = e.detonationArtifactPath(iteration, format)
	}
	return flags
}

// detonationArtifactPath returns the host-owned output path for a loader
// build. The module derives its default name from the shellcode basename, and
// the first cycle's shellcode carries the full agent artifact name. RedEdr's
// kernel driver rejects target filenames of 128 wide characters or more, and
// LitterBox prefixes the uploaded file with a 32-character digest, so that
// default name silently disables kernel and hook telemetry for the baseline
// only. The loop supplies a short, per-cycle name instead.
func (e *evolver) detonationArtifactPath(iteration int, format string) string {
	ext := ".exe"
	if strings.EqualFold(strings.TrimSpace(format), "dll") {
		ext = ".dll"
	}
	root := e.cfg.StoreRoot
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", e.cfg.LoopID, e.attempt)))
	dir := filepath.Join(root, "artifacts", sanitizeName(e.cfg.Module))
	return filepath.Join(dir, fmt.Sprintf("sc-%s-%d%s", hex.EncodeToString(sum[:3]), iteration, ext))
}

func (e *evolver) buildOptionsSnapshot() map[string]string {
	out := map[string]string{}
	e.buildOpts.Range(func(key, value any) bool {
		name, _ := key.(string)
		text, _ := value.(string)
		if name != "" {
			out[name] = text
		}
		return true
	})
	return out
}

func (e *evolver) replaceBuildOptions(opts map[string]string) {
	e.buildOpts.Clear()
	e.initBuildOptions(opts)
}

func producerOptionKey(producer, name string) string {
	return strings.ToLower(strings.TrimSpace(producer)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
}

func (e *evolver) producerOptionsSnapshot(producer string) map[string]string {
	producer = strings.ToLower(strings.TrimSpace(producer))
	out := map[string]string{}
	if producer == "" {
		return out
	}
	prefix := producer + "\x00"
	e.producerOpts.Range(func(key, value any) bool {
		text, _ := key.(string)
		if strings.HasPrefix(text, prefix) {
			if item, ok := value.(string); ok {
				out[strings.TrimPrefix(text, prefix)] = item
			}
		}
		return true
	})
	return out
}

func (e *evolver) replaceProducerOptions(producer string, opts map[string]string) {
	producer = strings.ToLower(strings.TrimSpace(producer))
	if producer == "" {
		return
	}
	prefix := producer + "\x00"
	e.producerOpts.Range(func(key, _ any) bool {
		if text, _ := key.(string); strings.HasPrefix(text, prefix) {
			e.producerOpts.Delete(key)
		}
		return true
	})
	for name, value := range opts {
		e.producerOpts.Store(producerOptionKey(producer, name), value)
	}
}

func (e *evolver) activeProducerOptions() map[string]string {
	return e.producerOptionsSnapshot(e.activeProducer)
}

// mergeProducerOptions layers a per-call option set over the values the active
// producer already uses, so an agent rotation rebuilds the same wrapper.
func (e *evolver) mergeProducerOptions(producer string, supplied map[string]string) map[string]string {
	merged := e.producerOptionsSnapshot(producer)
	for name, value := range supplied {
		merged[name] = value
	}
	return merged
}

// rememberProducerOptions stores the non-path options of a successful build.
// The host fills the input and output paths on every build, so they must not be
// replayed from a previous agent.
func (e *evolver) rememberProducerOptions(producer string, flags map[string]string, inputName string) {
	stored := make(map[string]string, len(flags))
	for name, value := range flags {
		name = strings.ToLower(name)
		if name == buildOptionOutput || name == inputName || name == "input" || name == "dll" {
			continue
		}
		stored[name] = value
	}
	e.replaceProducerOptions(producer, stored)
}

// moduleOptions reads the declared parameters for one module from its
// config.json. The source root already points at the directory the loop builds.
func moduleOptions(dir, name string) (def.ModOptions, error) {
	configs, err := modconfig.ReadConfigs(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("read %s module config: %w", name, err)
	}
	for _, config := range configs {
		if config != nil && strings.EqualFold(config.Name, name) {
			return config.Options, nil
		}
	}
	return nil, fmt.Errorf("%s is not defined in %s/config.json", name, dir)
}

// hostOwnedBuildOption reports options the loop fills on every build. They are
// visible for discovery but cannot be overridden by the model.
func (e *evolver) hostOwnedBuildOption(module string, declared def.ModOptions, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == buildOptionOutput {
		return true
	}
	if strings.EqualFold(module, e.cfg.Module) {
		if e.platform() == platformLinux {
			return name == "shellcode" || name == "agent-pic" || name == "format" || name == buildOptionArch
		}
		return name == "shellcode" || name == buildOptionArch
	}
	input, err := producerInputName(module, declared)
	return err == nil && name == input
}

func (e *evolver) summaryBuildOptions(summary *cycleSummary) {
	if summary == nil {
		return
	}
	if summary.BuildOptions != nil {
		e.replaceBuildOptions(summary.BuildOptions)
	}
	if producer := strings.TrimSpace(summary.Producer); producer != "" && summary.ProducerOptions != nil {
		// The host fills the input and output paths on every build. A stored
		// copy must never point a rotation at a superseded agent or artifact.
		opts := make(map[string]string, len(summary.ProducerOptions))
		for name, value := range summary.ProducerOptions {
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "input", "dll", "output":
				continue
			}
			opts[name] = value
		}
		e.replaceProducerOptions(producer, opts)
	}
}

// buildOptionsChangedFrom reports whether the current build state differs from
// the options recorded by a cycle. A nil field means the cycle predates option
// recording, so it is not compared.
func (e *evolver) buildOptionsChangedFrom(summary cycleSummary) bool {
	if summary.BuildOptions != nil && !mapsEqual(e.buildOptionsSnapshot(), summary.BuildOptions) {
		return true
	}
	if summary.ProducerOptions != nil {
		producer := strings.TrimSpace(summary.Producer)
		if producer == "" {
			producer = e.activeProducer
		}
		if !mapsEqual(e.producerOptionsSnapshot(producer), summary.ProducerOptions) {
			return true
		}
	}
	return false
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if other, ok := right[key]; !ok || other != value {
			return false
		}
	}
	return true
}

func formatBuildOptions(opts map[string]string) string {
	if len(opts) == 0 {
		return "module defaults"
	}
	names := make([]string, 0, len(opts))
	for name := range opts {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		value := strings.TrimSpace(opts[name])
		if value == "" {
			value = `""`
		}
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, " ")
}

// buildOptionChoiceBrief lists the enumerated payload build options so the
// planner can name a value without a read tool.
func (e *evolver) buildOptionChoiceBrief() string {
	declared, err := moduleOptions(e.cfg.ModuleDir, e.cfg.Module)
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(declared))
	for name, opt := range declared {
		if opt == nil || opt.Internal || len(opt.Vals) == 0 {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+strings.Join(declared[name].Vals, "|"))
	}
	return strings.Join(parts, "; ")
}

func clipOptionText(text string, limit int) string {
	text = strings.TrimSpace(sanitizeLine(text))
	if limit > 0 && len(text) > limit {
		text = text[:limit] + "…"
	}
	return text
}

// buildOptionsTool exposes and changes the build options for the payload
// module and the configured producers. A change here is a design change: it is
// recorded in the cycle summary, counted as a change by DetectionCycle, and
// restored with the last executing payload.
func (e *evolver) buildOptionsTool() tool.CoreTool {
	description := "List or change build options for the next build. Options are the parameters declared in the module's config.json; " +
		"unknown names, invalid choices, and host-filled values are rejected. loader_windows options change the host container, " +
		"injection path, sacrificial process, and call-stack spoofing; producer options change the wrapper, for example Crystal Palace " +
		"link options. Call with no options to list effective values and choices. `reset` removes an override so the module's own " +
		"default applies. A build-option change is a valid change for DetectionCycle and is recorded and restored per cycle."
	moduleDescription := "Writable source root: the payload module (default), donut, or crystal_pack."
	if e.platform() == platformLinux {
		description = "List or change stager_linux build options. The module's config.json declares transport, unpacker, sleep mask, " +
			"dynload mode, hash style, ECH, and supervision. format and agent-pic are host-owned: PenguinBox executes an ELF and the host " +
			"embeds the generated C agent PIC. Call with no options to list effective values and choices; `reset` restores one default. " +
			"A build-option change is a valid change for DetectionCycle and is recorded and restored per cycle."
		moduleDescription = "Writable source root: the payload module (default) or malasada."
	}
	return tool.Build(tool.Spec{
		Name:        "BuildOptions",
		Description: description,
		Prompt:      "List or change build options.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module": map[string]any{
					"type":        "string",
					"description": moduleDescription,
				},
				"options": map[string]any{
					"type":                 "object",
					"description":          "Build options to set for the next build; values are strings.",
					"additionalProperties": map[string]any{"type": "string"},
				},
				"reset": map[string]any{
					"type":        "array",
					"description": "Option names to remove so the module's own default applies.",
					"items":       map[string]any{"type": "string"},
				},
			},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module  string            `json:"module"`
				Options map[string]string `json:"options"`
				Reset   []string          `json:"reset"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			moduleName := strings.ToLower(strings.TrimSpace(args.Module))
			if moduleName == "" {
				moduleName = e.cfg.Module
			}
			root, err := e.root(moduleName)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if !root.Writable {
				return tool.Errorf(fmt.Sprintf("source root %s is read-only", root.Name)), nil
			}
			declared, err := moduleOptions(root.Dir, moduleName)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			isProducer := !strings.EqualFold(moduleName, e.cfg.Module)
			current := e.buildOptionsSnapshot()
			origin := "override"
			if isProducer {
				current = e.producerOptionsSnapshot(moduleName)
			}

			changed := false
			for name, value := range args.Options {
				name = strings.ToLower(strings.TrimSpace(name))
				opt, ok := declared[name]
				if !ok || opt == nil {
					return tool.Errorf(fmt.Sprintf("%s has no build option %q; available: %s",
						moduleName, name, producerOptionNames(declared))), nil
				}
				if opt.Internal {
					return tool.Errorf(fmt.Sprintf("%s option %q is filled in by the C2", moduleName, name)), nil
				}
				if e.hostOwnedBuildOption(moduleName, declared, name) {
					return tool.Errorf(fmt.Sprintf("%s option %q is filled in by the host", moduleName, name)), nil
				}
				value = strings.TrimSpace(value)
				if err := modconfig.ValidateOption(opt, value); err != nil {
					return tool.Errorf(fmt.Sprintf("%s option %q: %v", moduleName, name, err)), nil
				}
				if value == "" {
					if isProducer {
						e.producerOpts.Delete(producerOptionKey(moduleName, name))
					} else {
						e.buildOpts.Delete(name)
					}
					delete(current, name)
				} else {
					if isProducer {
						e.producerOpts.Store(producerOptionKey(moduleName, name), value)
					} else {
						e.buildOpts.Store(name, value)
					}
					current[name] = value
				}
				changed = true
			}
			for _, name := range args.Reset {
				name = strings.ToLower(strings.TrimSpace(name))
				if _, ok := declared[name]; !ok {
					return tool.Errorf(fmt.Sprintf("%s has no build option %q; available: %s",
						moduleName, name, producerOptionNames(declared))), nil
				}
				if isProducer {
					e.producerOpts.Delete(producerOptionKey(moduleName, name))
				} else {
					e.buildOpts.Delete(name)
				}
				delete(current, name)
				changed = true
			}

			views := make([]optionView, 0, len(declared))
			hostManaged := make([]string, 0, 3)
			names := make([]string, 0, len(declared))
			for name := range declared {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				opt := declared[name]
				if opt == nil || opt.Internal {
					continue
				}
				view := optionView{
					Name:        name,
					Default:     clipOptionText(opt.Val, 300),
					Choices:     opt.Vals,
					Description: clipOptionText(opt.Desc, 300),
					Origin:      origin,
				}
				if value, ok := current[name]; ok {
					view.Value = clipOptionText(value, 300)
				} else {
					view.Value = view.Default
					view.Origin = "module-default"
				}
				if e.hostOwnedBuildOption(moduleName, declared, name) {
					view.HostManaged = true
					view.Origin = "host"
					hostManaged = append(hostManaged, name)
				}
				views = append(views, view)
			}

			message := "these are the build options the next DetectionCycle uses"
			if changed {
				e.logClass(logging.ClassEdit, "build options %s: %s", moduleName, formatBuildOptions(current))
				message = "build options applied; the next DetectionCycle uses them, and an execution-gate restore returns to the last executing values"
			}
			out := map[string]any{
				"module":       moduleName,
				"options":      current,
				"available":    views,
				"host_managed": hostManaged,
				"message":      message,
			}
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}
