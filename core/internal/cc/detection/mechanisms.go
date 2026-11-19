package detection

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
)

// mechanismSpec is the harness-side operational contract for one loading
// mechanism. The model chooses a mechanism; the host supplies what that choice
// changes, what it can and cannot fix, and how to verify it. This keeps the
// model from inferring module internals from telemetry alone.
type mechanismSpec struct {
	Name         string
	Layer        string
	Summary      string
	Constraints  []string
	Signals      []string
	Verification string
}

var mechanismSpecs = map[string]mechanismSpec{
	"self-load": {
		Name: "self-load", Layer: "loader",
		Summary: "The loader runs the payload in its own process; no child process or injection.",
		Constraints: []string{
			"Execution proof is the loader process reaching the payload and the agent checking in.",
			"A loader that exits before calling the payload is a loader bug, not a producer bug.",
			"Do not change the producer to fix a loader-side exit.",
		},
		Signals:      []string{"process creation", "loader exit status", "payload mapping/protect", "network/check-in"},
		Verification: "the expected agent UUID checks in and the trace shows a mapping/protect of the payload",
	},
	"section-map": {
		Name: "section-map", Layer: "loader",
		Summary: "Map the payload as a file/section view instead of a private allocation.",
		Constraints: []string{
			"The loader must keep a valid backing image; a malformed PE or missing relocation makes the section map fail.",
			"Fall back to the verified path when the image map fails; do not silently skip the payload.",
		},
		Signals:      []string{"NtCreateSection/NtMapViewOfSection", "image-backed vs private memory", "network/check-in"},
		Verification: "the payload runs from an image view, the private executable region disappears, and the agent checks in",
	},
	"module-stomp": {
		Name: "module-stomp", Layer: "loader",
		Summary: "Place the payload in the executable tail of a mapped signed image.",
		Constraints: []string{
			"The host image must be mapped and large enough for the payload.",
			"The payload entry and protection must be valid for the image layout.",
		},
		Signals:      []string{"image load", "section tail write", "protection change", "network/check-in"},
		Verification: "the payload executes from an image-backed region and the agent checks in",
	},
	"pe-image": {
		Name: "pe-image", Layer: "loader",
		Summary: "Map the payload as a PE image (SEC_IMAGE) and enter its entry point.",
		Constraints: []string{
			"The source must be a valid PE with a usable entry point and relocations.",
			"A minimal image without relocations must not advertise DYNAMIC_BASE.",
		},
		Signals:      []string{"image load", "relocation/entry", "network/check-in"},
		Verification: "the image maps, the entry runs, and the agent checks in",
	},
	"remote-apc": {
		Name: "remote-apc", Layer: "loader",
		Summary: "Early-bird QueueUserAPC into a parked sacrificial process.",
		Constraints: []string{
			"The sacrificial process must start suspended and stay alive long enough.",
			"The APC entry must preserve alignment and park the thread after the payload.",
		},
		Signals:      []string{"child process", "remote thread/APC", "network/check-in"},
		Verification: "the child process runs the payload and the expected agent checks in",
	},
	"remote-thread": {
		Name: "remote-thread", Layer: "loader",
		Summary: "CreateRemoteThread in a sacrificial process.",
		Constraints: []string{
			"The sacrificial process must stay alive; pair this with a long-lived host.",
			"The remote entry must be valid at the chosen base.",
		},
		Signals:      []string{"child process", "remote thread", "network/check-in"},
		Verification: "the remote thread runs the payload and the agent checks in",
	},
	"producer": {
		Name: "producer", Layer: "producer",
		Summary: "Change the shellcode producer's source and rebuild the artifact.",
		Constraints: []string{
			"The producer must stay compatible with the active agent type.",
			"Rebuild and inspect the generated artifact before the cycle.",
			"Producer edits cannot fix a loader that never reaches the producer artifact.",
		},
		Signals:      []string{"build log", "artifact type/size", "payload mapping", "network/check-in"},
		Verification: "the new artifact is the active shellcode and the agent checks in",
	},
	"producer-swap": {
		Name: "producer-swap", Layer: "producer",
		Summary: "Switch to a different shellcode producer and regenerate the agent for its input type.",
		Constraints: []string{
			"GenerateAgent for the new producer's required agent type first.",
			"BuildShellcode with the new producer and its declared input option.",
			"The swap is not a source edit of the old producer.",
		},
		Signals:      []string{"agent type", "producer input option", "active shellcode", "network/check-in"},
		Verification: "the new producer's artifact is active and the expected agent checks in",
	},
	"static-hygiene": {
		Name: "static-hygiene", Layer: "hygiene",
		Summary: "Remove strings, imports, section names, or other static surface.",
		Constraints: []string{
			"Static hygiene does not change the loading path and cannot fix dynamic execution failures.",
			"Do not add literals or code to chase an entropy finding; that adds new static findings.",
		},
		Signals:      []string{"static analyzers", "section entropy", "imports/strings"},
		Verification: "the targeted static finding disappears without a new high finding or an execution regression",
	},
	"other": {
		Name: "other", Layer: "other",
		Summary: "A mechanism not covered by the catalog.",
		Constraints: []string{
			"Name the concrete loading path and the component it changes.",
			"State one falsifiable prediction and the telemetry that would show it.",
		},
		Signals:      []string{"state the expected telemetry"},
		Verification: "state the exact observed result that would confirm the prediction",
	},
}

func mechanismNames() []string {
	names := make([]string, 0, len(mechanismSpecs))
	for name := range mechanismSpecs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func normalizeMechanism(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if _, ok := mechanismSpecs[name]; ok {
		return name
	}
	return "other"
}

// mechanismSpecFor returns the catalog entry, specialized with the active
// producer's declared input option and agent type when the mechanism touches a
// producer. The specialization comes from the module's config.json, not from a
// hardcoded module list.
func (e *evolver) mechanismSpecFor(name string) mechanismSpec {
	spec := mechanismSpecs[normalizeMechanism(name)]
	if spec.Name != "producer" && spec.Name != "producer-swap" {
		return spec
	}
	producer := strings.ToLower(strings.TrimSpace(e.activeProducer))
	dir := strings.TrimSpace(e.cfg.ProducerDirs[producer])
	if producer == "" || dir == "" {
		return spec
	}
	configs, err := modconfig.ReadConfigs(filepath.Join(dir, "config.json"))
	if err != nil {
		return spec
	}
	var declared def.ModOptions
	for _, config := range configs {
		if config != nil && strings.EqualFold(config.Name, producer) {
			declared = config.Options
			break
		}
	}
	if declared == nil {
		return spec
	}
	if input, err := producerInputName(producer, declared); err == nil {
		spec.Constraints = append(spec.Constraints, fmt.Sprintf("active producer %s declares input option %q", producer, input))
		if input == "dll" {
			spec.Constraints = append(spec.Constraints, "this producer requires agent_type=windows_dll")
		} else {
			spec.Constraints = append(spec.Constraints, "this producer takes a PE input; keep the agent type compatible")
		}
	}
	return spec
}

// mechanismCatalogBrief is the planner's menu. The operational limits live in
// methodology/mechanism-<name>; the host injects the selected contract for the
// editor instead of repeating every mechanism in the prompt.
func mechanismCatalogBrief() string {
	var b strings.Builder
	b.WriteString("Mechanism catalog (read methodology/mechanism-<name> for limits):\n")
	for _, name := range mechanismNames() {
		if name == "other" {
			continue
		}
		spec := mechanismSpecs[name]
		fmt.Fprintf(&b, "- %s (%s)\n", spec.Name, spec.Layer)
	}
	return b.String()
}

// mechanismBrief is the selected mechanism's contract for the editor.
func (e *evolver) mechanismBrief(name string) string {
	spec := e.mechanismSpecFor(name)
	var b strings.Builder
	fmt.Fprintf(&b, "Selected mechanism: %s (layer %s)\n", spec.Name, spec.Layer)
	fmt.Fprintf(&b, "%s\n", spec.Summary)
	if len(spec.Constraints) > 0 {
		fmt.Fprintf(&b, "Constraints: %s\n", strings.Join(spec.Constraints, " "))
	}
	if len(spec.Signals) > 0 {
		fmt.Fprintf(&b, "Signals to inspect: %s\n", strings.Join(spec.Signals, ", "))
	}
	fmt.Fprintf(&b, "Verification: %s\n", spec.Verification)
	return b.String()
}

// producerSwapHelp describes the concrete GenerateAgent/BuildShellcode steps
// for a producer target, using that module's declared input option. It keeps
// the swap instructions general instead of assuming one producer's input.
func (e *evolver) producerSwapHelp(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	dir := strings.TrimSpace(e.cfg.ProducerDirs[name])
	if name == "" || dir == "" {
		return "the producer is not configured"
	}
	configs, err := modconfig.ReadConfigs(filepath.Join(dir, "config.json"))
	if err != nil {
		return fmt.Sprintf("read %s config: %v", name, err)
	}
	var declared def.ModOptions
	for _, config := range configs {
		if config != nil && strings.EqualFold(config.Name, name) {
			declared = config.Options
			break
		}
	}
	if declared == nil {
		return fmt.Sprintf("%s is not defined in its config.json", name)
	}
	input, err := producerInputName(name, declared)
	if err != nil {
		return fmt.Sprintf("%s: %v", name, err)
	}
	if input == "dll" {
		return fmt.Sprintf("%s needs GenerateAgent agent_type=windows_dll, then BuildShellcode producer=%s dll=<artifact_path>, then mechanism=producer-swap", name, name)
	}
	return fmt.Sprintf("%s needs GenerateAgent with a compatible agent type, then BuildShellcode producer=%s %s=<artifact_path>, then mechanism=producer-swap", name, name, input)
}

// producerRequiresDLL reports whether a producer's declared input is a DLL.
func (e *evolver) producerRequiresDLL(name string) bool {
	return e.producerAgentType(name) == "windows_dll"
}

// producerAgentType derives the agent type a producer needs from its declared
// input option. It is the general replacement for hardcoding one producer's
// input format.
func (e *evolver) producerAgentType(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	dir := strings.TrimSpace(e.cfg.ProducerDirs[name])
	if name == "" || dir == "" {
		return ""
	}
	configs, err := modconfig.ReadConfigs(filepath.Join(dir, "config.json"))
	if err != nil {
		return ""
	}
	var declared def.ModOptions
	for _, config := range configs {
		if config != nil && strings.EqualFold(config.Name, name) {
			declared = config.Options
			break
		}
	}
	if declared == nil {
		return ""
	}
	input, err := producerInputName(name, declared)
	if err != nil {
		return ""
	}
	if input == "dll" {
		return "windows_dll"
	}
	return "windows_executable"
}
