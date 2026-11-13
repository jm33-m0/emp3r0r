package detection

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PlanVersion is the persisted plan schema version.
const PlanVersion = 1

// Covered reports whether a local module emits a payload this loop tests.
// The plan is built for these modules automatically after a successful build.
func Covered(module string) bool {
	switch strings.ToLower(strings.TrimSpace(module)) {
	case "loader_windows", "stager_linux":
		return true
	}
	return false
}

// Artifact is one built payload.
type Artifact struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5,omitempty"`
	Kind   string `json:"kind"`
}

// Stage is one planned sandbox test.
type Stage struct {
	Kind             StageKind `json:"kind"`
	Tool             string    `json:"tool"`
	Executes         bool      `json:"executes"`
	RequiresApproval bool      `json:"requires_approval"`
	Runnable         bool      `json:"runnable"`
	Reason           string    `json:"reason,omitempty"`
}

// SandboxPlan is the capability snapshot a plan was built from.
type SandboxPlan struct {
	URL          string   `json:"url"`
	Available    bool     `json:"available"`
	StaticTools  []string `json:"static_tools,omitempty"`
	DynamicTools []string `json:"dynamic_tools,omitempty"`
	EDRProfiles  []string `json:"edr_profiles,omitempty"`
	Issues       []string `json:"issues,omitempty"`
}

// Plan is the detection test plan for one artifact.
type Plan struct {
	Version       int         `json:"version"`
	Module        string      `json:"module"`
	ModuleDir     string      `json:"module_dir,omitempty"`
	Platform      string      `json:"platform"`
	Artifact      Artifact    `json:"artifact"`
	CreatedAt     time.Time   `json:"created_at"`
	Sandbox       SandboxPlan `json:"sandbox"`
	Stages        []Stage     `json:"stages"`
	SourceTargets []string    `json:"source_targets,omitempty"`
	Notes         []string    `json:"notes,omitempty"`
}

// Request describes a plan to build.
type Request struct {
	Module       string
	ModuleDir    string
	Platform     string
	ArtifactPath string
	Flags        map[string]string
}

// InspectArtifact hashes one built payload and classifies its container.
func InspectArtifact(path string) (Artifact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("stat artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Artifact{}, fmt.Errorf("artifact is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()
	md5Hash := md5.New()
	sha256Hash := sha256.New()
	head := make([]byte, 4)
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return Artifact{}, fmt.Errorf("read artifact header: %w", err)
	}
	head = head[:n]
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Artifact{}, fmt.Errorf("rewind artifact: %w", err)
	}
	if _, err := io.Copy(io.MultiWriter(md5Hash, sha256Hash), file); err != nil {
		return Artifact{}, fmt.Errorf("hash artifact: %w", err)
	}
	return Artifact{
		Path:   path,
		Name:   filepath.Base(path),
		Size:   info.Size(),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		Kind:   artifactKind(head),
	}, nil
}

func artifactKind(head []byte) string {
	switch {
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return "pe"
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		return "elf"
	default:
		return "raw"
	}
}

// BuildPlan derives the deterministic test plan from the module, artifact, and
// sandbox capabilities. It performs no network calls and runs nothing.
func BuildPlan(req Request, health Health) (Plan, error) {
	module := strings.ToLower(strings.TrimSpace(req.Module))
	if module == "" {
		return Plan{}, fmt.Errorf("module is required")
	}
	if strings.TrimSpace(req.ArtifactPath) == "" {
		return Plan{}, fmt.Errorf("artifact path is required")
	}
	artifact, err := InspectArtifact(req.ArtifactPath)
	if err != nil {
		return Plan{}, err
	}
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	if platform == "" {
		switch artifact.Kind {
		case "pe":
			platform = "windows"
		case "elf":
			platform = "linux"
		}
	}

	plan := Plan{
		Version:   PlanVersion,
		Module:    module,
		ModuleDir: req.ModuleDir,
		Platform:  platform,
		Artifact:  artifact,
		CreatedAt: time.Now().UTC(),
		Sandbox: SandboxPlan{
			URL:          health.URL,
			Available:    health.Available,
			StaticTools:  health.Tools("static"),
			DynamicTools: health.Tools("dynamic"),
			EDRProfiles:  append([]string(nil), health.EDRProfiles...),
			Issues:       append([]string(nil), health.Issues...),
		},
	}

	for _, tool := range plan.Sandbox.StaticTools {
		plan.Stages = append(plan.Stages, Stage{
			Kind:     StageStatic,
			Tool:     tool,
			Executes: false,
			Runnable: health.Available,
			Reason:   staticStageReason(artifact, tool),
		})
	}
	if len(plan.Stages) == 0 {
		plan.Notes = append(plan.Notes, "no static scanners are configured on the sandbox")
	}

	for _, tool := range plan.Sandbox.DynamicTools {
		stage := Stage{Kind: StageDynamic, Tool: tool, Executes: true, RequiresApproval: true}
		switch {
		case !health.Available:
			stage.Reason = "sandbox is unreachable"
		case platform != "windows":
			stage.Reason = "dynamic analysis detonates Windows payloads only"
		default:
			stage.Runnable = true
		}
		plan.Stages = append(plan.Stages, stage)
	}

	for _, profile := range plan.Sandbox.EDRProfiles {
		stage := Stage{Kind: StageEDR, Tool: profile, Executes: true, RequiresApproval: true}
		switch {
		case !health.Available:
			stage.Reason = "sandbox is unreachable"
		case platform != "windows":
			stage.Reason = "EDR detonation runs Windows payloads only"
		default:
			stage.Runnable = true
		}
		plan.Stages = append(plan.Stages, stage)
	}
	if len(plan.Sandbox.EDRProfiles) == 0 {
		plan.Notes = append(plan.Notes, "no EDR profiles are configured on the sandbox")
	}
	if !health.Available {
		plan.Notes = append(plan.Notes, "sandbox is unreachable; plan is saved and can run later")
	}
	if artifact.Kind != "pe" && platform == "windows" {
		plan.Notes = append(plan.Notes, "artifact is not a PE; PE-only scanners may return no findings")
	}
	plan.Notes = append(plan.Notes,
		"static analysis reads the artifact and never executes it",
		"dynamic and EDR stages detonate the artifact and need explicit approval",
	)
	plan.SourceTargets = sourceTargets(req.ModuleDir)
	return plan, nil
}

func staticStageReason(artifact Artifact, tool string) string {
	if artifact.Kind == "pe" {
		return ""
	}
	switch strings.ToLower(tool) {
	case "checkplz", "stringnalyzer":
		return "scanner targets PE structure; result may be empty for a " + artifact.Kind + " artifact"
	}
	return ""
}

// sourceTargets lists the module source files the feedback can point at.
func sourceTargets(moduleDir string) []string {
	if strings.TrimSpace(moduleDir) == "" {
		return nil
	}
	var out []string
	index := newSourceIndex(moduleDir)
	for _, file := range index.files {
		out = append(out, file.rel)
	}
	sort.Strings(out)
	return out
}

// StageRunnable reports whether a plan contains a runnable stage of a kind.
func (p Plan) StageRunnable(kind StageKind) bool {
	for _, stage := range p.Stages {
		if stage.Kind == kind && stage.Runnable {
			return true
		}
	}
	return false
}
