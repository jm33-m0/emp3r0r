package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// artifactRoot is the operator workspace that contains the detection store.
// Agent executables and DSOs are written there; logs and reports live in the
// detection store and are never deleted by rotation.
func (e *evolver) artifactRoot() string {
	store := strings.TrimSpace(e.cfg.StoreRoot)
	if store == "" {
		return ""
	}
	root, err := filepath.Abs(filepath.Dir(store))
	if err != nil {
		return ""
	}
	return root
}

// cleanupGeneratedFile removes one loop-generated agent or shellcode file. It
// refuses paths outside the workspace and the detection shellcode directory.
func (e *evolver) cleanupGeneratedFile(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	allowed := false
	if root := strings.TrimSpace(e.cfg.StoreRoot); root != "" {
		if ensureWithin(filepath.Join(root, "shellcode"), path) == nil {
			allowed = true
		}
	}
	if !allowed {
		if root := e.artifactRoot(); root != "" && ensureWithin(root, path) == nil {
			allowed = true
		}
	}
	if !allowed {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		e.logClass(logging.ClassWarning, "remove old agent file %s: %v", path, err)
	}
}

// cleanupShellcode removes a superseded shellcode unless the operator supplied
// it explicitly or it belongs to the last payload that executed. That shellcode
// is the execution gate's restore target.
func (e *evolver) cleanupShellcode(path string) {
	path = strings.TrimSpace(path)
	if path == "" || path == strings.TrimSpace(e.shellcode) {
		return
	}
	if path == strings.TrimSpace(e.preservedShellcode) {
		return
	}
	if e.lastExecuting != nil {
		var summary cycleSummary
		if json.Unmarshal([]byte(e.lastExecuting.Summary), &summary) == nil &&
			strings.TrimSpace(summary.Shellcode) == path {
			e.preservedShellcode = path
			return
		}
	}
	if path == strings.TrimSpace(e.cfg.Shellcode) && !e.initialShellcodeGenerated {
		return
	}
	e.cleanupGeneratedFile(path)
}

func (e *evolver) cleanupAgentArtifact(path string) {
	path = strings.TrimSpace(path)
	if path == "" || path == strings.TrimSpace(e.agentArtifact) {
		return
	}
	e.cleanupGeneratedFile(path)
}

// markActiveAgentUsed records the shellcode and UUID before a detonation, so a
// failed run still forces the next cycle to rotate the agent.
func (e *evolver) markActiveAgentUsed() {
	if shellcode := strings.TrimSpace(e.activeShellcode()); shellcode != "" {
		e.testedShellcodes.Store(shellcode, struct{}{})
	}
	if uuid := strings.TrimSpace(e.expectedAgentUUID); uuid != "" {
		e.testedAgentUUIDs.Store(uuid, struct{}{})
	}
}

// ensureFreshAgent rotates the test agent when the active shellcode or UUID has
// already been detonated. The C2 pins the first key per UUID (TOFU), so a
// reused agent is rejected before it can check in.
func (e *evolver) ensureFreshAgent(ctx context.Context) error {
	if e.cfg.BuildAgent == nil {
		return nil
	}
	shellcode := strings.TrimSpace(e.activeShellcode())
	uuid := strings.TrimSpace(e.expectedAgentUUID)
	_, shellUsed := e.testedShellcodes.Load(shellcode)
	_, uuidUsed := e.testedAgentUUIDs.Load(uuid)
	if shellcode != "" && !shellUsed && !uuidUsed {
		return nil
	}
	return e.rotateAgent(ctx)
}

// rotationAgentType keeps the agent format compatible with the active
// producer. The producer's declared input option decides whether the agent
// must be an EXE or a DLL, so a producer swap does not keep a stale format.
func (e *evolver) rotationAgentType() string {
	if e.platform() == platformLinux {
		return "linux_so"
	}
	if e.producerRequiresDLL(e.activeProducer) {
		return "windows_dll"
	}
	agentType := strings.ToLower(strings.TrimSpace(e.cfg.AgentType))
	if agentType == "" || agentType == "auto" {
		return "windows_executable"
	}
	return agentType
}

func (e *evolver) rotationProducer(agentType string) string {
	if e.platform() == platformLinux {
		if _, ok := e.cfg.ProducerDirs["malasada"]; ok {
			return "malasada"
		}
		return ""
	}
	configured := func(name string) bool {
		_, ok := e.cfg.ProducerDirs[name]
		return ok
	}
	if active := strings.ToLower(strings.TrimSpace(e.activeProducer)); active != "" && configured(active) {
		return active
	}
	wantDLL := strings.EqualFold(agentType, "windows_dll")
	for _, name := range e.producerNames() {
		if wantDLL == e.producerRequiresDLL(name) {
			return name
		}
	}
	return ""
}

// rotateAgent builds a new Go agent, wraps it with the active producer, forgets
// the previous UUID, and deletes the superseded agent and shellcode files.
// Logs, reports, and telemetry rows are kept.
func (e *evolver) rotateAgent(ctx context.Context) error {
	if e.cfg.BuildAgent == nil {
		return fmt.Errorf("agent rotation is not configured")
	}
	agentType := e.rotationAgentType()
	arch := strings.ToLower(strings.TrimSpace(e.cfg.AgentArch))
	if arch == "" {
		arch = "amd64"
	}
	oldArtifact := e.agentArtifact
	oldShellcode := e.shellcode
	oldUUID := strings.TrimSpace(e.expectedAgentUUID)
	e.logClass(logging.ClassCycle, "rotating test agent: building a fresh %s/%s agent (previous %s)",
		agentType, arch, headerOrNone(oldUUID))
	result, err := e.cfg.BuildAgent(AgentBuildOptions{
		Type: agentType, Arch: arch, Platform: e.platform(), SourceDir: e.cfg.AgentSourceDir,
		Glibc: e.agentGlibc, Dynload: e.agentDynload, Libc: e.agentLibc,
	})
	if err != nil {
		return fmt.Errorf("rotate agent: %w", err)
	}
	if result == nil || strings.TrimSpace(result.ArtifactPath) == "" {
		return fmt.Errorf("rotate agent: build returned no artifact")
	}
	newUUID := strings.TrimSpace(result.AgentUUID)
	if newUUID == "" {
		return fmt.Errorf("rotate agent: build returned no UUID")
	}
	if oldUUID != "" && strings.EqualFold(oldUUID, newUUID) {
		e.cleanupAgentArtifact(strings.TrimSpace(result.ArtifactPath))
		return fmt.Errorf("rotate agent: build reused UUID %s; TOFU would reject it", newUUID)
	}
	artifactPath, err := filepath.Abs(strings.TrimSpace(result.ArtifactPath))
	if err != nil {
		return fmt.Errorf("rotate agent: resolve artifact: %w", err)
	}
	info, err := os.Stat(artifactPath)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("rotate agent: artifact %s is not a regular file", artifactPath)
	}
	if info.Size() < minAgentShellcodeBytes {
		e.cleanupAgentArtifact(artifactPath)
		return fmt.Errorf("rotate agent: artifact is only %d bytes; the agent payload is missing", info.Size())
	}
	if root := e.artifactRoot(); root != "" {
		if err := ensureWithin(root, artifactPath); err != nil {
			e.cleanupAgentArtifact(artifactPath)
			return fmt.Errorf("rotate agent: artifact is outside the operator workspace")
		}
	}
	producer := e.rotationProducer(agentType)
	if producer == "" {
		e.cleanupAgentArtifact(artifactPath)
		return fmt.Errorf("rotate agent: no shellcode producer is configured")
	}
	e.agentArtifact = artifactPath
	if _, _, _, err := e.buildShellcodeWithProducer(ctx, producer, nil, "agent rotation"); err != nil {
		e.agentArtifact = oldArtifact
		e.cleanupAgentArtifact(artifactPath)
		return fmt.Errorf("rotate agent shellcode: %w", err)
	}
	e.expectedAgentUUID = newUUID
	e.payloadSeenOnline.Store(false)
	e.cfg.AgentType = agentType
	e.cfg.AgentArch = arch
	if oldUUID != "" {
		if err := e.forgetAgent(ctx, oldUUID); err != nil {
			e.logClass(logging.ClassWarning, "rotate agent: forget %s: %v", oldUUID, err)
			e.audit("cleanup_agent_denied", oldUUID, err.Error())
		} else {
			e.audit("cleanup_agent", oldUUID, "agent rotation")
		}
	}
	e.cleanupAgentArtifact(oldArtifact)
	e.cleanupShellcode(oldShellcode)
	e.audit("generate_agent", newUUID,
		fmt.Sprintf("rotation type=%s arch=%s artifact=%s", agentType, arch, artifactPath))
	if producer != "" {
		e.logClass(logging.ClassCycle, "rotated test agent to %s (producer %s)", newUUID, producer)
	} else {
		e.logClass(logging.ClassCycle, "rotated test agent to %s", newUUID)
	}
	return nil
}
