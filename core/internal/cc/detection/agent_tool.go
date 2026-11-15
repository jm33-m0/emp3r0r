package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// generateAgentTool rebuilds the Go agent without wrapping it.
func (e *evolver) generateAgentTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "GenerateAgent",
		Description: "Build a fresh real Go agent with generator flags, without wrapping it in shellcode. " +
			"Every dynamic cycle needs this fresh UUID: the C2 rejects a repeated UUID with a new key as a TOFU key rotation. " +
			"The previous test agent is forgotten automatically. " +
			"agent_type selects windows_executable or windows_dll; arch is amd64. " +
			"The result includes artifact_path (the EXE/DLL). " +
			"Call BuildShellcode with producer=donut input=artifact_path, " +
			"or producer=crystal_pack dll=artifact_path, to choose the wrapper.",
		Prompt: "Generate a new Go agent payload.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_type": map[string]any{
					"type":        "string",
					"enum":        []string{"windows_executable", "windows_dll"},
					"description": "windows_executable (EXE) or windows_dll (DLL). The DLL can be wrapped by crystal_pack.",
				},
				"arch": map[string]any{
					"type":        "string",
					"enum":        []string{"amd64"},
					"description": "Agent architecture; loader_windows is x64.",
				},
				"note": map[string]any{"type": "string", "description": "What this agent build is testing."},
			},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				AgentType string `json:"agent_type"`
				Arch      string `json:"arch"`
				Note      string `json:"note"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			agentType := strings.ToLower(strings.TrimSpace(args.AgentType))
			if agentType == "" {
				agentType = strings.ToLower(strings.TrimSpace(e.cfg.AgentType))
			}
			if agentType == "" {
				agentType = "windows_executable"
			}
			if agentType != "windows_executable" && agentType != "windows_dll" {
				return tool.Errorf("agent_type must be windows_executable or windows_dll"), nil
			}
			arch := strings.ToLower(strings.TrimSpace(args.Arch))
			if arch == "" {
				arch = strings.ToLower(strings.TrimSpace(e.cfg.AgentArch))
			}
			if arch == "" {
				arch = "amd64"
			}
			if arch != "amd64" {
				return tool.Errorf("loader_windows is x64; arch must be amd64"), nil
			}
			if e.cfg.BuildAgent == nil {
				return tool.Errorf("agent generation is not configured for this loop"), nil
			}
			e.logClass(logging.ClassBuild, "GenerateAgent: %s/%s", agentType, arch)
			result, err := e.cfg.BuildAgent(AgentBuildOptions{Type: agentType, Arch: arch})
			if err != nil {
				return tool.Errorf(fmt.Sprintf("generate agent: %v", err)), nil
			}
			if result == nil {
				return tool.Errorf("agent generation returned no result"), nil
			}
			artifact, err := filepath.Abs(result.ArtifactPath)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("resolve agent artifact: %v", err)), nil
			}
			info, err := os.Stat(artifact)
			if err != nil || !info.Mode().IsRegular() {
				return tool.Errorf(fmt.Sprintf("agent artifact %q is not a regular file", artifact)), nil
			}
			if info.Size() < minAgentShellcodeBytes {
				return tool.Errorf(fmt.Sprintf("agent artifact is only %d bytes; the agent payload is missing", info.Size())), nil
			}
			if err := ensureWithin(e.payloadDir(), artifact); err != nil {
				return tool.Errorf("agent artifact is outside the active payload directory"), nil
			}
			inspect, err := InspectArtifact(artifact)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("inspect agent artifact: %v", err)), nil
			}
			e.agentArtifact = artifact
			e.cfg.AgentType = agentType
			e.cfg.AgentArch = arch
			// A repeated UUID with a new runtime key is rejected by TOFU. Forget
			// the previous test agent before switching the loop to this build.
			if old := e.expectedAgentUUID; old != "" && old != result.AgentUUID {
				if forgetErr := e.forgetAgent(ctx, old); forgetErr != nil {
					e.logClass(logging.ClassWarning, "forget previous agent %s: %v", old, forgetErr)
				}
			}
			if result.AgentUUID != "" {
				e.expectedAgentUUID = result.AgentUUID
			}
			e.audit("generate_agent", result.AgentUUID,
				fmt.Sprintf("type=%s arch=%s artifact=%s", agentType, arch, artifact))
			out := map[string]any{
				"agent_type":    agentType,
				"arch":          arch,
				"agent_uuid":    result.AgentUUID,
				"artifact_path": artifact,
				"sha256":        inspect.SHA256,
				"size":          inspect.Size,
				"message": "the agent is built but not wrapped; call BuildShellcode with producer=donut " +
					"input=artifact_path, or producer=crystal_pack dll=artifact_path. The new shellcode becomes active.",
			}
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}
