package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// generateAgentTool rebuilds the agent without wrapping it. A Windows loop
// builds a Go EXE or DLL for a producer; a Linux loop builds the C agent PIC
// that stager_linux embeds.
func (e *evolver) generateAgentTool() tool.CoreTool {
	description := "Build a fresh Go agent from the editable go_agent source with generator flags, without wrapping it in shellcode. " +
		"Every dynamic cycle needs this fresh UUID: the C2 rejects a repeated UUID with a new key as a TOFU key rotation. " +
		"The previous test agent is forgotten automatically. " +
		"agent_type selects windows_executable or windows_dll; arch is amd64. " +
		"The result includes artifact_path (the EXE/DLL). " +
		"Call BuildShellcode with producer=donut input=artifact_path, " +
		"or producer=crystal_pack dll=artifact_path, to choose the wrapper."
	agentTypes := []string{"windows_executable", "windows_dll"}
	agentDescription := "windows_executable (EXE) or windows_dll (DLL). The DLL can be wrapped by crystal_pack."
	archDescription := "Agent architecture; loader_windows is x64."
	if e.platform() == platformLinux {
		description = "Build a fresh C agent shared object from the editable c_agent tree. " +
			"Every dynamic cycle needs this fresh UUID: the C2 rejects a repeated UUID with a new key as a TOFU key rotation. " +
			"The previous test agent is forgotten automatically. " +
			"agent_type is linux_so and arch is amd64. Call BuildShellcode producer=malasada " +
			"input=artifact_path to produce the PIC that stager_linux embeds."
		agentTypes = []string{"linux_so"}
		agentDescription = "linux_so builds the C agent shared object for the malasada producer."
		archDescription = "The C agent shared object is amd64-only."
	}
	return tool.Build(tool.Spec{
		Name:        "GenerateAgent",
		Description: description,
		Prompt:      "Generate a new agent payload.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_type": map[string]any{
					"type":        "string",
					"enum":        agentTypes,
					"description": agentDescription,
				},
				"arch": map[string]any{
					"type":        "string",
					"enum":        []string{"amd64"},
					"description": archDescription,
				},
				"glibc_version": map[string]any{
					"type":        "string",
					"enum":        builder.CAgentGlibcVersions,
					"description": "Linux C agent: oldest glibc ABI. Default 2.17 for portability; 2.34 requires public dynload.",
				},
				"dynload": map[string]any{
					"type":        "string",
					"enum":        builder.CAgentDynloadModes,
					"description": "Linux C agent: auto tries libc_dl then public dlopen; public is 2.34+ only.",
				},
				"libc": map[string]any{
					"type":        "string",
					"enum":        builder.CAgentLibcs,
					"description": "Linux C agent libc ABI. musl forces public dynload.",
				},
				"tags": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "enum": builder.AllAgentTags()},
					"description": "Windows Go agent: exact opt-in feature-tag set. Omit to derive from the operator transport; [] builds the slim agent.",
				},
				"note": map[string]any{"type": "string", "description": "What this agent build is testing."},
			},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				AgentType    string    `json:"agent_type"`
				Arch         string    `json:"arch"`
				GlibcVersion string    `json:"glibc_version"`
				Dynload      string    `json:"dynload"`
				Libc         string    `json:"libc"`
				Tags         *[]string `json:"tags"`
				Note         string    `json:"note"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			agentType := strings.ToLower(strings.TrimSpace(args.AgentType))
			if agentType == "" {
				agentType = strings.ToLower(strings.TrimSpace(e.cfg.AgentType))
			}
			if agentType == "" {
				if e.platform() == platformLinux {
					agentType = "linux_so"
				} else {
					agentType = "windows_executable"
				}
			}
			if e.platform() == platformLinux {
				if agentType != "linux_so" {
					return tool.Errorf("agent_type must be linux_so on this platform"), nil
				}
			} else if agentType != "windows_executable" && agentType != "windows_dll" {
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
				if e.platform() == platformLinux {
					return tool.Errorf("the C agent shared object is amd64-only; arch must be amd64"), nil
				}
				return tool.Errorf("loader_windows is x64; arch must be amd64"), nil
			}
			if e.cfg.BuildAgent == nil {
				return tool.Errorf("agent generation is not configured for this loop"), nil
			}
			glibc := strings.TrimSpace(args.GlibcVersion)
			dynload := strings.TrimSpace(args.Dynload)
			libc := strings.TrimSpace(args.Libc)
			if e.platform() == platformLinux {
				if glibc == "" {
					glibc = e.agentGlibc
				}
				if dynload == "" {
					dynload = e.agentDynload
				}
				if libc == "" {
					libc = e.agentLibc
				}
				if glibc == "" {
					glibc = builder.CAgentGlibcVersions[0]
				}
				if dynload == "" {
					dynload = builder.CAgentDynloadModes[0]
				}
				if libc == "" {
					libc = builder.CAgentLibcs[0]
				}
				dynload = builder.CAgentDynloadForLibc(libc, dynload, false)
				if !slices.Contains(builder.CAgentGlibcVersions, glibc) || !slices.Contains(builder.CAgentDynloadModes, dynload) || !slices.Contains(builder.CAgentLibcs, libc) {
					return tool.Errorf("invalid glibc_version, dynload, or libc"), nil
				}
			}
			buildTags := e.cfg.AgentTags
			if args.Tags != nil {
				if e.platform() == platformLinux {
					return tool.Errorf("tags apply to the Windows Go agent only"), nil
				}
				normalized, err := builder.NormalizeAgentTags(*args.Tags)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("%v", err)), nil
				}
				buildTags = normalized
			}
			e.logClass(logging.ClassBuild, "GenerateAgent: %s/%s", agentType, arch)
			result, err := e.cfg.BuildAgent(AgentBuildOptions{
				Type: agentType, Arch: arch, Platform: e.platform(), SourceDir: e.cfg.AgentSourceDir,
				Glibc: glibc, Dynload: dynload, Libc: libc,
				BuildTags: buildTags,
			})
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
			oldArtifact := e.agentArtifact
			e.agentArtifact = artifact
			e.cfg.AgentType = agentType
			e.cfg.AgentArch = arch
			if args.Tags != nil {
				e.cfg.AgentTags = buildTags
			}
			e.agentSourceDirty.Store(false)
			if e.platform() == platformLinux {
				e.agentGlibc, e.agentDynload, e.agentLibc = glibc, dynload, libc
				e.cfg.AgentGlibc, e.cfg.AgentDynload, e.cfg.AgentLibc = glibc, dynload, libc
			}
			// A repeated UUID with a new runtime key is rejected by TOFU. Forget
			// the previous test agent before switching the loop to this build.
			if old := e.expectedAgentUUID; old != "" && old != result.AgentUUID {
				if forgetErr := e.forgetAgent(ctx, old); forgetErr != nil {
					e.logClass(logging.ClassWarning, "forget previous agent %s: %v", old, forgetErr)
				} else {
					e.audit("cleanup_agent", old, "agent rotation")
				}
			}
			e.cleanupAgentArtifact(oldArtifact)
			if result.AgentUUID != "" {
				if old := strings.TrimSpace(e.expectedAgentUUID); old != "" && !strings.EqualFold(old, result.AgentUUID) {
					e.payloadSeenOnline.Store(false)
				}
				e.expectedAgentUUID = result.AgentUUID
			}
			e.audit("generate_agent", result.AgentUUID,
				fmt.Sprintf("type=%s arch=%s tags=%s artifact=%s", agentType, arch, strings.Join(e.cfg.AgentTags, " "), artifact))
			out := map[string]any{
				"agent_type":    agentType,
				"arch":          arch,
				"build_tags":    e.cfg.AgentTags,
				"agent_uuid":    result.AgentUUID,
				"artifact_path": artifact,
				"sha256":        inspect.SHA256,
				"size":          inspect.Size,
				"message": "the agent is built but not wrapped; call BuildShellcode with producer=donut " +
					"input=artifact_path, or producer=crystal_pack dll=artifact_path. The new shellcode becomes active.",
			}
			if e.platform() == platformLinux {
				out["message"] = "the C agent shared object is built; call BuildShellcode producer=malasada input=artifact_path. The resulting PIC becomes the payload stager_linux embeds."
			}
			data, _ := json.Marshal(out)
			return tool.Text(string(data)), nil
		},
	})
}
