package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

const (
	// DefaultVerifyModule is a small BOF whose output proves the target agent
	// is running code, not merely that a loader process survived the sandbox window.
	DefaultVerifyModule = "whoami"
	// PayloadVerifyTimeout bounds one agent online/module verification check.
	PayloadVerifyTimeout = 15 * time.Second
)

var verifyModules = map[string]struct{}{DefaultVerifyModule: {}}

// IsAllowedVerifyModule reports whether module is permitted for loop verification.
func IsAllowedVerifyModule(module string) bool {
	_, ok := verifyModules[strings.ToLower(strings.TrimSpace(module))]
	return ok
}

// VerifyAgentStatus describes the online state of the loop's single test agent.
type VerifyAgentStatus struct {
	ExpectedAgent string         `json:"expected_agent"`
	Online        bool           `json:"online"`
	Agent         map[string]any `json:"agent,omitempty"`
}

// VerifyModuleResult captures one scoped verification BOF run.
type VerifyModuleResult struct {
	Agent   map[string]any `json:"agent,omitempty"`
	Module  string         `json:"module"`
	JobID   string         `json:"job_id,omitempty"`
	Output  string         `json:"output"`
	Message string         `json:"message,omitempty"`
}

// VerifyOps performs scoped C2 verification actions for the loop's test agent.
// Keeping this behind an interface isolates detection from direct C2 client
// state.
type VerifyOps interface {
	AgentStatus(ctx context.Context, agentUUID string) (*VerifyAgentStatus, error)
	RunVerifyModule(ctx context.Context, agentUUID, module string) (*VerifyModuleResult, error)
	ForgetAgent(ctx context.Context, agentUUID string) error
}

// agentStatusTool reports whether the payload under test is online. It never
// lists or accepts another agent because loop telemetry is untrusted.
func (e *evolver) agentStatusTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "AgentStatus",
		Description: "Check whether the agent UUID generated for this loop is connected to the C2. " +
			"Use it to prove the payload under test checked in before editing the loader or claiming success.",
		Prompt: "Check whether the payload under test is online.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, _ json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			if e.cfg.Verify == nil {
				e.audit("agent_status_denied", e.expectedAgentUUID, "verification is not configured")
				return tool.Errorf("verification is not configured for this loop"), nil
			}
			if e.expectedAgentUUID == "" {
				e.audit("agent_status_denied", "", "no expected agent UUID")
				return tool.Errorf("no expected agent UUID; call GenerateAgent and BuildShellcode first"), nil
			}
			status, err := e.cfg.Verify.AgentStatus(ctx, e.expectedAgentUUID)
			if err != nil {
				e.audit("agent_status_denied", e.expectedAgentUUID, err.Error())
				return tool.Errorf(fmt.Sprintf("agent status: %v", err)), nil
			}
			if status == nil {
				status = &VerifyAgentStatus{ExpectedAgent: e.expectedAgentUUID}
			}
			e.audit("agent_status", e.expectedAgentUUID, fmt.Sprintf("online=%v", status.Online))
			data, _ := json.Marshal(status)
			return tool.Text(string(data)), nil
		},
	})
}

// runModuleTool lets the model run the verification BOF on its own test
// agent. It deliberately has no target and no options so untrusted telemetry
// cannot turn verification into a general post-exploitation console.
func (e *evolver) runModuleTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "RunModule",
		Description: "Run the verification BOF (" + DefaultVerifyModule + ") on the payload agent as a diagnostic and return its output. " +
			"A live AgentStatus is the health signal; LitterBox may terminate the beacon before this BOF runs. " +
			"Use AgentStatus first; an agent that is not online cannot run a module.",
		Prompt: "Run the verification BOF on the payload agent.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module": map[string]any{
					"type":        "string",
					"enum":        []string{DefaultVerifyModule},
					"description": "Verification module; only " + DefaultVerifyModule + " is allowed.",
				},
			},
			"required": []string{"module"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module string `json:"module"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			module := strings.ToLower(strings.TrimSpace(args.Module))
			if !IsAllowedVerifyModule(module) {
				e.audit("run_module_denied", e.expectedAgentUUID, "module="+module)
				return tool.Errorf("module is not allowed; use " + DefaultVerifyModule), nil
			}
			if e.cfg.Verify == nil {
				e.audit("run_module_denied", e.expectedAgentUUID, "verification is not configured")
				return tool.Errorf("verification is not configured for this loop"), nil
			}
			if e.expectedAgentUUID == "" {
				e.audit("run_module_denied", "", "no expected agent UUID")
				return tool.Errorf("no expected agent UUID; call GenerateAgent and BuildShellcode first"), nil
			}
			res, err := e.cfg.Verify.RunVerifyModule(ctx, e.expectedAgentUUID, module)
			if err != nil {
				e.audit("run_module_denied", e.expectedAgentUUID, fmt.Sprintf("module=%s error=%v", module, err))
				return tool.Errorf(fmt.Sprintf("run %s: %v", module, err)), nil
			}
			if res == nil {
				res = &VerifyModuleResult{Module: module}
			}
			e.audit("run_module", e.expectedAgentUUID, fmt.Sprintf("module=%s job=%s message=%s", module, res.JobID, res.Message))
			data, _ := json.Marshal(res)
			return tool.Text(string(data)), nil
		},
	})
}

// cleanupAgentTool forgets the loop's own test agent so a rotation does not
// leave stale TOFU records, live entries, or locks behind.
func (e *evolver) cleanupAgentTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name:        "CleanupAgent",
		Description: "Forget the expected test agent from the C2 (database, live registry, and lock). GenerateAgent does this automatically.",
		Prompt:      "Remove the previous test agent from the C2.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, _ json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			if e.cfg.Verify == nil {
				e.audit("cleanup_agent_denied", e.expectedAgentUUID, "verification is not configured")
				return tool.Errorf("verification is not configured for this loop"), nil
			}
			if e.expectedAgentUUID == "" {
				e.audit("cleanup_agent_denied", "", "no expected agent UUID")
				return tool.Errorf("no test agent to clean up"), nil
			}
			if err := e.forgetAgent(ctx, e.expectedAgentUUID); err != nil {
				e.audit("cleanup_agent_denied", e.expectedAgentUUID, err.Error())
				return tool.Errorf(fmt.Sprintf("forget agent: %v", err)), nil
			}
			e.audit("cleanup_agent", e.expectedAgentUUID, "")
			return tool.Text(fmt.Sprintf("forgot test agent %s", e.expectedAgentUUID)), nil
		},
	})
}

func (e *evolver) forgetAgent(ctx context.Context, identifier string) error {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" || e.cfg.Verify == nil {
		return nil
	}
	return e.cfg.Verify.ForgetAgent(ctx, identifier)
}

// FindAgentByUUID returns the live agent matching want by UUID only.
func FindAgentByUUID(agents []*def.Emp3r0rAgent, want string) *def.Emp3r0rAgent {
	want = strings.TrimSpace(want)
	if want == "" {
		return nil
	}
	for _, agent := range agents {
		if agent == nil {
			continue
		}
		if strings.EqualFold(agent.UUID, want) {
			return agent
		}
	}
	return nil
}

// AgentSummary formats non-sensitive metadata for an agent under test.
func AgentSummary(agent *def.Emp3r0rAgent) map[string]any {
	if agent == nil {
		return nil
	}
	return map[string]any{
		"tag": agent.Tag, "uuid": agent.UUID, "name": agent.Name,
		"hostname": agent.Hostname, "user": agent.User, "os": agent.OS,
		"goos": agent.GOOS, "arch": agent.GOArch, "last_seen": agent.LastSeen,
	}
}
