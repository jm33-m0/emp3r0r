package detection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

type stubVerifyOps struct {
	statusCalls []string
	moduleCalls []string
	forgetCalls []string
}

func (s *stubVerifyOps) AgentStatus(_ context.Context, agentUUID string) (*VerifyAgentStatus, error) {
	s.statusCalls = append(s.statusCalls, agentUUID)
	return &VerifyAgentStatus{
		ExpectedAgent: agentUUID,
		Online:        true,
		Agent:         map[string]any{"uuid": agentUUID, "tag": "agent-tag"},
	}, nil
}

func (s *stubVerifyOps) RunVerifyModule(_ context.Context, agentUUID, module string) (*VerifyModuleResult, error) {
	s.moduleCalls = append(s.moduleCalls, agentUUID+":"+module)
	return &VerifyModuleResult{
		Module: module,
		JobID:  "job-1",
		Output: "NT AUTHORITY\\SYSTEM",
	}, nil
}

func (s *stubVerifyOps) ForgetAgent(_ context.Context, agentUUID string) error {
	s.forgetCalls = append(s.forgetCalls, agentUUID)
	return nil
}

func TestFindAgentMatchesUUIDOnly(t *testing.T) {
	agents := []*def.Emp3r0rAgent{
		{UUID: "uuid-one", Tag: "tag-one"},
		{UUID: "uuid-two", Tag: "tag-two"},
	}
	if got := FindAgentByUUID(agents, "UUID-ONE"); got == nil || got.UUID != "uuid-one" {
		t.Fatalf("FindAgentByUUID by UUID = %+v", got)
	}
	if got := FindAgentByUUID(agents, "tag-two"); got != nil {
		t.Fatalf("FindAgentByUUID matched a tag: %+v", got)
	}
	if got := FindAgentByUUID(agents, "missing"); got != nil {
		t.Fatalf("FindAgentByUUID missing = %+v", got)
	}
}

func TestVerificationToolsRejectUntrustedTargets(t *testing.T) {
	audits := make([]string, 0, 2)
	e := &evolver{
		expectedAgentUUID: "loop-uuid",
		cfg: EvolveConfig{
			Verify: &stubVerifyOps{},
			Audit: func(action, target, detail string) {
				audits = append(audits, action+" "+target+" "+detail)
			},
		},
		logf: func(logging.Class, string, ...any) {},
	}

	result, err := e.runModuleTool().Call(context.Background(),
		json.RawMessage(`{"module":"shell","agent":"production-uuid"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("RunModule accepted a non-verification module: %+v", result)
	}
	if len(audits) != 1 || !strings.Contains(audits[0], "run_module_denied") {
		t.Fatalf("denial was not audited: %v", audits)
	}

	for _, candidate := range []tool.CoreTool{e.agentStatusTool(), e.cleanupAgentTool()} {
		properties, _ := candidate.InputSchema()["properties"].(map[string]any)
		if _, ok := properties["agent"]; ok {
			t.Fatalf("%s still accepts an agent override", candidate.Name())
		}
	}
}

func TestVerificationToolsGatedWhenUnconfigured(t *testing.T) {
	audits := make([]string, 0, 3)
	e := &evolver{
		expectedAgentUUID: "should-not-run",
		cfg: EvolveConfig{
			Module:    "loader_windows",
			ModuleDir: t.TempDir(),
			Audit: func(action, target, detail string) {
				audits = append(audits, action+" "+target+" "+detail)
			},
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()

	registered := make(map[string]bool)
	for _, tl := range e.tools() {
		registered[tl.Name()] = true
	}
	for _, forbidden := range []string{"AgentStatus", "RunModule", "CleanupAgent", "GenerateAgent"} {
		if registered[forbidden] {
			t.Fatalf("tool %s registered even though unconfigured", forbidden)
		}
	}

	hooks := e.hooks()
	for _, blocked := range []string{"AgentStatus", "RunModule", "CleanupAgent", "GenerateAgent"} {
		if res := e.allowToolHook(blocked); res.Decision != "block" {
			t.Fatalf("allowToolHook allowed unconfigured tool %s: %+v", blocked, res)
		}
		if isBlocked, _, _ := hooks.PreToolUse(context.Background(), blocked, nil); !isBlocked {
			t.Fatalf("PreToolUse hook allowed unconfigured tool %s", blocked)
		}
	}

	r1, _ := e.agentStatusTool().Call(context.Background(), json.RawMessage(`{}`), nil)
	r2, _ := e.runModuleTool().Call(context.Background(), json.RawMessage(`{"module":"whoami"}`), nil)
	r3, _ := e.cleanupAgentTool().Call(context.Background(), json.RawMessage(`{}`), nil)
	for idx, res := range []tool.Result{r1, r2, r3} {
		if !res.IsError {
			t.Fatalf("tool call #%d succeeded without VerifyOps: %+v", idx, res)
		}
	}
	if len(audits) != 3 {
		t.Fatalf("expected 3 denied audit entries, got %d: %v", len(audits), audits)
	}
}

func TestVerificationToolsDelegateWhenConfigured(t *testing.T) {
	ops := &stubVerifyOps{}
	audits := make([]string, 0, 3)
	e := &evolver{
		expectedAgentUUID: "owned-uuid-1",
		cfg: EvolveConfig{
			Module:    "loader_windows",
			ModuleDir: t.TempDir(),
			Verify:    ops,
			BuildAgent: func(AgentBuildOptions) (*AgentBuildResult, error) {
				return &AgentBuildResult{}, nil
			},
			Audit: func(action, target, detail string) {
				audits = append(audits, action+" "+target+" "+detail)
			},
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()

	registered := make(map[string]bool)
	for _, tl := range e.tools() {
		registered[tl.Name()] = true
	}
	for _, expected := range []string{"AgentStatus", "RunModule", "CleanupAgent", "GenerateAgent"} {
		if !registered[expected] {
			t.Fatalf("expected configured tool %s to be registered", expected)
		}
	}

	if res, err := e.agentStatusTool().Call(context.Background(), json.RawMessage(`{}`), nil); err != nil || res.IsError {
		t.Fatalf("AgentStatus failed: err=%v res=%+v", err, res)
	}
	if res, err := e.runModuleTool().Call(context.Background(), json.RawMessage(`{"module":"whoami"}`), nil); err != nil || res.IsError {
		t.Fatalf("RunModule failed: err=%v res=%+v", err, res)
	}
	if res, err := e.cleanupAgentTool().Call(context.Background(), json.RawMessage(`{}`), nil); err != nil || res.IsError {
		t.Fatalf("CleanupAgent failed: err=%v res=%+v", err, res)
	}

	if len(ops.statusCalls) != 1 || ops.statusCalls[0] != "owned-uuid-1" {
		t.Fatalf("statusCalls = %v", ops.statusCalls)
	}
	if len(ops.moduleCalls) != 1 || ops.moduleCalls[0] != "owned-uuid-1:whoami" {
		t.Fatalf("moduleCalls = %v", ops.moduleCalls)
	}
	if len(ops.forgetCalls) != 1 || ops.forgetCalls[0] != "owned-uuid-1" {
		t.Fatalf("forgetCalls = %v", ops.forgetCalls)
	}
	if len(audits) != 3 {
		t.Fatalf("audits = %v", audits)
	}
}
