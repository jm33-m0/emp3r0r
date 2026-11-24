package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// evolveRole is one model worker. Each role runs in its own session with its
// own system prompt and tool set; the coordinator sequences them.
type evolveRole string

const (
	rolePlanner  evolveRole = "planner"
	roleEditor   evolveRole = "editor"
	roleDebugger evolveRole = "debugger"
)

func (r evolveRole) label() string {
	switch r {
	case rolePlanner:
		return "planner"
	case roleEditor:
		return "editor"
	case roleDebugger:
		return "debugger"
	default:
		return string(r)
	}
}

// plannerPlan is the coordinator's instruction. The planner never mutates
// source or runs a cycle; it chooses the hypothesis and the next worker.
type plannerPlan struct {
	Action      string         `json:"action"`
	Reason      string         `json:"reason,omitempty"`
	Mechanism   string         `json:"mechanism,omitempty"`
	Prediction  string         `json:"prediction,omitempty"`
	EditorBrief string         `json:"editor_brief,omitempty"`
	DebugFocus  string         `json:"debug_focus,omitempty"`
	Final       map[string]any `json:"final,omitempty"`
}

// debugDiagnosis is the debugger's structured result. GuestActions is the
// audit record of what changed inside the sandbox.
type debugDiagnosis struct {
	Cause             string   `json:"cause"`
	Evidence          []string `json:"evidence,omitempty"`
	GuestActions      []string `json:"guest_actions,omitempty"`
	AgentOnlineAfter  bool     `json:"agent_online_after,omitempty"`
	SourceFixRequired bool     `json:"source_fix_required,omitempty"`
	EditorBrief       string   `json:"editor_brief,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
}

// workerRun is one persisted model session. Full prompts and outputs stay in
// SQLite so a later session can cite the coordinator's history without
// replaying it in context.
type WorkerRun struct {
	LoopID    string `json:"loop_id"`
	Iteration int    `json:"iteration"`
	Role      string `json:"role"`
	Model     string `json:"model,omitempty"`
	Prompt    string `json:"prompt,omitempty"`
	Output    string `json:"output,omitempty"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Turns     int    `json:"turns,omitempty"`
	TokensIn  int    `json:"tokens_in,omitempty"`
	TokensOut int    `json:"tokens_out,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

// toolsFor returns only the capabilities the role needs. The planner never
// gets a mutation tool; the editor never gets the guest; the debugger never
// gets a source or build tool.
func (e *evolver) toolsFor(role evolveRole) []tool.CoreTool {
	tools := []tool.CoreTool{
		sourceTreeTool(e.roots),
		moduleListTool(e.roots),
		moduleReadTool(e.roots, e),
		moduleSearchTool(e.roots),
		analystTelemetryTool(e.db),
		e.loopMemoryTool(),
		e.inspectFeedbackTool(),
		e.payloadsTool(),
		e.comparePayloadsTool(),
	}
	// Methodology entries are built in, so search/read must be callable even
	// when no external knowledge database is configured.
	tools = append(tools, e.knowledgeSearchTool(), e.knowledgeReadTool())
	if e.knowledge != nil {
		tools = append(tools, e.knowledgeStatsTool(), e.knowledgeListTool())
	}
	if e.git != nil {
		tools = append(tools, e.gitHistoryTool())
	}
	switch role {
	case rolePlanner:
		if e.verifyEnabled() {
			tools = append(tools, e.agentStatusTool())
		}
	case roleEditor:
		tools = append(tools, e.editSourceTool(), e.sourceWriteTool(), e.sourceMultiEditTool(), e.sourceDeleteTool(), e.sourceMoveTool(),
			e.buildOptionsTool(), e.buildShellcodeTool(), e.revertPayloadTool(), e.detectionCycleTool())
		if e.cfg.BuildAgent != nil {
			tools = append(tools, e.generateAgentTool())
		}
	case roleDebugger:
		if e.verifyEnabled() {
			tools = append(tools, e.agentStatusTool(), e.cleanupAgentTool())
			if e.platform() == platformWindows {
				tools = append(tools, e.runModuleTool())
			}
		}
		if e.guest != nil {
			tools = append(tools, e.guestSSHTool())
		}
	}
	return tools
}

// tools is the union used by tests and diagnostics. The loop itself always
// selects a role-specific set.
func (e *evolver) tools() []tool.CoreTool {
	seen := make(map[string]struct{})
	var out []tool.CoreTool
	for _, role := range []evolveRole{rolePlanner, roleEditor, roleDebugger} {
		for _, candidate := range e.toolsFor(role) {
			if _, ok := seen[candidate.Name()]; ok {
				continue
			}
			seen[candidate.Name()] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out
}

func (e *evolver) allowToolHookFor(role evolveRole, toolName string) hook.Result {
	for _, candidate := range e.toolsFor(role) {
		if candidate.Name() == toolName {
			return hook.Result{}
		}
	}
	return hook.Result{Decision: "block", Message: "tool is not part of the " + role.label() + " worker"}
}

// allowToolHook is the union check kept for diagnostics and tests. A tool is
// allowed when at least one worker owns it.
func (e *evolver) allowToolHook(toolName string) hook.Result {
	for _, role := range []evolveRole{rolePlanner, roleEditor, roleDebugger} {
		if e.allowToolHookFor(role, toolName).Decision != "block" {
			return hook.Result{}
		}
	}
	return hook.Result{Decision: "block", Message: "tool is not part of the detection loop"}
}

const (
	// plannerReadBudget is how many read-only calls the planner gets before the
	// host requires the plan. The planner decides; it does not need to
	// re-prove the same baseline.
	plannerReadBudget = 12
	// editorReadBudget is how many read-only calls the editor gets without a
	// mutation. The host then blocks reading and requires an action.
	editorReadBudget = 24
)

func readOnlyToolName(name string) bool {
	switch name {
	case "SourceTree", "SourceList", "SourceRead", "SourceSearch", "TelemetryQuery",
		"InspectFeedback", "Payloads", "ComparePayloads", "GitHistory",
		"KnowledgeSearch", "KnowledgeRead", "KnowledgeStats", "KnowledgeList",
		"AgentStatus":
		return true
	}
	return false
}

// mutatingToolName reports a tool that changes source, artifacts, or the
// guest. A call to one of these ends the read-only streak.
func mutatingToolName(name string) bool {
	switch name {
	case "EditSource", "SourceWrite", "SourceMultiEdit", "SourceDelete", "SourceMove",
		"BuildOptions", "BuildShellcode", "RevertToPayload", "DetectionCycle",
		"GenerateAgent", "RunModule", "CleanupAgent":
		return true
	}
	return false
}

func lastAssistantText(messages []llm.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == llm.RoleAssistant {
			return messages[i].Text()
		}
	}
	return ""
}

func (e *evolver) hooksFor(role evolveRole) *hook.Registry {
	plannerRead := e.cfg.PlannerReadBudget
	if plannerRead == 0 {
		plannerRead = plannerReadBudget
	}
	editorRead := e.cfg.EditorReadBudget
	if editorRead == 0 {
		editorRead = editorReadBudget
	}
	debuggerTools := e.cfg.DebuggerToolBudget
	var totalCalls, readOnlyCalls atomic.Int32
	hooks := hook.NewRegistry()
	// A queued operator prompt must reach the model at the next turn, not only
	// at the next worker session. UserPromptSubmit covers session starts and
	// deadline/provider retries; the Stop hook covers a model that pauses in
	// the middle of a session.
	hooks.On(hook.UserPromptSubmit, func(_ context.Context, _ hook.Event) hook.Result {
		if prompts := e.takeOperatorPrompts(); len(prompts) > 0 {
			return hook.Result{AdditionalContext: FormatOperatorPrompts(prompts)}
		}
		return hook.Result{}
	})
	hooks.On(hook.PreToolUse, func(_ context.Context, event hook.Event) hook.Result {
		decision := e.allowToolHookFor(role, event.ToolName)
		if decision.Decision == "block" {
			e.logClass(logging.ClassWarning, "%s worker blocked tool %s: %s", role.label(), event.ToolName, decision.Message)
			return decision
		}
		switch role {
		case rolePlanner:
			if plannerRead > 0 && readOnlyToolName(event.ToolName) && readOnlyCalls.Load() >= int32(plannerRead) {
				return e.blockTool(role, event.ToolName, "you have read enough evidence; return one JSON plan now instead of another query")
			}
		case roleEditor:
			if editorRead > 0 && readOnlyToolName(event.ToolName) && readOnlyCalls.Load() >= int32(editorRead) {
				return e.blockTool(role, event.ToolName, "the editor read budget is exhausted; apply the edit with EditSource and call DetectionCycle now")
			}
		case roleDebugger:
			if debuggerTools > 0 && totalCalls.Load() >= int32(debuggerTools) {
				return e.blockTool(role, event.ToolName, "the debugger tool budget is exhausted; return the debugger JSON object now with the cause you have")
			}
		}
		e.toolGate.Lock()
		defer e.toolGate.Unlock()
		if e.deadlineHit.Load() {
			e.logClass(logging.ClassWarning, "%s worker blocked tool %s: the session deadline expired", role.label(), event.ToolName)
			return hook.Result{
				Decision: "block",
				Message:  "the session deadline expired; the loop will continue this session with the required output",
			}
		}
		e.lastToolCall.Store(time.Now().UnixNano())
		e.activeTools.Add(1)
		totalCalls.Add(1)
		if readOnlyToolName(event.ToolName) {
			readOnlyCalls.Add(1)
		}
		return decision
	})
	hooks.On(hook.PostToolUse, func(_ context.Context, event hook.Event) hook.Result {
		e.lastToolCall.Store(time.Now().UnixNano())
		e.toolCalls.Add(1)
		for {
			active := e.activeTools.Load()
			if active <= 0 || e.activeTools.CompareAndSwap(active, active-1) {
				break
			}
		}
		if mutatingToolName(event.ToolName) {
			// A mutation attempt ends the read-only streak even when it failed:
			// the model may need one corrective read to fix the edit.
			readOnlyCalls.Store(0)
		}
		status := "ok"
		if event.IsError {
			status = "error"
		}
		preview := clip(sanitizeLine(string(event.Result)), 300)
		if preview == "" {
			preview = "(no output)"
		}
		class := logging.ClassToolResult
		if event.IsError {
			class = logging.ClassError
		}
		e.logClass(class, "%s %s %s: %s", role.label(), event.ToolName, status, preview)
		return hook.Result{}
	})
	hooks.On(hook.Stop, func(_ context.Context, event hook.Event) hook.Result {
		text := lastAssistantText(event.Messages)
		var required string
		switch role {
		case roleEditor:
			if e.sessionCycles.Load() == 0 {
				required = "You have not called DetectionCycle. Apply the remaining source edit with EditSource now, " +
					"then call DetectionCycle exactly once. Do not end this session without it."
			}
		case rolePlanner:
			if _, err := parsePlannerPlan(text); err != nil {
				required = "Your answer is not the required planner JSON object (" + err.Error() + "). " +
					"Return exactly one JSON object now: action=test, action=debug only when the brief says the debugger is available, or action=stop. Do not call tools."
			}
		case roleDebugger:
			if _, err := parseDebugDiagnosis(text); err != nil {
				required = "Your answer is not the required debugger JSON object (" + err.Error() + "). " +
					"Return exactly one JSON object now with cause, evidence, guest_actions, agent_online_after, source_fix_required, and confidence."
			}
		}
		promptContext := ""
		if prompts := e.takeOperatorPrompts(); len(prompts) > 0 {
			promptContext = FormatOperatorPrompts(prompts)
		}
		switch {
		case required != "" && promptContext != "":
			return hook.Result{Decision: "block", AdditionalContext: promptContext + "\n" + required}
		case required != "":
			return hook.Result{Decision: "block", AdditionalContext: required}
		case promptContext != "":
			return hook.Result{Decision: "block", AdditionalContext: promptContext}
		}
		return hook.Result{}
	})
	return hooks
}

func (e *evolver) blockTool(role evolveRole, toolName, message string) hook.Result {
	e.logClass(logging.ClassWarning, "%s worker blocked tool %s: %s", role.label(), toolName, message)
	return hook.Result{Decision: "block", Message: message}
}

// hooks is the union hook registry used by diagnostics and tests.
func (e *evolver) hooks() *hook.Registry {
	return e.hooksFor(roleEditor)
}

// --- parsing --------------------------------------------------------------

// jsonObject extracts the first JSON object from a model answer. Fenced code
// blocks and prose around it are ignored.
func jsonObject(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("answer is not a JSON object")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text[start:end+1]), &obj); err != nil {
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	return obj, nil
}

func parsePlannerPlan(text string) (plannerPlan, error) {
	obj, err := jsonObject(text)
	if err != nil {
		return plannerPlan{}, err
	}
	var plan plannerPlan
	if value, ok := obj["action"].(string); ok {
		plan.Action = strings.ToLower(strings.TrimSpace(value))
	}
	if value, ok := obj["reason"].(string); ok {
		plan.Reason = value
	}
	if value, ok := obj["mechanism"].(string); ok {
		plan.Mechanism = value
	}
	if value, ok := obj["prediction"].(string); ok {
		plan.Prediction = value
	}
	if value, ok := obj["editor_brief"].(string); ok {
		plan.EditorBrief = value
	}
	if value, ok := obj["debug_focus"].(string); ok {
		plan.DebugFocus = value
	}
	if value, ok := obj["final"].(map[string]any); ok {
		plan.Final = value
	}
	if plan.Action == "" {
		// A bare final answer is still a stop decision; this keeps older
		// prompts and scripted providers working.
		plan.Action = "stop"
	}
	switch plan.Action {
	case "test", "debug", "stop":
	default:
		return plannerPlan{}, fmt.Errorf("unknown planner action %q; use test, debug, or stop", plan.Action)
	}
	if plan.Action == "stop" && plan.Final == nil {
		plan.Final = obj
	}
	if plan.Action == "test" {
		plan.Mechanism = strings.ToLower(strings.TrimSpace(plan.Mechanism))
		if !evolveMechanisms[plan.Mechanism] {
			plan.Mechanism = "other"
		}
	}
	return plan, nil
}

var evolveMechanisms = map[string]bool{
	"baseline": true, "self-load": true, "remote-apc": true,
	"remote-thread": true, "section-map": true, "module-stomp": true,
	"pe-image": true, "producer": true, "producer-swap": true,
	"static-hygiene": true, "other": true,
}

func parseDebugDiagnosis(text string) (debugDiagnosis, error) {
	obj, err := jsonObject(text)
	if err != nil {
		return debugDiagnosis{}, err
	}
	var diag debugDiagnosis
	if value, ok := obj["cause"].(string); ok {
		diag.Cause = strings.TrimSpace(value)
	}
	if values, ok := obj["evidence"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				diag.Evidence = append(diag.Evidence, text)
			}
		}
	}
	if values, ok := obj["guest_actions"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				diag.GuestActions = append(diag.GuestActions, text)
			}
		}
	}
	if value, ok := obj["agent_online_after"].(bool); ok {
		diag.AgentOnlineAfter = value
	}
	if value, ok := obj["source_fix_required"].(bool); ok {
		diag.SourceFixRequired = value
	}
	if value, ok := obj["editor_brief"].(string); ok {
		diag.EditorBrief = value
	}
	if value, ok := obj["confidence"].(string); ok {
		diag.Confidence = value
	}
	if diag.Cause == "" && len(diag.Evidence) == 0 {
		return debugDiagnosis{}, fmt.Errorf("debugger answer names no cause or evidence")
	}
	if diag.Cause == "" {
		diag.Cause = "unknown"
	}
	return diag, nil
}
