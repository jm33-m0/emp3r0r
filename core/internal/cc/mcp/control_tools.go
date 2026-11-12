package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/operator"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// controlTools exposes C2-side operator actions that do not run on a target.
func (a *Actions) controlTools() map[string]Tool {
	return map[string]Tool{
		"resume_operator": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "resume_operator",
					Description: "Clear the server-side operator idle state so agents disconnected by the idle timeout can reconnect. Takes no arguments and needs no selected target. Returns executed and the OPSEC decision; it does not change target state.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			Run: a.resumeOperator,
		},
		"forget_agent": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "forget_agent",
					Description: "Permanently remove one agent's record from the C2 database. The agent argument is a tag from list_agents. This is irreversible, so the policy must allow irreversible actions. It does not uninstall the agent; a reconnecting agent is tracked as a new record. Returns executed, agent, and the server response.",
					Parameters: ObjectSchema(map[string]any{
						"agent": StringProp("Agent tag from list_agents"),
					}, "agent"),
				},
			},
			Destructive: true,
			Run:         a.forgetAgent,
		},
		"socks_start": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "socks_start",
					Description: "Start a SOCKS5 listener on the C2 that relays through the selected target. port defaults to 1080. bind is the C2-side bind address; empty uses the operator's reachable WireGuard address. Returns port, bind, agent, and a stealth warning when the agent must poll faster during relays. Requires an active target.",
					Parameters: ObjectSchema(map[string]any{
						"port": IntegerProp("Listener port, 1-65535; default 1080"),
						"bind": StringProp("C2-side bind address; empty uses the reachable WireGuard address"),
					}),
				},
			},
			Destructive: true,
			Run:         a.socksStart,
		},
		"socks_stop": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "socks_stop",
					Description: "Stop one C2-side SOCKS5 listener. port is the listener port returned by socks_start or socks_status. Returns executed and port.",
					Parameters: ObjectSchema(map[string]any{
						"port": IntegerProp("Listener port, 1-65535"),
					}, "port"),
				},
			},
			Destructive: true,
			Run:         a.socksStop,
		},
		"socks_status": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "socks_status",
					Description: "List C2-side SOCKS5 listeners started by this operator. Returns pivots with port, bind, and agent. Takes no arguments.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.socksStatus,
		},
		"tun2socks_start": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "tun2socks_start",
					Description: "Create a local TUN device and route destination prefixes through a C2 SOCKS5 pivot. route is required and repeatable; the default route is never changed. exclude removes subnets from the routed set. When socks5 is empty, host and port select the pivot, and port 0 auto-detects the only running pivot. Returns name, socks5, and the OPSEC decision.",
					Parameters: ObjectSchema(map[string]any{
						"route": map[string]any{
							"type":        "array",
							"description": "Destination prefixes routed into the TUN, for example 10.10.0.0/24",
							"items":       map[string]any{"type": "string"},
							"minItems":    1,
						},
						"exclude": map[string]any{
							"type":        "array",
							"description": "Prefixes subtracted from route and left on the normal path",
							"items":       map[string]any{"type": "string"},
						},
						"socks5": StringProp("Full pivot address host:port; overrides host and port"),
						"port":   IntegerProp("SOCKS5 pivot port; 0 auto-detects the only running pivot"),
						"host":   StringProp("Pivot host; empty uses the reachable WireGuard address"),
						"name":   StringProp("TUN device name; default emp3r0r0"),
						"addr":   StringProp("TUN address in prefix form; default 10.0.8.1/24"),
						"mtu":    IntegerProp("TUN MTU; default 1500"),
					}, "route"),
				},
			},
			Destructive: true,
			Run:         a.tun2socksStart,
		},
		"tun2socks_stop": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "tun2socks_stop",
					Description: "Close one local TUN instance and remove its routes. name defaults to emp3r0r0. Returns executed and name.",
					Parameters: ObjectSchema(map[string]any{
						"name": StringProp("TUN device name; default emp3r0r0"),
					}),
				},
			},
			Destructive: true,
			Run:         a.tun2socksStop,
		},
		"tun2socks_status": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "tun2socks_status",
					Description: "List local TUN instances with their name and SOCKS5 pivot address. Takes no arguments.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.tun2socksStatus,
		},
		"set_debug": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "set_debug",
					Description: "Set operator log verbosity from 0 (least verbose) to 4 (most verbose); the default is 2. This changes the MCP process log only, and release builds ignore it. Returns executed and level.",
					Parameters: ObjectSchema(map[string]any{
						"level": IntegerProp("Log level, 0-4"),
					}, "level"),
				},
			},
			Run: a.setDebug,
		},
	}
}

func controlReview(reasons ...string) def.OpsecReview {
	return def.OpsecReview{
		Noise:      "low",
		Reversible: true,
		Reasons:    reasons,
		Artifacts:  []string{"operator audit entry"},
	}
}

func (a *Actions) runControl(ctx context.Context, tool string, target *def.Emp3r0rAgent, review def.OpsecReview, fn func() (map[string]any, error)) (any, error) {
	decision, auditErr := a.screen(tool, "", "", target, review)
	if !decision.Allowed {
		return actionBlocked(tool, "", "", target, review, decision, auditErr), nil
	}
	payload, err := fn()
	result := a.actionResult(tool, "", "", target, review, decision, auditErr, "", err, err == nil)
	for key, value := range payload {
		result[key] = value
	}
	return result, nil
}

func controlString(name, value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return "", fmt.Errorf("%s is longer than %d bytes", name, max)
	}
	if err := ValidateCommandLine(value); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

func (a *Actions) resumeOperator(ctx context.Context, _ json.RawMessage) (any, error) {
	return a.runControl(ctx, "resume_operator", nil, controlReview("clears operator idle state so agents can reconnect"), func() (map[string]any, error) {
		return map[string]any{}, a.Executor.ResumeOperator(ctx)
	})
}

func (a *Actions) forgetAgent(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Agent string `json:"agent"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	agent, err := controlString("agent", args.Agent, 256)
	if err != nil {
		return nil, err
	}
	if agent == "" {
		return nil, fmt.Errorf("agent is required")
	}
	review := controlReview("permanently removes the agent record from the C2")
	review.Reversible = false
	review.Rules = []string{"destructive"}
	return a.runControl(ctx, "forget_agent", nil, review, func() (map[string]any, error) {
		body, err := a.Executor.ForgetAgent(ctx, agent)
		return map[string]any{"agent": agent, "response": body}, err
	})
}

func (a *Actions) socksStart(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Port int    `json:"port"`
		Bind string `json:"bind"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if args.Port < 0 || args.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	bind, err := controlString("bind", args.Bind, 256)
	if err != nil {
		return nil, err
	}
	target := a.target()
	review := controlReview("starts a SOCKS5 listener that relays through the target")
	addOperatorRule(&review, "data-transfer", "moves operator traffic through the target")
	return a.runControl(ctx, "socks_start", target, review, func() (map[string]any, error) {
		pivot, err := a.Executor.StartSocks5(ctx, args.Port, bind)
		if err != nil {
			return nil, err
		}
		return map[string]any{"port": pivot.Port, "bind": pivot.Bind, "agent": pivot.Agent, "warning": pivot.Warning}, nil
	})
}

func (a *Actions) socksStop(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if args.Port <= 0 || args.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	review := controlReview("stops a SOCKS5 listener")
	addOperatorRule(&review, "data-transfer", "ends a pivot that carried operator traffic")
	return a.runControl(ctx, "socks_stop", nil, review, func() (map[string]any, error) {
		return map[string]any{"port": args.Port}, a.Executor.StopSocks5(ctx, args.Port)
	})
}

func (a *Actions) socksStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	pivots, err := a.Executor.ListSocks5(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"pivots": pivots}, nil
}

func (a *Actions) tun2socksStart(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Route   []string `json:"route"`
		Exclude []string `json:"exclude"`
		Socks5  string   `json:"socks5"`
		Port    int      `json:"port"`
		Host    string   `json:"host"`
		Name    string   `json:"name"`
		Addr    string   `json:"addr"`
		MTU     int      `json:"mtu"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if len(args.Route) == 0 {
		return nil, fmt.Errorf("route is required")
	}
	for _, prefix := range append(append([]string{}, args.Route...), args.Exclude...) {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", prefix, err)
		}
	}
	socks5, err := controlString("socks5", args.Socks5, 256)
	if err != nil {
		return nil, err
	}
	host, err := controlString("host", args.Host, 256)
	if err != nil {
		return nil, err
	}
	name, err := controlString("name", args.Name, 64)
	if err != nil {
		return nil, err
	}
	addr, err := controlString("addr", args.Addr, 64)
	if err != nil {
		return nil, err
	}
	if args.Port < 0 || args.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	review := controlReview("routes operator traffic through a target-side network")
	addOperatorRule(&review, "data-transfer", "moves operator traffic through the target")
	return a.runControl(ctx, "tun2socks_start", nil, review, func() (map[string]any, error) {
		state, err := a.Executor.StartTun2Socks(ctx, operator.Tun2SocksOptions{
			Port:     args.Port,
			Host:     host,
			Socks5:   socks5,
			Name:     name,
			Addr:     addr,
			MTU:      args.MTU,
			Routes:   args.Route,
			Excludes: args.Exclude,
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": state.Name, "socks5": state.Socks5}, nil
	})
}

func (a *Actions) tun2socksStop(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	name, err := controlString("name", args.Name, 64)
	if err != nil {
		return nil, err
	}
	review := controlReview("closes a local TUN instance and removes its routes")
	addOperatorRule(&review, "data-transfer", "ends a TUN route that carried operator traffic")
	return a.runControl(ctx, "tun2socks_stop", nil, review, func() (map[string]any, error) {
		return map[string]any{"name": name}, a.Executor.StopTun2Socks(ctx, name)
	})
}

func (a *Actions) tun2socksStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	return map[string]any{"instances": a.Executor.Tun2SocksStatus(ctx)}, nil
}

func (a *Actions) setDebug(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Level int `json:"level"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if args.Level < 0 || args.Level > 4 {
		return nil, fmt.Errorf("level must be between 0 and 4")
	}
	review := controlReview("changes operator log verbosity")
	return a.runControl(ctx, "set_debug", nil, review, func() (map[string]any, error) {
		return map[string]any{"level": args.Level}, a.Executor.SetDebugLevel(ctx, args.Level)
	})
}
